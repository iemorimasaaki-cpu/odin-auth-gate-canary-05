"""Shared helpers: record validation, GitHub API client, hashing, git."""
import base64
import datetime
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request

EXPECTED_REPO = "iemorimasaaki-cpu/odin-auth-gate-canary-05"
OWNER_LOGIN = "iemorimasaaki-cpu"
PKG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,39}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ZERO_SHA = "0" * 40
AUTHZ_PATH_RE = re.compile(r"^authz/([a-z0-9][a-z0-9-]{2,39})\.json$")
SPEC_PATH_RE = re.compile(r"^specs/([a-z0-9][a-z0-9-]{2,39})\.md$")
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
MAX_WINDOW = datetime.timedelta(days=7)
SKEW = datetime.timedelta(seconds=300)
ALLOWED_OPS = {"synthetic-echo"}
FORBIDDEN_PREFIXES = (".github/", ".git/", "tools/", "authz/", "specs/", "tests/", "docs/")
FORBIDDEN_NAMES = {".git", ".gitmodules", ".gitattributes", "CODEOWNERS"}

RECORD_KEYS = {
    "schema", "package_id", "revision", "baseline_sha", "spec_path", "spec_sha256",
    "allowed_ops", "scope_paths", "max_files", "max_patch_bytes", "issued_at",
    "expires_at", "max_rounds", "worker_timeout_min", "status", "summary",
}


class Reject(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def parse_ts(s, field):
    try:
        return datetime.datetime.strptime(s, TS_FMT)
    except (TypeError, ValueError):
        raise Reject("SCHEMA", f"{field} must be UTC like 2026-01-01T00:00:00Z")


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None, microsecond=0)


def norm_rel_path(p):
    """Return a normalized relative posix path or None if unsafe."""
    if not isinstance(p, str) or not p or p.startswith("/") or "\\" in p or "\x00" in p:
        return None
    parts = p.split("/")
    if parts[-1] == "":
        parts = parts[:-1]
    if not parts or any(x in ("", ".", "..") for x in parts):
        return None
    return "/".join(parts)


def validate_record(rec, pkg, now):
    """Strict structural + temporal validation. Raises Reject."""
    if not isinstance(rec, dict):
        raise Reject("SCHEMA", "record must be an object")
    extra, missing = set(rec) - RECORD_KEYS, RECORD_KEYS - set(rec)
    if extra or missing:
        raise Reject("SCHEMA", f"extra={sorted(extra)} missing={sorted(missing)}")
    if rec["schema"] != "odin-authz/1":
        raise Reject("SCHEMA", "schema")
    if rec["package_id"] != pkg or not PKG_RE.match(str(rec["package_id"])):
        raise Reject("SCHEMA", "package_id does not match file name")
    ints = {"revision": (1, 999), "max_files": (1, 20), "max_patch_bytes": (1, 49152),
            "max_rounds": (1, 3), "worker_timeout_min": (1, 5)}
    for k, (lo, hi) in ints.items():
        v = rec[k]
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise Reject("SCHEMA", f"{k} out of range [{lo},{hi}]")
    if not SHA_RE.match(str(rec["baseline_sha"])):
        raise Reject("SCHEMA", "baseline_sha")
    if rec["spec_path"] != f"specs/{pkg}.md":
        raise Reject("SCHEMA", "spec_path")
    if not SHA256_RE.match(str(rec["spec_sha256"])):
        raise Reject("SCHEMA", "spec_sha256")
    ops = rec["allowed_ops"]
    if not isinstance(ops, list) or not ops or not set(ops) <= ALLOWED_OPS:
        raise Reject("SCHEMA", "allowed_ops")
    sp = rec["scope_paths"]
    if not isinstance(sp, list) or not 1 <= len(sp) <= 5:
        raise Reject("SCHEMA", "scope_paths")
    for p in sp:
        n = norm_rel_path(p)
        if n is None or not (n + "/").startswith(f"synthetic-out/{pkg}/"):
            raise Reject("SCOPE", f"scope path not under synthetic-out/{pkg}/: {p!r}")
    if rec["status"] not in ("approved", "revoked"):
        raise Reject("SCHEMA", "status")
    if not isinstance(rec["summary"], str) or len(rec["summary"]) > 200:
        raise Reject("SCHEMA", "summary")
    issued, expires = parse_ts(rec["issued_at"], "issued_at"), parse_ts(rec["expires_at"], "expires_at")
    if expires <= issued or expires - issued > MAX_WINDOW:
        raise Reject("SCHEMA", "validity window")
    if rec["status"] == "revoked":
        raise Reject("REVOKED", "status=revoked")
    if issued > now + SKEW:
        raise Reject("NOT_YET_VALID", rec["issued_at"])
    if now >= expires:  # exclusive upper bound
        raise Reject("EXPIRED", rec["expires_at"])
    return rec


def load_json_strict(text, what):
    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError(f"duplicate key {k}")
            d[k] = v
        return d
    try:
        return json.loads(text, object_pairs_hook=no_dupes)
    except ValueError as e:
        raise Reject("SCHEMA", f"{what}: {e}")


def git(*args, cwd=".", check=True):
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}: {body[:200]}")
        self.status = status
        self.body = body


class GitHubAPI:
    def __init__(self, repo, token, base=None):
        self.repo, self.token = repo, token
        self.base = (base or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")

    def request(self, method, path, body=None):
        url = f"{self.base}/repos/{self.repo}{path}"
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "odin-gate-canary-05",
            "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                txt = r.read().decode()
                return json.loads(txt) if txt else {}
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, e.read().decode(errors="replace"))

    # --- thin typed helpers (the fake in tests implements the same surface) ---
    def get_ref_sha(self, ref):
        """ref like 'tags/odin/claim/x/r1'. Returns object sha or None."""
        try:
            return self.request("GET", f"/git/ref/{ref}")["object"]["sha"]
        except ApiError as e:
            if e.status == 404:
                return None
            raise

    def create_ref(self, ref, sha):
        """Create-only. Returns True, or False when the ref already exists."""
        try:
            self.request("POST", "/git/refs", {"ref": ref, "sha": sha})
            return True
        except ApiError as e:
            if e.status == 422 and "already exists" in e.body.lower():
                return False
            raise

    def get_contents(self, path, ref):
        try:
            j = self.request("GET", f"/contents/{path}?ref={ref}")
        except ApiError as e:
            if e.status == 404:
                return None
            raise
        return j["sha"], base64.b64decode(j["content"]).decode()

    def commit_pulls(self, sha):
        return self.request("GET", f"/commits/{sha}/pulls")

    def get_pull(self, number):
        return self.request("GET", f"/pulls/{number}")

    def create_blob(self, content_b64):
        return self.request("POST", "/git/blobs", {"content": content_b64, "encoding": "base64"})["sha"]

    def get_commit_tree(self, commit_sha):
        return self.request("GET", f"/git/commits/{commit_sha}")["tree"]["sha"]

    def create_tree(self, base_tree, entries):
        return self.request("POST", "/git/trees", {"base_tree": base_tree, "tree": entries})["sha"]

    def create_commit(self, message, tree, parents):
        return self.request("POST", "/git/commits", {
            "message": message, "tree": tree, "parents": parents,
            "author": {"name": "odin-canary", "email": "odin-canary@users.noreply.github.com"}})["sha"]

    def create_tag_object(self, tag, message, object_sha):
        return self.request("POST", "/git/tags", {
            "tag": tag, "message": message, "object": object_sha, "type": "commit",
            "tagger": {"name": "odin-canary", "email": "odin-canary@users.noreply.github.com"}})["sha"]

    def get_tag_message(self, tag_sha):
        return self.request("GET", f"/git/tags/{tag_sha}")["message"]


def claim_ref(pkg, rnd):
    return f"odin/claim/{pkg}/r{rnd}"


def evidence_ref(pkg, rnd):
    return f"odin/evidence/{pkg}/r{rnd}"


def live_check(api, pkg, expected_blob):
    """Re-read the authorization record from main NOW. Raises Reject on revoke/stale."""
    cur = api.get_contents(f"authz/{pkg}.json", "main")
    if cur is None:
        raise Reject("REVOKED", "record missing on main")
    blob, text = cur
    if blob != expected_blob:
        try:
            if load_json_strict(text, "live record").get("status") == "revoked":
                raise Reject("REVOKED", "record revoked on main")
        except Reject as e:
            if e.code == "REVOKED":
                raise
        raise Reject("STALE_AUTHZ", "record on main differs from launched record")
    return True


def write_output(name, value):
    value = str(value)
    if "\n" in value or "\r" in value:
        raise ValueError("output values must be single-line")
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as f:
            f.write(f"{name}={value}\n")
    print(f"output {name}={value}")


def summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(text + "\n")
    print(text)
