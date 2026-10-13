"""WORKER job logic: deterministic synthetic fixture. No model, no secrets, no write token.

The first spec line 'fixture: <name>' selects a deterministic output. Adversarial fixtures exist only
to exercise VERIFY; they cannot reach publish unless VERIFY is broken (that is what E6 measures).
"""
import base64
import json
import os
import re
import time

from .common import (EXPECTED_REPO, Reject, GitHubAPI, live_check, load_json_strict, sha256_hex, summary,
                     utcnow, validate_record, write_output, read_tree_file)

FIXTURES = {"echo", "slow", "out-of-scope", "oversize", "forbidden-path", "too-many-files", "max-size"}
SLOW_SECONDS = 90  # bounded in-flight window for E10; job timeout is 5 min


def build_files(pkg, rnd, spec_text, rec):
    fixture = fixture_of(spec_text)
    if fixture not in FIXTURES:
        raise Reject("FIXTURE_UNKNOWN", fixture)
    base = f"synthetic-out/{pkg}"
    body = f"synthetic echo\npackage={pkg}\nround={rnd}\nspec_sha256={rec['spec_sha256']}\n".encode()
    files = {f"{base}/echo.txt": body}
    if fixture == "out-of-scope":
        files["synthetic-out/other-package/escape.txt"] = b"outside the approved scope\n"
    elif fixture == "oversize":
        files[f"{base}/big.bin"] = b"x" * (rec["max_patch_bytes"] + 1)
    elif fixture == "forbidden-path":
        files[".github/workflows/injected.yml"] = b"on: push\n"
    elif fixture == "max-size":  # exactly at the approved byte limit (positive boundary test)
        files[f"{base}/pad.bin"] = b"p" * (rec["max_patch_bytes"] - len(body))
    elif fixture == "too-many-files":
        for i in range(rec["max_files"] + 1):
            files[f"{base}/f{i}.txt"] = b"x\n"
    return files


def make_bundle(files):
    entries = [{"path": p, "size": len(b), "sha256": sha256_hex(b), "b64": base64.b64encode(b).decode()}
               for p, b in sorted(files.items())]
    return json.dumps({"schema": "odin-bundle/1", "files": entries}, sort_keys=True, separators=(",", ":"))


def fixture_of(spec_text):
    m = re.match(r"fixture: ([a-z-]+)\n", spec_text)
    return m.group(1) if m else "echo"


def run_worker(env, api, repo_dir, now=None, sleep_fn=time.sleep):
    now = now or utcnow()
    pkg, rnd, blob = env["PACKAGE_ID"], int(env["ROUND"]), env["AUTHZ_BLOB"]
    sha = env.get("GITHUB_SHA", "HEAD")
    rec = validate_record(load_json_strict(read_tree_file(repo_dir, sha, f"authz/{pkg}.json").decode(), "record"), pkg, now)
    spec = read_tree_file(repo_dir, sha, rec["spec_path"])
    if sha256_hex(spec) != rec["spec_sha256"]:
        raise Reject("SPEC_MISMATCH", "worker spec hash")
    live_check(api, pkg, blob)
    files = build_files(pkg, rnd, spec.decode(), rec)
    if fixture_of(spec.decode()) == "slow":
        sleep_fn(SLOW_SECONDS)
        live_check(api, pkg, blob)  # in-flight exposure ends at the next check point
    return make_bundle(files)


def main(env=None):
    env = dict(os.environ if env is None else env)
    assert env.get("GITHUB_REPOSITORY") == EXPECTED_REPO
    api = GitHubAPI(EXPECTED_REPO, env["GITHUB_TOKEN"])
    try:
        bundle = run_worker(env, api, ".")
    except Reject as r:
        summary(f"### Worker\nREJECT {r.code}: {r.detail}")
        return 1
    write_output("bundle", bundle)
    summary(f"### Worker\nbundle bytes={len(bundle)}")
    return 0
