"""GATE job logic (read-only). Decides GO / REJECT / DUPLICATE / NOOP. Never writes to GitHub."""
import json
import os
import re
import time

from .common import (AUTHZ_PATH_RE, EXPECTED_REPO, OWNER_LOGIN, PKG_RE, SPEC_PATH_RE, ZERO_SHA, Reject,
                     claim_ref, git, live_check, load_json_strict, read_tree_file, sha256_hex, summary, utcnow,
                     validate_record, write_output)


PULL_RETRY_SLEEP = (2, 5)  # seconds before 2nd/3rd lookup: commits/{sha}/pulls can lag the push


def changed_files(repo_dir, before, after):
    out = git("diff", "--name-status", "--no-renames", "-z", before, after, cwd=repo_dir).stdout
    toks = [t for t in out.split("\0") if t]
    res = {}
    for i in range(0, len(toks), 2):
        res[toks[i + 1]] = toks[i]
    return res


def classify_push(changes):
    """Return (pkg, kind) with kind in LAUNCH|REVOKE_CANDIDATE or raise Reject."""
    outside = sorted(p for p in changes if not (AUTHZ_PATH_RE.match(p) or SPEC_PATH_RE.match(p)))
    if outside:
        raise Reject("GATE_CHANGE", f"non-authorization paths changed: {outside[:5]}")
    authz = {AUTHZ_PATH_RE.match(p).group(1): s for p, s in changes.items() if AUTHZ_PATH_RE.match(p)}
    specs = {SPEC_PATH_RE.match(p).group(1): s for p, s in changes.items() if SPEC_PATH_RE.match(p)}
    if len(authz) == 0:
        raise Reject("NO_AUTHZ", "no authorization record changed" + (" (spec-only change)" if specs else ""))
    if len(authz) != 1 or set(specs) - set(authz):
        raise Reject("MULTI_PACKAGE", f"authz={sorted(authz)} specs={sorted(specs)}")
    (pkg, st), = authz.items()
    if st == "A" and specs.get(pkg) == "A" and len(changes) == 2:
        return pkg, "LAUNCH"
    if st == "M" and not specs:
        return pkg, "REVOKE_CANDIDATE"
    raise Reject("AUTHZ_AMEND", f"unsupported change shape {changes}")


def check_provenance(api, sha):
    prs = []
    for delay in (0,) + tuple(PULL_RETRY_SLEEP):
        time.sleep(delay)
        prs = [p for p in api.commit_pulls(sha) if p.get("merged_at") and p.get("base", {}).get("ref") == "main"]
        if prs:
            break
    if not prs:
        raise Reject("NO_PR", "commit is not the result of a merged PR into main")
    pr = None
    for cand in prs:
        full = api.get_pull(cand["number"])
        if full.get("merged") and full.get("merge_commit_sha") == sha:
            pr = full
            break
    if pr is None:
        raise Reject("NOT_MERGE_COMMIT", "no merged PR has merge_commit_sha == pushed sha")
    merger = (pr.get("merged_by") or {}).get("login")
    if merger != OWNER_LOGIN:
        raise Reject("MERGER_MISMATCH", f"merged_by={merger!r}")
    return pr["number"], merger


def check_baseline(repo_dir, rec, sha, allowed_re):
    b = rec["baseline_sha"]
    if git("merge-base", "--is-ancestor", b, sha, cwd=repo_dir, check=False).returncode != 0:
        raise Reject("BASELINE_DRIFT", "baseline_sha is not an ancestor of the launched commit")
    ch = changed_files(repo_dir, b, sha)
    bad = sorted(p for p in ch if not any(r.match(p) for r in allowed_re))
    if bad:
        raise Reject("GATE_CHANGE", f"files changed between baseline and launch: {bad[:5]}")


def evaluate(env, api, repo_dir, now=None):
    """Pure decision function. Returns dict; never raises Reject (folded into the dict)."""
    now = now or utcnow()
    d = {"decision": "REJECT", "code": "", "detail": "", "package_id": "", "round": 0,
         "event": env.get("GITHUB_EVENT_NAME", ""), "sha": env.get("GITHUB_SHA", ""),
         "actor": env.get("GITHUB_ACTOR", ""), "triggering_actor": env.get("TRIGGERING_ACTOR", ""),
         "run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""), "authz_blob": "", "pr": "", "merged_by": ""}
    try:
        _evaluate(env, api, repo_dir, now, d)
    except Reject as r:
        d["code"], d["detail"] = r.code, r.detail
        d["decision"] = "NOOP" if r.code == "REVOKE_RECORDED" else "REJECT"
    return d


def _evaluate(env, api, repo_dir, now, d):
    if env.get("GITHUB_REPOSITORY") != EXPECTED_REPO:
        raise Reject("REPO_MISMATCH", env.get("GITHUB_REPOSITORY", ""))
    event = env.get("GITHUB_EVENT_NAME")
    if event not in ("push", "workflow_dispatch"):
        raise Reject("EVENT_NOT_ALLOWED", str(event))
    if env.get("GITHUB_REF") != "refs/heads/main":
        raise Reject("REF_NOT_MAIN", env.get("GITHUB_REF", ""))
    sha = env.get("GITHUB_SHA", "")
    try:
        attempt = int(env.get("GITHUB_RUN_ATTEMPT", ""))
    except ValueError:
        raise Reject("RERUN", "bad run_attempt")
    if attempt < 1 or attempt > 2:
        raise Reject("RERUN", f"run_attempt={attempt} exceeds retry bound (2)")

    if event == "push":
        with open(env["GITHUB_EVENT_PATH"]) as f:
            ev = json.load(f)
        before, after = ev.get("before", ""), ev.get("after", "")
        if after != sha or before in ("", ZERO_SHA):
            raise Reject("BASE_UNKNOWN", "push without a usable before/after pair")
        pkg, kind = classify_push(changed_files(repo_dir, before, after))
        d["pr"], d["merged_by"] = (lambda n, m: (str(n), m))(*check_provenance(api, sha))
        rnd = 1
        d["package_id"] = pkg
        rec_text = read_tree_file(repo_dir, sha, f"authz/{pkg}.json").decode()
        rec_raw = load_json_strict(rec_text, "authz record")
        if kind == "REVOKE_CANDIDATE":
            prev = load_json_strict(read_tree_file(repo_dir, before, f"authz/{pkg}.json").decode(), "prior record")
            same = {k: v for k, v in prev.items() if k != "status"} == {k: v for k, v in rec_raw.items() if k != "status"}
            if rec_raw.get("status") == "revoked" and prev.get("status") == "approved" and same:
                raise Reject("REVOKE_RECORDED", "valid revocation; no worker launched")
            raise Reject("AUTHZ_AMEND", "modification other than approved->revoked")
        allowed = [AUTHZ_PATH_RE, SPEC_PATH_RE]
    else:
        pkg = env.get("INPUT_PACKAGE_ID", "")
        if not PKG_RE.match(pkg):
            raise Reject("SCHEMA", "package_id input")
        d["package_id"] = pkg
        try:
            rnd = int(env.get("INPUT_ROUND", ""))
        except ValueError:
            raise Reject("ROUND_INVALID", "round input")
        d["merged_by"] = ""
        if env.get("GITHUB_ACTOR") != OWNER_LOGIN or env.get("TRIGGERING_ACTOR", "") != OWNER_LOGIN:
            raise Reject("ACTOR_MISMATCH", f"actor={env.get('GITHUB_ACTOR')}")
        if rnd < 2:
            raise Reject("ROUND_INVALID", "dispatch is for remediation rounds >= 2 only")
        rec_text = read_tree_file(repo_dir, sha, f"authz/{pkg}.json").decode()
        rec_raw = load_json_strict(rec_text, "authz record")
        allowed = [AUTHZ_PATH_RE, SPEC_PATH_RE]
    d["round"] = rnd

    rec = validate_record(rec_raw, pkg, now)
    d["authz_blob"] = git("rev-parse", f"{sha}:authz/{pkg}.json", cwd=repo_dir).stdout.strip()
    if rnd > rec["max_rounds"]:
        raise Reject("ROUND_LIMIT", f"round {rnd} > max_rounds {rec['max_rounds']}")
    check_baseline(repo_dir, rec, sha, allowed)
    if sha256_hex(read_tree_file(repo_dir, sha, rec["spec_path"])) != rec["spec_sha256"]:
        raise Reject("SPEC_MISMATCH", "spec sha256 differs from record")
    if rnd > 1:
        prev_sha = api.get_ref_sha(f"tags/{claim_ref(pkg, rnd - 1)}")
        if prev_sha is None:
            raise Reject("ROUND_GAP", f"no claim for round {rnd - 1}")
        msg = api.get_tag_message(prev_sha)
        if load_json_strict(msg, "prior claim").get("authz_blob_sha") != d["authz_blob"]:
            raise Reject("STALE_AUTHZ", "record changed since round 1")
    live_check(api, pkg, d["authz_blob"])
    if api.get_ref_sha(f"tags/{claim_ref(pkg, rnd)}") is not None:
        d["decision"], d["code"] = "DUPLICATE", "DUPLICATE"
        return
    d["decision"], d["code"] = "GO", "GO"


def main(env=None):
    from .common import GitHubAPI
    env = dict(os.environ if env is None else env)
    api = GitHubAPI(env.get("GITHUB_REPOSITORY", EXPECTED_REPO), env.get("GITHUB_TOKEN", ""))
    d = evaluate(env, api, ".")
    for k in ("decision", "code", "package_id", "round", "authz_blob"):
        v = str(d[k])
        write_output(k, v if re.fullmatch(r"[A-Za-z0-9_-]{0,64}", v) else "")
    summary(f"### Gate\n`{json.dumps(d, sort_keys=True)}`")
    return 1 if d["decision"] == "REJECT" else 0
