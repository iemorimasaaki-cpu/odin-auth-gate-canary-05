"""CLAIM job logic: create-only annotated tag odin/claim/<pkg>/r<N>. Only write: that one ref."""
import json
import os

from .common import (EXPECTED_REPO, PKG_RE, Reject, claim_ref, live_check, sha256_hex, summary, utcnow,
                     validate_record, write_output, load_json_strict, GitHubAPI)


def run_claim(env, api, repo_dir, now=None):
    now = now or utcnow()
    pkg, rnd, blob = env["PACKAGE_ID"], int(env["ROUND"]), env["AUTHZ_BLOB"]
    if not PKG_RE.match(pkg):
        raise Reject("SCHEMA", "package_id")
    rec = validate_record(load_json_strict(open(os.path.join(repo_dir, f"authz/{pkg}.json")).read(), "record"), pkg, now)
    live_check(api, pkg, blob)  # revocation between GATE and CLAIM is caught here
    msg = json.dumps({
        "kind": "claim", "package_id": pkg, "round": rnd, "authz_blob_sha": blob,
        "spec_sha256": rec["spec_sha256"], "sha": env["GITHUB_SHA"], "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": env["GITHUB_RUN_ATTEMPT"], "event": env["GITHUB_EVENT_NAME"],
        "claimed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}, sort_keys=True)
    tag_obj = api.create_tag_object(claim_ref(pkg, rnd), msg, env["GITHUB_SHA"])
    created = api.create_ref(f"refs/tags/{claim_ref(pkg, rnd)}", tag_obj)  # atomic, create-only
    return "claimed" if created else "duplicate"


def main(env=None):
    env = dict(os.environ if env is None else env)
    assert env.get("GITHUB_REPOSITORY") == EXPECTED_REPO
    api = GitHubAPI(EXPECTED_REPO, env["GITHUB_TOKEN"])
    try:
        res = run_claim(env, api, ".")
    except Reject as r:
        write_output("claimed", "false")
        summary(f"### Claim\nREJECT {r.code}: {r.detail}")
        return 1
    write_output("claimed", "true" if res == "claimed" else "false")
    summary(f"### Claim\n{res}")
    return 0
