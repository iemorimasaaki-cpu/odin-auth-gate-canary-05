"""PUBLISH job logic: the only job (besides CLAIM) with a write token. No model/other secrets.

Re-runs VERIFY on the received bytes, re-checks revocation, then creates (create-only):
  refs/heads/odin/<pkg>/r<N>   result branch (parent = approved baseline)
  refs/tags/odin/evidence/<pkg>/r<N>  annotated evidence tag with hash chain
No PR, no merge, no workflow-file writes.
"""
import json
import os

from .common import (EXPECTED_REPO, GitHubAPI, Reject, canonical_json, claim_ref, evidence_ref, live_check,
                     sha256_hex, summary, utcnow, write_output)
from .verify import run_verify
import base64


def run_publish(env, api, repo_dir, bundle_text, now=None):
    now = now or utcnow()
    pkg, rnd, blob = env["PACKAGE_ID"], int(env["ROUND"]), env["AUTHZ_BLOB"]
    rec, files, manifest = run_verify(env, repo_dir, bundle_text, now)  # defense in depth
    live_check(api, pkg, blob)  # revocation before the write
    if api.get_ref_sha(f"tags/{claim_ref(pkg, rnd)}") is None:
        raise Reject("NO_CLAIM", "publish without a claim")
    prev = None
    if rnd > 1:
        ps = api.get_ref_sha(f"tags/{evidence_ref(pkg, rnd - 1)}")
        if ps is None:
            raise Reject("ROUND_GAP", "previous evidence missing")
        prev = sha256_hex(api.get_tag_message(ps).encode())
    baseline = rec["baseline_sha"]
    tree = api.create_tree(api.get_commit_tree(baseline), [
        {"path": f["path"], "mode": "100644", "type": "blob",
         "sha": api.create_blob(base64.b64encode(files[f["path"]]).decode())} for f in manifest["files"]])
    commit = api.create_commit(f"ODIN synthetic output {pkg} r{rnd}", tree, [baseline])
    branch = f"odin/{pkg}/r{rnd}"
    if not api.create_ref(f"refs/heads/{branch}", commit):
        # Partial-failure resume: accept an existing branch only if it holds exactly the verified tree
        # on the approved baseline and no evidence exists yet; otherwise it is a genuine duplicate.
        existing = api.get_ref_sha(f"heads/{branch}")
        if existing is None or api.get_commit_tree(existing) != tree or \
                api.get_commit_parents(existing) != [baseline] or \
                api.get_ref_sha(f"tags/{evidence_ref(pkg, rnd)}") is not None:
            raise Reject("ALREADY_PUBLISHED", branch)
        commit = existing
    evidence = {
        "kind": "evidence", "package_id": pkg, "round": rnd, "authz_blob_sha": blob,
        "spec_sha256": rec["spec_sha256"], "baseline_sha": baseline, "launch_sha": env["GITHUB_SHA"],
        "event": env["GITHUB_EVENT_NAME"], "actor": env.get("GITHUB_ACTOR", ""),
        "run_id": env["GITHUB_RUN_ID"], "run_attempt": env["GITHUB_RUN_ATTEMPT"],
        "result_commit": commit, "result_branch": branch,
        "verified_manifest_sha256": sha256_hex(canonical_json(manifest).encode()),
        "prev_evidence_sha256": prev, "published_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    tag_obj = api.create_tag_object(evidence_ref(pkg, rnd), canonical_json(evidence), commit)
    if not api.create_ref(f"refs/tags/{evidence_ref(pkg, rnd)}", tag_obj):
        raise Reject("EVIDENCE_EXISTS", evidence_ref(pkg, rnd))
    return branch, commit


def main(env=None):
    env = dict(os.environ if env is None else env)
    assert env.get("GITHUB_REPOSITORY") == EXPECTED_REPO
    api = GitHubAPI(EXPECTED_REPO, env["GITHUB_TOKEN"])
    try:
        branch, commit = run_publish(env, api, ".", env["BUNDLE"])
    except Reject as r:
        summary(f"### Publish\nREJECT {r.code}: {r.detail}")
        return 1
    summary(f"### Publish\nbranch `{branch}` -> `{commit}`")
    return 0
