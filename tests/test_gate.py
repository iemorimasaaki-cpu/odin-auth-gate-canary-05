import json
import os
import threading
import unittest

from helpers import FakeAPI, NOW, PKG, Repo, push_env, record, sh
from odin_gate import claim, gate
from odin_gate.common import OWNER_LOGIN


def launch(**over):
    """Return (repo, api, env, sha) for a valid launch commit unless overridden."""
    r = Repo()
    spec = over.pop("spec", b"fixture: echo\nsynthetic\n")
    sha = r.authorize(spec=spec, **over)
    api = FakeAPI()
    api.add_pr(sha)
    api.set_main_record(r)
    return r, api, push_env(r, r.base, sha), sha


def ev(r, api, env):
    return gate.evaluate(env, api, r.d, NOW)


class GateTests(unittest.TestCase):
    def test_go(self):
        r, api, env, _ = launch()
        d = ev(r, api, env)
        self.assertEqual((d["decision"], d["code"], d["round"], d["merged_by"]), ("GO", "GO", 1, OWNER_LOGIN))

    def test_no_pr_direct_push(self):
        r, api, env, sha = launch()
        api.commits_pulls.clear()
        self.assertEqual(ev(r, api, env)["code"], "NO_PR")

    def test_unmerged_pr(self):
        r, api, env, sha = launch()
        api.add_pr(sha, merged=False)
        self.assertEqual(ev(r, api, env)["code"], "NO_PR")

    def test_merger_mismatch(self):
        r, api, env, sha = launch()
        api.add_pr(sha, merged_by="someone-else")
        self.assertEqual(ev(r, api, env)["code"], "MERGER_MISMATCH")

    def test_merge_commit_mismatch(self):
        r, api, env, sha = launch()
        api.add_pr(sha, merge_sha="a" * 40)
        self.assertEqual(ev(r, api, env)["code"], "NOT_MERGE_COMMIT")

    def test_gate_change_mixed_with_authz(self):
        r = Repo()
        r.write(".github/workflows/gate.yml", "name: changed\n")
        sha = r.authorize()
        api = FakeAPI(); api.add_pr(sha); api.set_main_record(r)
        self.assertEqual(ev(r, api, push_env(r, r.base, sha))["code"], "GATE_CHANGE")

    def test_baseline_drift_gate_changed_before_launch(self):
        r = Repo()
        r.write(".github/workflows/gate.yml", "name: sneaky\n")
        r.commit("sneaky change after baseline")
        before = sh(r.d, "git", "rev-parse", "HEAD")
        sha = r.authorize(baseline=r.base)  # baseline predates the sneaky gate change
        api = FakeAPI(); api.add_pr(sha); api.set_main_record(r)
        self.assertEqual(ev(r, api, push_env(r, before, sha))["code"], "GATE_CHANGE")

    def test_baseline_not_ancestor(self):
        r, api, env, _ = launch(baseline="f" * 40)
        self.assertEqual(ev(r, api, env)["code"], "BASELINE_DRIFT")

    def test_expired_exclusive_boundary(self):
        r, api, env, _ = launch(expires_at="2026-10-14T00:00:00Z")
        self.assertEqual(ev(r, api, env)["code"], "EXPIRED")
        r, api, env, _ = launch(expires_at="2026-10-14T00:00:01Z")
        self.assertEqual(ev(r, api, env)["code"], "GO")

    def test_revoked_record_rejected(self):
        r, api, env, _ = launch(status="revoked")
        self.assertEqual(ev(r, api, env)["code"], "REVOKED")

    def test_scope_outside_package_dir(self):
        r, api, env, _ = launch(scope_paths=["synthetic-out/other/"])
        self.assertEqual(ev(r, api, env)["code"], "SCOPE")
        r, api, env, _ = launch(scope_paths=["synthetic-out/demo-package/../x"])
        self.assertEqual(ev(r, api, env)["code"], "SCOPE")

    def test_schema_extra_key_and_dup_key(self):
        r, api, env, _ = launch(unexpected=1)
        self.assertEqual(ev(r, api, env)["code"], "SCHEMA")
        r = Repo()
        r.write("specs/demo-package.md", "x")
        r.write("authz/demo-package.json", '{"schema":"a","schema":"b"}')
        sha = r.commit("dup")
        api = FakeAPI(); api.add_pr(sha)
        self.assertEqual(ev(r, api, push_env(r, r.base, sha))["code"], "SCHEMA")

    def test_spec_hash_mismatch(self):
        r = Repo()
        r.write("specs/demo-package.md", "tampered\n")
        r.write("authz/demo-package.json", json.dumps(record(baseline=r.base)))
        sha = r.commit("x")
        api = FakeAPI(); api.add_pr(sha); api.set_main_record(r)
        self.assertEqual(ev(r, api, push_env(r, r.base, sha))["code"], "SPEC_MISMATCH")

    def test_rerun_bound(self):
        r, api, env, _ = launch()
        env["GITHUB_RUN_ATTEMPT"] = "3"
        self.assertEqual(ev(r, api, env)["code"], "RERUN")
        env["GITHUB_RUN_ATTEMPT"] = "2"
        self.assertEqual(ev(r, api, env)["decision"], "GO")  # pre-claim retry allowed once

    def test_rerun_after_claim_is_duplicate(self):
        r, api, env, _ = launch()
        api.create_ref(f"refs/tags/odin/claim/{PKG}/r1", "x")
        env["GITHUB_RUN_ATTEMPT"] = "2"
        d = ev(r, api, env)
        self.assertEqual((d["decision"], d["code"]), ("DUPLICATE", "DUPLICATE"))

    def test_event_not_allowed(self):
        r, api, env, _ = launch()
        for name in ("issue_comment", "pull_request_target", "schedule", "workflow_run", "issues", "label"):
            env["GITHUB_EVENT_NAME"] = name
            self.assertEqual(ev(r, api, env)["code"], "EVENT_NOT_ALLOWED", name)

    def test_repo_and_ref_mismatch(self):
        r, api, env, _ = launch()
        e = dict(env, GITHUB_REPOSITORY="iemorimasaaki-cpu/other")
        self.assertEqual(ev(r, api, e)["code"], "REPO_MISMATCH")
        e = dict(env, GITHUB_REF="refs/heads/impl")
        self.assertEqual(ev(r, api, e)["code"], "REF_NOT_MAIN")

    def test_spec_only_change(self):
        r, api, env, sha = launch()
        r.write(f"specs/{PKG}.md", "mutated\n")
        sha2 = r.commit("spec mutate")
        api.add_pr(sha2)
        self.assertEqual(ev(r, api, push_env(r, sha, sha2))["code"], "NO_AUTHZ")

    def test_multi_package(self):
        r = Repo()
        r.authorize(pkg="pkg-one"); sha = r.authorize(pkg="pkg-two")
        r2 = Repo()
        for p in ("pkg-one", "pkg-two"):
            r2.write(f"specs/{p}.md", "fixture: echo\nsynthetic\n")
            r2.write(f"authz/{p}.json", json.dumps(record(p, r2.base)))
        sha = r2.commit("both")
        api = FakeAPI(); api.add_pr(sha)
        self.assertEqual(ev(r2, api, push_env(r2, r2.base, sha))["code"], "MULTI_PACKAGE")

    def test_amend_vs_revoke(self):
        r, api, env, sha = launch()
        base_rec = json.load(open(os.path.join(r.d, f"authz/{PKG}.json")))

        def amend(rec, parent):
            r.write(f"authz/{PKG}.json", json.dumps(rec))
            s = r.commit("amend")
            api.add_pr(s)
            return gate.evaluate(push_env(r, parent, s), api, r.d, NOW), s

        d, s2 = amend(dict(base_rec, max_files=9), sha)  # widening is not a routine launch
        self.assertEqual(d["code"], "AUTHZ_AMEND")
        d, s3 = amend(dict(base_rec, status="revoked", max_files=12), s2)  # revoke mixed with other edits
        self.assertEqual(d["code"], "AUTHZ_AMEND")
        d, s4 = amend(dict(base_rec, status="revoked"), s3)  # prior already revoked and fields differ
        self.assertEqual(d["code"], "AUTHZ_AMEND")
        r.write(f"authz/{PKG}.json", json.dumps(base_rec)); s5 = r.commit("restore")
        d, _ = amend(dict(base_rec, status="revoked"), s5)  # pure approved->revoked
        self.assertEqual((d["decision"], d["code"]), ("NOOP", "REVOKE_RECORDED"))

    def test_live_revocation_after_merge(self):
        r, api, env, _ = launch()
        rec = json.load(open(os.path.join(r.d, f"authz/{PKG}.json"))); rec["status"] = "revoked"
        api.main_contents[f"authz/{PKG}.json"] = ("1" * 40, json.dumps(rec))
        self.assertEqual(ev(r, api, env)["code"], "REVOKED")
        api.main_contents[f"authz/{PKG}.json"] = ("2" * 40, json.dumps({"schema": "odin-authz/1"}))
        self.assertEqual(ev(r, api, env)["code"], "STALE_AUTHZ")


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.r, self.api, _, self.sha = launch()
        self.blob = self.api.main_contents[f"authz/{PKG}.json"][0]
        self.env = {"GITHUB_REPOSITORY": "iemorimasaaki-cpu/odin-auth-gate-canary-05", "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": self.sha, "GITHUB_ACTOR": OWNER_LOGIN,
                    "TRIGGERING_ACTOR": OWNER_LOGIN, "GITHUB_RUN_ATTEMPT": "1", "INPUT_PACKAGE_ID": PKG, "INPUT_ROUND": "2"}

    def prior_claim(self, blob=None):
        t = self.api.create_tag_object("c", json.dumps({"authz_blob_sha": blob or self.blob}), self.sha)
        self.api.create_ref(f"refs/tags/odin/claim/{PKG}/r1", t)

    def test_round_gap(self):
        self.assertEqual(ev(self.r, self.api, self.env)["code"], "ROUND_GAP")

    def test_round2_go_and_limits(self):
        self.prior_claim()
        self.assertEqual(ev(self.r, self.api, self.env)["decision"], "GO")
        self.env["INPUT_ROUND"] = "3"
        self.assertEqual(ev(self.r, self.api, self.env)["code"], "ROUND_LIMIT")
        self.env["INPUT_ROUND"] = "1"
        self.assertEqual(ev(self.r, self.api, self.env)["code"], "ROUND_INVALID")
        self.env["INPUT_ROUND"] = "x"
        self.assertEqual(ev(self.r, self.api, self.env)["code"], "ROUND_INVALID")

    def test_actor_and_stale(self):
        self.prior_claim()
        self.assertEqual(ev(self.r, self.api, dict(self.env, GITHUB_ACTOR="mallory"))["code"], "ACTOR_MISMATCH")
        self.assertEqual(ev(self.r, self.api, dict(self.env, TRIGGERING_ACTOR="mallory"))["code"], "ACTOR_MISMATCH")
        self.api.refs.clear(); self.prior_claim(blob="9" * 40)
        self.assertEqual(ev(self.r, self.api, self.env)["code"], "STALE_AUTHZ")

    def test_bad_inputs(self):
        self.assertEqual(ev(self.r, self.api, dict(self.env, INPUT_PACKAGE_ID="../x"))["code"], "SCHEMA")
        self.assertEqual(ev(self.r, self.api, dict(self.env, INPUT_PACKAGE_ID="nonexistent-pkg"))["code"], "NO_AUTHZ")
        self.assertEqual(ev(self.r, self.api, dict(self.env, GITHUB_REF="refs/heads/evil"))["code"], "REF_NOT_MAIN")

    def test_duplicate_round(self):
        self.prior_claim()
        self.api.create_ref(f"refs/tags/odin/claim/{PKG}/r2", "z")
        self.assertEqual(ev(self.r, self.api, self.env)["decision"], "DUPLICATE")


class ClaimTests(unittest.TestCase):
    def test_race_single_winner(self):
        r, api, env, sha = launch()
        blob = api.main_contents[f"authz/{PKG}.json"][0]
        cenv = {"PACKAGE_ID": PKG, "ROUND": "1", "AUTHZ_BLOB": blob, "GITHUB_SHA": sha, "GITHUB_RUN_ID": "1",
                "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push"}
        results, bar = [], threading.Barrier(30)

        def go():
            bar.wait()
            results.append(claim.run_claim(cenv, api, r.d, NOW))
        ts = [threading.Thread(target=go) for _ in range(30)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(results.count("claimed"), 1)
        self.assertEqual(results.count("duplicate"), 29)
        self.assertEqual(api.writes.count(f"refs/tags/odin/claim/{PKG}/r1"), 1)

    def test_claim_blocked_by_revocation_between_jobs(self):
        r, api, env, sha = launch()
        blob = api.main_contents[f"authz/{PKG}.json"][0]
        rec = json.load(open(os.path.join(r.d, f"authz/{PKG}.json"))); rec["status"] = "revoked"
        api.main_contents[f"authz/{PKG}.json"] = ("3" * 40, json.dumps(rec))
        from odin_gate.common import Reject
        cenv = {"PACKAGE_ID": PKG, "ROUND": "1", "AUTHZ_BLOB": blob, "GITHUB_SHA": sha, "GITHUB_RUN_ID": "1",
                "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push"}
        with self.assertRaises(Reject) as cm:
            claim.run_claim(cenv, api, r.d, NOW)
        self.assertEqual(cm.exception.code, "REVOKED")
        self.assertEqual(api.writes, [])


if __name__ == "__main__":
    unittest.main()
