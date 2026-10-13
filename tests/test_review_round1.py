"""Regression tests for independent-review round 1 findings."""
import json
import os
import subprocess
import sys
import unittest

from helpers import FakeAPI, NOW, PKG, Repo, push_env, record, sh
from odin_gate import gate, publish, verify, worker_echo
from odin_gate.common import AUTHZ_PATH_RE, PKG_RE, Reject, claim_ref, read_tree_file, sha256_hex


class NewlineFilenameTests(unittest.TestCase):
    def test_regexes_do_not_accept_trailing_newline(self):
        self.assertIsNone(AUTHZ_PATH_RE.match("authz/abc.json\n"))
        self.assertIsNone(PKG_RE.match("abc-d\n"))

    def test_junk_newline_files_cannot_launch_existing_package(self):
        r = Repo(); sha = r.authorize()  # package exists on main but was never claimed
        api = FakeAPI(); api.set_main_record(r)
        r.write(f"authz/{PKG}.json\n", "junk"); r.write(f"specs/{PKG}.md\n", "junk")
        sha2 = r.commit("junk"); api.add_pr(sha2)
        d = gate.evaluate(push_env(r, sha, sha2), api, r.d, NOW)
        self.assertEqual((d["decision"], d["code"]), ("REJECT", "GATE_CHANGE"))


class FileModeTests(unittest.TestCase):
    def test_symlink_and_exec_record_rejected(self):
        r = Repo(); spec = b"fixture: echo\nx\n"
        r.write(f"specs/{PKG}.md", spec)
        r.write("real.json", json.dumps(record(PKG, r.base, spec)))
        os.symlink("../real.json", os.path.join(r.d, f"authz/{PKG}.json")) if os.makedirs(os.path.join(r.d, "authz"), exist_ok=True) is None else None
        sha = r.commit("symlink record"); api = FakeAPI(); api.add_pr(sha)
        d = gate.evaluate(push_env(r, r.base, sha), api, r.d, NOW)
        self.assertEqual(d["code"], "GATE_CHANGE")  # real.json is outside authz/specs
        with self.assertRaises(Reject) as cm:
            read_tree_file(r.d, sha, f"authz/{PKG}.json")
        self.assertEqual(cm.exception.code, "BAD_FILE_MODE")

    def test_executable_spec_rejected(self):
        r = Repo(); sha = r.authorize()
        sh(r.d, "git", "update-index", "--chmod=+x", f"specs/{PKG}.md"); sh(r.d, "git", "commit", "-qm", "x")
        head = sh(r.d, "git", "rev-parse", "HEAD")
        with self.assertRaises(Reject) as cm:
            read_tree_file(r.d, head, f"specs/{PKG}.md")
        self.assertEqual(cm.exception.code, "BAD_FILE_MODE")


class PullLookupTests(unittest.TestCase):
    def test_eventual_consistency_retry_then_success(self):
        r = Repo(); sha = r.authorize(); api = FakeAPI(); api.set_main_record(r)
        calls = []
        orig = api.commit_pulls

        def lagging(s):
            calls.append(s)
            return [] if len(calls) < 3 else orig(s)
        api.commit_pulls = lagging; api.add_pr(sha)
        d = gate.evaluate(push_env(r, r.base, sha), api, r.d, NOW)
        self.assertEqual((d["decision"], len(calls)), ("GO", 3))

    def test_picks_pr_whose_merge_commit_matches(self):
        r = Repo(); sha = r.authorize(); api = FakeAPI(); api.set_main_record(r)
        api.commits_pulls[sha] = [{"number": 1, "merged_at": "x", "base": {"ref": "main"}},
                                  {"number": 2, "merged_at": "x", "base": {"ref": "main"}}]
        api.pulls[1] = {"number": 1, "merged": True, "merge_commit_sha": "e" * 40, "merged_by": {"login": "mallory"}}
        api.pulls[2] = {"number": 2, "merged": True, "merge_commit_sha": sha, "merged_by": {"login": "iemorimasaaki-cpu"}}
        self.assertEqual(gate.evaluate(push_env(r, r.base, sha), api, r.d, NOW)["pr"], "2")

    def test_missing_triggering_actor_rejected(self):
        r = Repo(); sha = r.authorize(); api = FakeAPI(); api.set_main_record(r)
        env = {"GITHUB_REPOSITORY": "iemorimasaaki-cpu/odin-auth-gate-canary-05", "GITHUB_EVENT_NAME": "workflow_dispatch",
               "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": sha, "GITHUB_ACTOR": "iemorimasaaki-cpu",
               "GITHUB_RUN_ATTEMPT": "1", "INPUT_PACKAGE_ID": PKG, "INPUT_ROUND": "2"}
        self.assertEqual(gate.evaluate(env, api, r.d, NOW)["code"], "ACTOR_MISMATCH")


class PublishResumeTests(unittest.TestCase):
    def setup(self):
        r = Repo(); sha = r.authorize(); api = FakeAPI(); blob = api.set_main_record(r)
        api.create_ref(f"refs/tags/{claim_ref(PKG, 1)}", "c")
        env = {"PACKAGE_ID": PKG, "ROUND": "1", "AUTHZ_BLOB": blob, "GITHUB_SHA": sha, "GITHUB_RUN_ID": "9",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push", "GITHUB_ACTOR": "iemorimasaaki-cpu"}
        b = worker_echo.make_bundle(worker_echo.build_files(PKG, 1, "x", record(PKG)))
        return r, api, env, b

    def test_resume_after_branch_created_but_evidence_missing(self):
        r, api, env, b = self.setup()
        publish.run_publish(env, api, r.d, b, NOW)
        del api.refs[f"refs/tags/odin/evidence/{PKG}/r1"]  # simulate failure after branch creation
        branch, _ = publish.run_publish(env, api, r.d, b, NOW)  # failed-job re-run completes the evidence
        self.assertIn(f"refs/tags/odin/evidence/{PKG}/r1", api.refs)

    def test_foreign_branch_not_adopted(self):
        r, api, env, b = self.setup()
        api.commit_objs["f" * 40] = ("evil", "treeEVIL", [])
        api.refs[f"refs/heads/odin/{PKG}/r1"] = "f" * 40
        with self.assertRaises(Reject) as cm:
            publish.run_publish(env, api, r.d, b, NOW)
        self.assertEqual(cm.exception.code, "ALREADY_PUBLISHED")
        self.assertNotIn(f"refs/tags/odin/evidence/{PKG}/r1", api.refs)


class PathAllowlistTests(unittest.TestCase):
    def test_exotic_paths_rejected(self):
        rec = record(PKG)
        for bad in (f"synthetic-out/{PKG}/.GIT/x", f"synthetic-out/{PKG}/git~1/x", f"synthetic-out/{PKG}/x.",
                    f"synthetic-out/{PKG}/é.txt", f"synthetic-out/{PKG}/A.txt", f"synthetic-out/{PKG}/a b.txt",
                    f"synthetic-out/{PKG}/.hidden", f"synthetic-out/{PKG}/a::$DATA"):
            with self.assertRaises(Reject, msg=bad) as cm:
                verify.verify_files({bad: b"x"}, rec)
            self.assertIn(cm.exception.code, ("BAD_PATH", "FORBIDDEN_PATH"), bad)


class MaxSizeTests(unittest.TestCase):
    def test_max_size_bundle_passes_and_fits_env(self):
        rec = record(PKG, max_patch_bytes=49152, max_files=2)
        files = worker_echo.build_files(PKG, 1, "fixture: max-size\n", rec)
        self.assertEqual(sum(map(len, files.values())), 49152)
        verify.verify_files(files, rec)
        bundle = worker_echo.make_bundle(files)
        self.assertLess(len(bundle), verify.MAX_BUNDLE_CHARS)
        out = subprocess.run([sys.executable, "-c", "import os;print(len(os.environ['B']))"], env={"B": bundle},
                             capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), str(len(bundle)))
        self.assertEqual(verify.decode_bundle(bundle).keys(), files.keys())


if __name__ == "__main__":
    unittest.main()


class Round2Tests(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

    def test_pinned_tools_tree_matches_repo(self):
        import re
        wf = open(os.path.join(self.ROOT, ".github/workflows/gate.yml")).read()
        pin = re.search(r"ODIN_TOOLS_TREE: ([0-9a-f]{40})\n", wf)
        self.assertIsNotNone(pin, "workflow pin missing or placeholder")
        # compare against the COMMITTED tools tree of the working HEAD (tests run on a clean checkout)
        out = sh(self.ROOT, "git", "rev-parse", "HEAD:tools")
        dirty = sh(self.ROOT, "git", "status", "--porcelain", "--", "tools")
        self.assertEqual(dirty, "", "tools/ has uncommitted changes; pin cannot be checked")
        self.assertEqual(pin.group(1), out)

    def test_cwd_shadow_module_is_not_loaded_with_dash_P(self):
        import tempfile
        d = tempfile.mkdtemp(); marker = os.path.join(d, "PWNED")
        for mod in ("json", "base64", "re", "subprocess", "hashlib", "datetime"):
            open(os.path.join(d, mod + ".py"), "w").write(f"open({marker!r}, 'w').write('x')\n")
        tools = os.path.join(self.ROOT, "tools")
        subprocess.run([sys.executable, "-P", "-B", "-m", "odin_gate", "verify"], cwd=d, env={"PYTHONPATH": tools},
                       capture_output=True)
        self.assertFalse(os.path.exists(marker), "cwd module was imported despite -P")
        # control: WITHOUT -P the same shadowing does execute (proves the test can detect it)
        subprocess.run([sys.executable, "-B", "-m", "odin_gate", "verify"], cwd=d, env={"PYTHONPATH": tools},
                       capture_output=True)
        self.assertTrue(os.path.exists(marker))

    def test_file_directory_collision_rejected(self):
        rec = record(PKG)
        with self.assertRaises(Reject) as cm:
            verify.verify_files({f"synthetic-out/{PKG}/a": b"1", f"synthetic-out/{PKG}/a/b": b"2"}, rec)
        self.assertEqual(cm.exception.code, "PATH_COLLISION")

    def test_resume_requires_baseline_parent(self):
        r = Repo(); sha = r.authorize(); api = FakeAPI(); blob = api.set_main_record(r)
        api.create_ref(f"refs/tags/{claim_ref(PKG, 1)}", "c")
        env = {"PACKAGE_ID": PKG, "ROUND": "1", "AUTHZ_BLOB": blob, "GITHUB_SHA": sha, "GITHUB_RUN_ID": "9",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push", "GITHUB_ACTOR": "iemorimasaaki-cpu"}
        b = worker_echo.make_bundle(worker_echo.build_files(PKG, 1, "x", record(PKG)))
        publish.run_publish(env, api, r.d, b, NOW)
        del api.refs[f"refs/tags/odin/evidence/{PKG}/r1"]
        head = api.refs[f"refs/heads/odin/{PKG}/r1"]
        msg, tree, _ = api.commit_objs[head]
        api.commit_objs[head] = (msg, tree, ["d" * 40])  # same tree, different parent
        with self.assertRaises(Reject) as cm:
            publish.run_publish(env, api, r.d, b, NOW)
        self.assertEqual(cm.exception.code, "ALREADY_PUBLISHED")
