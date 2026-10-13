import base64
import json
import unittest

from helpers import FakeAPI, NOW, PKG, Repo, record
from odin_gate import publish, verify, worker_echo
from odin_gate.common import Reject, sha256_hex, claim_ref

REC = record(PKG)


def bundle(files, **tamper):
    ents = []
    for p, b in files.items():
        e = {"path": p, "size": len(b), "sha256": sha256_hex(b), "b64": base64.b64encode(b).decode()}
        e.update({k: v for k, v in tamper.items()})
        ents.append(e)
    return json.dumps({"schema": "odin-bundle/1", "files": ents})


GOOD = {f"synthetic-out/{PKG}/a.txt": b"hello\n"}


def code(fn, *a):
    try:
        fn(*a)
    except Reject as r:
        return r.code
    return "OK"


class VerifyTests(unittest.TestCase):
    def v(self, files):
        return verify.verify_files(files, REC)

    def test_good(self):
        self.assertEqual(self.v(GOOD)["total_bytes"], 6)

    def test_rejections(self):
        p = f"synthetic-out/{PKG}"
        cases = {
            "OUT_OF_SCOPE": {"synthetic-out/other/x": b"x"},
            "FORBIDDEN_PATH": {".github/workflows/x.yml": b"x"},
            "BAD_PATH": {f"{p}/../../etc/x": b"x"},
            "BAD_PATH2": {"/abs/x": b"x"},
            "PATH_COLLISION": {f"{p}/A.txt": b"1", f"{p}/a.txt": b"2"},
            "EMPTY_OUTPUT": {},
            "TOO_MANY_FILES": {f"{p}/{i}": b"x" for i in range(4)},
            "TOO_LARGE": {f"{p}/big": b"x" * 1025},
            "OUT_OF_SCOPE2": {"synthetic-out/demo-package-evil/x": b"x"},
            "FORBIDDEN_PATH2": {f"{p}/.git/config": b"x"},
        }
        for name, files in cases.items():
            c = code(self.v, files)
            self.assertNotEqual(c, "OK", name)
        self.assertEqual(code(self.v, cases["OUT_OF_SCOPE"]), "OUT_OF_SCOPE")
        self.assertEqual(code(self.v, cases["OUT_OF_SCOPE2"]), "OUT_OF_SCOPE")
        self.assertEqual(code(self.v, cases["TOO_LARGE"]), "TOO_LARGE")
        self.assertEqual(code(self.v, cases["TOO_MANY_FILES"]), "TOO_MANY_FILES")
        self.assertEqual(code(self.v, cases["PATH_COLLISION"]), "PATH_COLLISION")
        self.assertEqual(code(self.v, cases["FORBIDDEN_PATH"]), "FORBIDDEN_PATH")
        self.assertEqual(code(self.v, cases["BAD_PATH"]), "BAD_PATH")

    def test_decode_checks_real_bytes(self):
        self.assertEqual(code(verify.decode_bundle, bundle(GOOD, size=1)), "MANIFEST_MISMATCH")
        self.assertEqual(code(verify.decode_bundle, bundle(GOOD, sha256="0" * 64)), "MANIFEST_MISMATCH")
        self.assertEqual(code(verify.decode_bundle, "not json"), "SCHEMA")
        self.assertEqual(code(verify.decode_bundle, "x" * 200000), "BUNDLE_TOO_LARGE")
        dup = json.loads(bundle(GOOD)); dup["files"] *= 2
        self.assertEqual(code(verify.decode_bundle, json.dumps(dup)), "DUPLICATE_PATH")
        self.assertEqual(code(verify.decode_bundle, json.dumps({"schema": "odin-bundle/1", "files": [], "extra": 1})), "BUNDLE_SCHEMA")


class WorkerFixtureTests(unittest.TestCase):
    def test_fixtures_vs_verify(self):
        expect = {"echo": "OK", "out-of-scope": "OUT_OF_SCOPE", "oversize": "TOO_LARGE",
                  "forbidden-path": "FORBIDDEN_PATH", "too-many-files": "TOO_MANY_FILES"}
        for fx, want in expect.items():
            files = worker_echo.build_files(PKG, 1, f"fixture: {fx}\n", REC)
            self.assertEqual(code(verify.verify_files, files, REC), want, fx)

    def test_unknown_fixture_and_determinism(self):
        self.assertEqual(code(worker_echo.build_files, PKG, 1, "fixture: rm-rf\n", REC), "FIXTURE_UNKNOWN")
        a = worker_echo.make_bundle(worker_echo.build_files(PKG, 1, "x", REC))
        b = worker_echo.make_bundle(worker_echo.build_files(PKG, 1, "x", REC))
        self.assertEqual(a, b)


class PublishTests(unittest.TestCase):
    def setup(self, spec=b"fixture: echo\nsynthetic\n"):
        r = Repo(); sha = r.authorize(spec=spec)
        api = FakeAPI(); blob = api.set_main_record(r)
        api.create_ref(f"refs/tags/{claim_ref(PKG, 1)}", "c")
        env = {"PACKAGE_ID": PKG, "ROUND": "1", "AUTHZ_BLOB": blob, "GITHUB_SHA": sha, "GITHUB_RUN_ID": "9",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push", "GITHUB_ACTOR": "iemorimasaaki-cpu"}
        return r, api, env

    def test_publish_creates_branch_and_evidence_once(self):
        r, api, env = self.setup()
        b = worker_echo.make_bundle(worker_echo.build_files(PKG, 1, "fixture: echo\n", record(PKG)))
        branch, commit = publish.run_publish(env, api, r.d, b, NOW)
        self.assertEqual(branch, f"odin/{PKG}/r1")
        self.assertIn(f"refs/heads/odin/{PKG}/r1", api.refs)
        self.assertIn(f"refs/tags/odin/evidence/{PKG}/r1", api.refs)
        self.assertEqual(api.commit_objs[commit][2], [record(PKG, r.base)["baseline_sha"]])
        self.assertEqual(code(publish.run_publish, env, api, r.d, b, NOW), "ALREADY_PUBLISHED")

    def test_publish_refuses_out_of_scope_even_if_verify_job_skipped(self):
        r, api, env = self.setup()
        files = worker_echo.build_files(PKG, 1, "fixture: out-of-scope\n", record(PKG))
        self.assertEqual(code(publish.run_publish, env, api, r.d, worker_echo.make_bundle(files), NOW), "OUT_OF_SCOPE")
        self.assertEqual([w for w in api.writes if "heads" in w], [])

    def test_publish_requires_claim_and_live_authz(self):
        r, api, env = self.setup()
        b = worker_echo.make_bundle(worker_echo.build_files(PKG, 1, "x", record(PKG)))
        api.refs.clear()
        self.assertEqual(code(publish.run_publish, env, api, r.d, b, NOW), "NO_CLAIM")
        api.create_ref(f"refs/tags/{claim_ref(PKG, 1)}", "c")
        rec = json.loads(api.main_contents[f"authz/{PKG}.json"][1]); rec["status"] = "revoked"
        api.main_contents[f"authz/{PKG}.json"] = ("7" * 40, json.dumps(rec))
        self.assertEqual(code(publish.run_publish, env, api, r.d, b, NOW), "REVOKED")
        self.assertEqual([w for w in api.writes if "heads" in w or "evidence" in w], [])

    def test_evidence_chain(self):
        r, api, env = self.setup()
        b1 = worker_echo.make_bundle(worker_echo.build_files(PKG, 1, "x", record(PKG)))
        publish.run_publish(env, api, r.d, b1, NOW)
        api.create_ref(f"refs/tags/{claim_ref(PKG, 2)}", "c")
        env2 = dict(env, ROUND="2")
        b2 = worker_echo.make_bundle(worker_echo.build_files(PKG, 2, "x", record(PKG)))
        publish.run_publish(env2, api, r.d, b2, NOW)
        ev2 = json.loads(api.tags[api.refs[f"refs/tags/odin/evidence/{PKG}/r2"]])
        ev1 = api.tags[api.refs[f"refs/tags/odin/evidence/{PKG}/r1"]]
        self.assertEqual(ev2["prev_evidence_sha256"], sha256_hex(ev1.encode()))


if __name__ == "__main__":
    unittest.main()
