import json
import unittest

from helpers import FakeAPI, NOW, PKG, Repo
from odin_gate import worker_echo
from odin_gate.common import ApiError, GitHubAPI, Reject


class StubAPI(GitHubAPI):
    def __init__(self, exc):
        super().__init__("o/r", "t")
        self.exc = exc

    def request(self, method, path, body=None):
        raise self.exc


class CreateRefTests(unittest.TestCase):
    def test_only_already_exists_422_is_duplicate(self):
        self.assertFalse(StubAPI(ApiError(422, '{"message":"Reference already exists"}')).create_ref("refs/tags/x", "a" * 40))
        for exc in (ApiError(422, '{"message":"Object does not exist"}'), ApiError(403, "forbidden"), ApiError(500, "x")):
            with self.assertRaises(ApiError):
                StubAPI(exc).create_ref("refs/tags/x", "a" * 40)

    def test_get_ref_404_none_other_raises(self):
        self.assertIsNone(StubAPI(ApiError(404, "nf")).get_ref_sha("tags/x"))
        with self.assertRaises(ApiError):
            StubAPI(ApiError(500, "x")).get_ref_sha("tags/x")


class WorkerRunTests(unittest.TestCase):
    def test_worker_stops_when_revoked_or_spec_changed(self):
        r = Repo(); sha = r.authorize(); api = FakeAPI(); blob = api.set_main_record(r)
        env = {"PACKAGE_ID": PKG, "ROUND": "1", "AUTHZ_BLOB": blob}
        self.assertIn("odin-bundle/1", worker_echo.run_worker(env, api, r.d, NOW))
        rec = json.loads(api.main_contents[f"authz/{PKG}.json"][1]); rec["status"] = "revoked"
        api.main_contents[f"authz/{PKG}.json"] = ("5" * 40, json.dumps(rec))
        with self.assertRaises(Reject) as cm:
            worker_echo.run_worker(env, api, r.d, NOW)
        self.assertEqual(cm.exception.code, "REVOKED")
        r.write(f"specs/{PKG}.md", "tampered"); r.commit("tamper")
        api.main_contents[f"authz/{PKG}.json"] = (blob, json.dumps(json.loads(open(r.d + f"/authz/{PKG}.json").read())))
        with self.assertRaises(Reject) as cm:
            worker_echo.run_worker(env, api, r.d, NOW)
        self.assertEqual(cm.exception.code, "SPEC_MISMATCH")


class SlowFixtureTests(unittest.TestCase):
    def test_revocation_during_sleep_stops_worker(self):
        r = Repo(); r.authorize(spec=b"fixture: slow\nx\n"); api = FakeAPI(); blob = api.set_main_record(r)
        env = {"PACKAGE_ID": PKG, "ROUND": "1", "AUTHZ_BLOB": blob}
        slept = []

        def revoke_while_asleep(sec):
            slept.append(sec)
            rec = json.loads(api.main_contents[f"authz/{PKG}.json"][1]); rec["status"] = "revoked"
            api.main_contents[f"authz/{PKG}.json"] = ("6" * 40, json.dumps(rec))
        with self.assertRaises(Reject) as cm:
            worker_echo.run_worker(env, api, r.d, NOW, sleep_fn=revoke_while_asleep)
        self.assertEqual((slept, cm.exception.code), ([90], "REVOKED"))


if __name__ == "__main__":
    unittest.main()
