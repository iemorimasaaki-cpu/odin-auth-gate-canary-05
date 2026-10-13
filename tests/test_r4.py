"""R4 regression tests (owner-approved remediation round)."""
import datetime
import json
import unittest

from helpers import FakeAPI, NOW, PKG, Repo, record
from odin_gate import gate, publish, verify, worker_echo
from odin_gate.common import Reject, claim_ref, validate_record

TS = "%Y-%m-%dT%H:%M:%SZ"


def code(fn, *a):
    try:
        fn(*a)
    except Reject as r:
        return r.code
    return "OK"


class ValidityWindowTests(unittest.TestCase):
    def test_window_over_seven_days_rejected_exactly_seven_allowed(self):
        issued = NOW - datetime.timedelta(hours=1)
        ok = record(PKG, issued_at=issued.strftime(TS), expires_at=(issued + datetime.timedelta(days=7)).strftime(TS))
        self.assertEqual(code(validate_record, ok, PKG, NOW), "OK")
        over = dict(ok, expires_at=(issued + datetime.timedelta(days=7, seconds=1)).strftime(TS))
        self.assertEqual(code(validate_record, over, PKG, NOW), "SCHEMA")

    def test_not_yet_valid_boundary(self):
        def rec(offset):
            iss = NOW + datetime.timedelta(seconds=offset)
            return record(PKG, issued_at=iss.strftime(TS), expires_at=(iss + datetime.timedelta(days=1)).strftime(TS))
        self.assertEqual(code(validate_record, rec(300), PKG, NOW), "OK")  # skew allowance is inclusive
        self.assertEqual(code(validate_record, rec(301), PKG, NOW), "NOT_YET_VALID")


class PreviousRoundEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.r = Repo(); self.sha = self.r.authorize(); self.api = FakeAPI()
        self.blob = self.api.set_main_record(self.r)
        self.env = {"GITHUB_REPOSITORY": "iemorimasaaki-cpu/odin-auth-gate-canary-05", "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": self.sha, "GITHUB_ACTOR": "iemorimasaaki-cpu",
                    "TRIGGERING_ACTOR": "iemorimasaaki-cpu", "GITHUB_RUN_ATTEMPT": "1", "INPUT_PACKAGE_ID": PKG,
                    "INPUT_ROUND": "2"}
        c = self.api.create_tag_object("c", json.dumps({"authz_blob_sha": self.blob}), self.sha)
        self.api.create_ref(f"refs/tags/odin/claim/{PKG}/r1", c)

    def ev(self):
        return gate.evaluate(self.env, self.api, self.r.d, NOW)

    def add_evidence(self, **over):
        body = {"kind": "evidence", "package_id": PKG, "round": 1, "authz_blob_sha": self.blob}
        body.update(over)
        t = self.api.create_tag_object("e", json.dumps(body), self.sha)
        self.api.create_ref(f"refs/tags/odin/evidence/{PKG}/r1", t)

    def test_claim_without_evidence_is_round_gap_and_burns_nothing(self):
        d = self.ev()
        self.assertEqual((d["decision"], d["code"]), ("REJECT", "ROUND_GAP"))
        self.assertIn("no evidence", d["detail"])
        self.assertNotIn(f"refs/tags/odin/claim/{PKG}/r2", self.api.refs)

    def test_valid_evidence_allows_round_two(self):
        self.add_evidence()
        self.assertEqual(self.ev()["decision"], "GO")

    def test_malformed_or_stale_evidence_rejected(self):
        self.add_evidence(round=7)
        self.assertEqual(self.ev()["code"], "ROUND_GAP")
        self.api.refs.pop(f"refs/tags/odin/evidence/{PKG}/r1")
        self.add_evidence(kind="claim")
        self.assertEqual(self.ev()["code"], "ROUND_GAP")
        self.api.refs.pop(f"refs/tags/odin/evidence/{PKG}/r1")
        self.add_evidence(authz_blob_sha="9" * 40)
        self.assertEqual(self.ev()["code"], "STALE_AUTHZ")
        self.api.refs.pop(f"refs/tags/odin/evidence/{PKG}/r1")
        self.add_evidence(package_id="other-pkg")
        self.assertEqual(self.ev()["code"], "ROUND_GAP")

    def test_stale_claim_blob_rejected_even_when_evidence_matches(self):
        self.api.refs.clear()
        c = self.api.create_tag_object("c", json.dumps({"authz_blob_sha": "9" * 40}), self.sha)
        self.api.create_ref(f"refs/tags/odin/claim/{PKG}/r1", c)
        self.add_evidence()  # evidence carries the CURRENT blob
        self.assertEqual(self.ev()["code"], "STALE_AUTHZ")

    def test_publish_round_two_without_previous_evidence_is_round_gap(self):
        self.api.create_ref(f"refs/tags/{claim_ref(PKG, 2)}", "c")
        env = {"PACKAGE_ID": PKG, "ROUND": "2", "AUTHZ_BLOB": self.blob, "GITHUB_SHA": self.sha, "GITHUB_RUN_ID": "9",
               "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_ACTOR": "iemorimasaaki-cpu"}
        b = worker_echo.make_bundle(worker_echo.build_files(PKG, 2, "x", record(PKG)))
        before = list(self.api.writes)
        with self.assertRaises(Reject) as cm:
            publish.run_publish(env, self.api, self.r.d, b, NOW)
        self.assertEqual(cm.exception.code, "ROUND_GAP")
        self.assertEqual(self.api.writes, before)  # nothing written


class GitTildeSegmentTests(unittest.TestCase):
    def test_git_tilde_segments_rejected(self):
        rec = record(PKG)
        for seg in ("git~1", "GIT~1", "x~1", "git~"):
            self.assertEqual(code(verify.verify_files, {f"synthetic-out/{PKG}/{seg}/f": b"x"}, rec), "BAD_PATH", seg)
            self.assertEqual(code(verify.verify_files, {f"synthetic-out/{PKG}/{seg}": b"x"}, rec), "BAD_PATH", seg)


if __name__ == "__main__":
    unittest.main()
