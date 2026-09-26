import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, PharmacovigilanceService, iso, utcnow
from rules import REDACTED_TEXT


class PrivacyDisposalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.svc = PharmacovigilanceService(Path(self.tmp.name) / "test.db", privacy_salt="unit-test-salt")
        self.now = iso(utcnow())

    def tearDown(self):
        self.tmp.cleanup()

    def case(self, patient="P-1", dedupe="intake-1", region="CN", serious=True, fatal=False):
        return self.svc.create_case(
            "reporter-a", "reporter", region,
            {"patient_ref": patient, "region": region, "product": "DrugA", "event_term": "肝损伤",
             "source": "email", "dedupe_key": dedupe, "received_at": self.now,
             "serious": serious, "fatal": fatal},
        )["case"]

    def request(self, patient="P-1"):
        return self.svc.create_privacy_request("global-admin", "global_admin", {"patient_ref": patient})

    def test_pending_request_lists_cases_reports_actions_and_blocker(self):
        first = self.case("P-1", "intake-1")
        second = self.case("P-1", "intake-2")
        report = self.svc.create_report(first["id"], "lead-cn", "regional_lead", "CN", {"country": "CN"})

        response = self.request()
        self.assertEqual(response["request"]["status"], "pending")
        self.assertFalse(response["order"]["ready"])
        self.assertEqual([row["case_id"] for row in response["order"]["same_patient_cases"]],
                         [first["id"], second["id"]])
        self.assertEqual(response["order"]["unfinished_reports"][0]["report_id"], report["id"])
        self.assertEqual(response["order"]["pending_regulatory_actions"][0]["required_action"], "submit_report")
        self.assertIn(str(report["id"]), response["order"]["blocking_reasons"][0])

        blocked = self.svc.execute_privacy_request(response["request"]["id"], "global-admin", "global_admin")
        self.assertFalse(blocked["executed"])
        self.assertEqual(blocked["request"]["status"], "pending")
        first_after = self.svc.get_case(first["id"], "global_admin", "")
        self.assertEqual(first_after["case"]["patient_ref"], "P-1")

    def test_repeated_request_returns_first_request_until_report_settled_then_anonymizes(self):
        case = self.case()
        report = self.svc.create_report(case["id"], "lead-cn", "regional_lead", "CN", {"country": "CN"})
        self.svc.add_followup(
            case["id"], "reporter-a", "reporter", "CN",
            {"content": "患者提供含姓名和联系方式的随访说明", "source": "phone",
             "expected_revision": 1, "received_at": self.now},
        )
        self.svc.medical_review(
            case["id"], "reviewer-1", "medical_reviewer",
            {"expected_revision": 2, "serious": True, "fatal": False,
             "causality": "possibly_related", "rationale": "随访病史含可识别患者信息", "received_at": self.now},
        )
        first = self.request()
        duplicate = self.request()

        self.assertTrue(duplicate["idempotent"])
        self.assertEqual(duplicate["request"]["id"], first["request"]["id"])

        self.svc.submit_report(report["id"], "lead-cn", "regional_lead", "CN", {})
        replayed_pending = self.request()
        self.assertTrue(replayed_pending["idempotent"])
        self.assertEqual(replayed_pending["order"]["blocking_reasons"], first["order"]["blocking_reasons"])
        self.assertTrue(replayed_pending["request"]["current_order"]["ready"])

        executed = self.svc.execute_privacy_request(first["request"]["id"], "global-admin", "global_admin")
        self.assertTrue(executed["executed"])
        self.assertEqual(executed["request"]["status"], "anonymized")
        pseudonym = executed["request"]["pseudonym"]
        self.assertTrue(pseudonym.startswith("PSEUDO-"))
        stored = self.svc.repo.conn.execute(
            "SELECT patient_ref,order_json,result_json FROM privacy_requests WHERE id=?",
            (first["request"]["id"],),
        ).fetchone()
        self.assertIsNone(stored["patient_ref"])
        self.assertNotIn("P-1", stored["order_json"])
        self.assertNotIn("P-1", stored["result_json"])

        detail = self.svc.get_case(case["id"], "global_admin", "")
        self.assertEqual(detail["case"]["patient_ref"], pseudonym)
        self.assertEqual(detail["reports"][0]["status"], "submitted")
        self.assertEqual(detail["intakes"][0]["dedupe_key"], f"REDACTED-{detail['intakes'][0]['id']}")
        intake = self.svc.repo.conn.execute("SELECT payload_json FROM intakes WHERE case_id=?", (case["id"],)).fetchone()
        self.assertEqual(json.loads(intake["payload_json"])["_redacted"], "原始录入内容已在隐私处置后清除")
        self.assertEqual(detail["followups"][0]["content"], REDACTED_TEXT)
        self.assertEqual(detail["reviews"][0]["rationale"], REDACTED_TEXT)
        self.assertTrue(any(row["action"] == "patient_anonymized" for row in detail["audit"]))

        replayed = self.request()
        self.assertTrue(replayed["idempotent"])
        self.assertEqual(replayed["request"]["id"], first["request"]["id"])
        self.assertEqual(replayed["request"]["status"], "anonymized")
        self.assertEqual(replayed["order"]["pseudonym"], pseudonym)
        self.assertNotIn("patient_ref", replayed["order"])
        self.assertNotIn("patient_ref", replayed["request"])

    def test_missing_regulatory_report_blocks_until_report_is_created_and_submitted(self):
        case = self.case(serious=False)
        response = self.request()
        self.assertEqual(response["request"]["status"], "pending")
        self.assertFalse(response["order"]["ready"])
        self.assertEqual(response["order"]["unfinished_reports"], [])
        self.assertEqual(response["order"]["pending_regulatory_actions"][0]["required_action"],
                         "create_and_submit_report")
        self.assertIn(case["case_no"], response["order"]["blocking_reasons"][0])

        report = self.svc.create_report(case["id"], "lead-cn", "regional_lead", "CN", {"country": "CN"})
        still_blocked = self.svc.execute_privacy_request(response["request"]["id"], "global-admin", "global_admin")
        self.assertFalse(still_blocked["executed"])
        self.svc.submit_report(report["id"], "lead-cn", "regional_lead", "CN", {})
        executed = self.svc.execute_privacy_request(response["request"]["id"], "global-admin", "global_admin")
        self.assertTrue(executed["executed"])
        self.assertEqual(executed["request"]["status"], "anonymized")

    def test_settled_report_allows_immediate_anonymization(self):
        case = self.case(serious=False)
        report = self.svc.create_report(case["id"], "lead-cn", "regional_lead", "CN", {"country": "CN"})
        self.svc.submit_report(report["id"], "lead-cn", "regional_lead", "CN", {})

        response = self.request()
        self.assertEqual(response["request"]["status"], "anonymized")
        self.assertTrue(response["order"]["ready"])
        self.assertEqual(response["order"]["unfinished_reports"], [])
        self.assertEqual(response["order"]["pending_regulatory_actions"], [])
        self.assertTrue(response["order"]["pseudonym"].startswith("PSEUDO-"))
        self.assertEqual(self.svc.get_case(case["id"], "global_admin", "")["case"]["patient_ref"],
                         response["order"]["pseudonym"])

    def test_privacy_requires_global_admin(self):
        self.case()
        with self.assertRaises(ApiError) as ctx:
            self.svc.create_privacy_request("reporter-a", "reporter", {"patient_ref": "P-1"})
        self.assertEqual(ctx.exception.status, 403)


if __name__ == "__main__":
    unittest.main()
