import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import ApiError, PharmacovigilanceService, iso, utcnow
import privacy_rules


class PrivacyDisposalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.svc = PharmacovigilanceService(Path(self.tmp.name) / "test.db")

    def tearDown(self):
        self.tmp.cleanup()

    def make_case(self, patient_ref="P-9", dedupe="dk-1", region="CN"):
        return self.svc.create_case(
            "reporter-a", "reporter", region,
            {"patient_ref": patient_ref, "region": region, "product": "DrugA", "event_term": "肝损伤",
             "source": "email", "dedupe_key": dedupe, "received_at": iso(utcnow()), "serious": True},
        )["case"]

    def make_request(self, key="REQ-1", patient_ref="P-9"):
        return self.svc.create_privacy_request(
            "privacy-officer", "global_admin",
            {"request_key": key, "patient_ref": patient_ref, "reason": "患者行使匿名化权利"},
        )

    def test_blocked_until_reports_cleared_then_anonymized(self):
        case1 = self.make_case(dedupe="dk-1")
        case2 = self.make_case(dedupe="dk-2", region="US")  # 同患者跨区域案例
        other = self.make_case(patient_ref="P-10", dedupe="dk-3")
        self.svc.add_followup(case1["id"], "reporter-a", "reporter", "CN",
                              {"content": "患者姓名张三,电话138", "source": "phone", "expected_revision": 1})
        report = self.svc.create_report(case1["id"], "lead-cn", "regional_lead", "CN", {"country": "CN"})

        created = self.make_request()
        self.assertFalse(created["idempotent"])
        req = created["request"]
        self.assertEqual(req["status"], "pending")
        self.assertEqual(req["status_label"], "待处理")
        self.assertTrue(req["blocked"])
        self.assertEqual({c["id"] for c in req["cases"]}, {case1["id"], case2["id"]})
        self.assertEqual(len(req["open_reports"]), 1)
        self.assertIn("未提交", req["blocked_reasons"][0])
        self.assertIn("CN", req["blocked_reasons"][0])

        with self.assertRaises(ApiError) as ctx:
            self.svc.execute_privacy_request(req["id"], "privacy-officer", "global_admin")
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, "privacy_blocked")
        self.assertTrue(ctx.exception.details["blocked_reasons"])

        self.svc.submit_report(report["id"], "lead-cn", "regional_lead", "CN", {})
        executed = self.svc.execute_privacy_request(req["id"], "privacy-officer", "global_admin")
        self.assertFalse(executed["idempotent"])
        result = executed["request"]
        self.assertEqual(result["status_label"], "已脱敏")
        pseudonym = result["pseudonym"]
        self.assertTrue(pseudonym.startswith("ANON-"))
        self.assertNotIn("P-9", pseudonym)
        self.assertEqual(result["case_count"], 2)
        self.assertEqual(result["intakes_scrubbed"], 2)
        self.assertEqual(result["followups_scrubbed"], 1)

        # 同患者案例标识变为同一不可逆代号, 其他患者不受影响
        for cid in (case1["id"], case2["id"]):
            detail = self.svc.get_case(cid, "global_admin", "")
            self.assertEqual(detail["case"]["patient_ref"], pseudonym)
            self.assertEqual(detail["case"]["status"], "open")
            self.assertGreaterEqual(len(detail["audit"]), 1)
        self.assertEqual(self.svc.get_case(other["id"], "global_admin", "")["case"]["patient_ref"], "P-10")

        # 原始录入内容已清除, 报告与提交记录仍在
        raw = self.svc.repo.conn
        for payload, in raw.execute("SELECT payload_json FROM intakes"):
            self.assertNotIn("P-9", payload)
            self.assertNotIn("张三", payload)
        content = raw.execute("SELECT content FROM followups WHERE case_id=?", (case1["id"],)).fetchone()[0]
        self.assertEqual(content, privacy_rules.CLEARED_MARKER)
        kept = raw.execute("SELECT status,submitted_at,submitted_by FROM reports WHERE id=?", (report["id"],)).fetchone()
        self.assertEqual(kept["status"], "submitted")
        self.assertIsNotNone(kept["submitted_at"])

        # 处置审计保留, 且不泄露原始患者标识
        actions = [r["action"] for r in raw.execute(
            "SELECT action FROM audit_log WHERE case_id=? ORDER BY id", (case1["id"],))]
        self.assertIn("privacy_anonymized", actions)
        disposed = raw.execute("SELECT detail_json FROM audit_log WHERE action='privacy_request_executed'").fetchone()
        self.assertIsNotNone(disposed)
        self.assertNotIn("P-9", disposed["detail_json"])
        stored = raw.execute("SELECT patient_ref FROM privacy_requests WHERE id=?", (req["id"],)).fetchone()[0]
        self.assertEqual(stored, pseudonym)

    def test_same_request_replays_first_result(self):
        self.make_case(dedupe="dk-1")
        first = self.make_request()
        again = self.make_request()
        self.assertTrue(again["idempotent"])
        self.assertEqual(again["request"]["id"], first["request"]["id"])

        executed = self.svc.execute_privacy_request(first["request"]["id"], "privacy-officer", "global_admin")
        replayed = self.svc.execute_privacy_request(first["request"]["id"], "privacy-officer", "global_admin")
        self.assertTrue(replayed["idempotent"])
        self.assertEqual(replayed["request"], executed["request"])

        after = self.make_request()
        self.assertTrue(after["idempotent"])
        self.assertEqual(after["request"]["status"], "executed")
        self.assertEqual(after["request"]["pseudonym"], executed["request"]["pseudonym"])
        count = self.svc.repo.conn.execute("SELECT COUNT(*) FROM privacy_requests").fetchone()[0]
        self.assertEqual(count, 1)

    def test_permissions_and_unknown_patient(self):
        self.make_case(dedupe="dk-1")
        with self.assertRaises(ApiError) as ctx:
            self.svc.create_privacy_request("lead-cn", "regional_lead",
                                            {"request_key": "REQ-X", "patient_ref": "P-9", "reason": "x"})
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(ApiError) as ctx:
            self.svc.create_privacy_request("privacy-officer", "global_admin",
                                            {"request_key": "REQ-Y", "patient_ref": "P-NONE", "reason": "x"})
        self.assertEqual(ctx.exception.code, "no_patient_cases")
        req = self.make_request()["request"]
        with self.assertRaises(ApiError) as ctx:
            self.svc.execute_privacy_request(req["id"], "lead-cn", "regional_lead")
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(ApiError) as ctx:
            self.svc.list_privacy_requests("reporter")
        self.assertEqual(ctx.exception.status, 403)
        listed = self.svc.list_privacy_requests("medical_reviewer")
        self.assertEqual(listed[0]["request_key"], "REQ-1")

    def test_late_case_linked_and_pseudonym_deterministic(self):
        case1 = self.make_case(dedupe="dk-1")
        req = self.make_request()["request"]
        case2 = self.make_case(dedupe="dk-2")  # 登记后新录入的同患者案例
        executed = self.svc.execute_privacy_request(req["id"], "privacy-officer", "global_admin")["request"]
        self.assertEqual(executed["case_count"], 2)
        for cid in (case1["id"], case2["id"]):
            self.assertEqual(self.svc.get_case(cid, "global_admin", "")["case"]["patient_ref"],
                             executed["pseudonym"])
        self.assertEqual(privacy_rules.pseudonym_for("ab" * 32, "P-9"),
                         privacy_rules.pseudonym_for("ab" * 32, "P-9"))
        self.assertNotEqual(privacy_rules.pseudonym_for("ab" * 32, "P-9"),
                            privacy_rules.pseudonym_for("ab" * 32, "P-10"))


if __name__ == "__main__":
    unittest.main()
