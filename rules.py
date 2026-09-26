"""Business rules for pharmacovigilance and privacy processing."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Any

ROLES = {"reporter", "regional_lead", "medical_reviewer", "global_admin"}
SUBMITTED = "submitted"


def report_deadline(received_at: datetime, serious: bool, fatal: bool) -> datetime:
    if serious:
        return received_at + timedelta(days=7 if fatal else 15)
    return received_at + timedelta(days=90)


def can_access(case: dict[str, Any], role: str, region: str) -> bool:
    return role in {"medical_reviewer", "global_admin"} or case["region"] == region


def case_summary(case: Any) -> dict[str, Any]:
    return {
        "case_id": case["id"],
        "case_no": case["case_no"],
        "region": case["region"],
        "product": case["product"],
        "event_term": case["event_term"],
        "status": case["status"],
        "revision": case["revision"],
        "due_at": case["report_due_at"],
    }


def unfinished_report_summary(report: Any) -> dict[str, Any]:
    return {
        "report_id": report["id"],
        "case_id": report["case_id"],
        "case_no": report["case_no"],
        "country": report["country"],
        "status": report["status"],
        "due_at": report["due_at"],
    }


def privacy_order(cases: list[Any], reports: list[Any], submitted_case_ids: set[int],
                  patient_ref: str, pseudonym: str | None = None) -> dict[str, Any]:
    """Build the regulatory snapshot needed before irreversible anonymization."""
    case_items = [case_summary(case) for case in cases]
    unfinished_reports = [unfinished_report_summary(report) for report in reports]
    pending_actions = [
        {
            "type": "regulatory_submission",
            "report_id": report["id"],
            "case_id": report["case_id"],
            "country": report["country"],
            "required_action": "submit_report",
            "due_at": report["due_at"],
            "status": report["status"],
        }
        for report in reports
    ]
    case_ids_with_submitted_report = set(submitted_case_ids)
    handled_case_ids = {report["case_id"] for report in reports} | case_ids_with_submitted_report
    regulatory_cases = [case for case in cases if case["status"] != "merged"]
    pending_actions.extend(
        {
            "type": "regulatory_submission",
            "report_id": None,
            "case_id": case["id"],
            "country": case["region"],
            "required_action": "create_and_submit_report",
            "due_at": case["report_due_at"],
            "status": "not_created",
        }
        for case in regulatory_cases if case["id"] not in handled_case_ids
    )
    blockers = [
        f"报告 {report['report_id']}（案例 {report['case_no']}/{report['country']}）尚未提交"
        for report in unfinished_reports
    ]
    blockers.extend(
        f"案例 {case['case_no']} 尚无已提交监管报告（{case['region']}）"
        for case in regulatory_cases if case["id"] not in handled_case_ids
    )
    pending_actions.sort(key=lambda action: action["due_at"])
    order: dict[str, Any] = {
        "patient_ref": patient_ref,
        "same_patient_cases": case_items,
        "unfinished_reports": unfinished_reports,
        "pending_regulatory_actions": pending_actions,
        "blocking_reasons": blockers,
        "ready": not blockers,
    }
    if pseudonym is not None:
        order["pseudonym"] = pseudonym
    return order


def patient_key_hash(patient_ref: str, salt: str) -> str:
    digest = hmac.new(salt.encode("utf-8"), patient_ref.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def irreversible_pseudonym() -> str:
    return f"PSEUDO-{secrets.token_hex(12).upper()}"


def redacted_intake_payload() -> dict[str, str]:
    return {"_redacted": "原始录入内容已在隐私处置后清除"}


REDACTED_TEXT = "原始录入内容已在隐私处置后清除"
