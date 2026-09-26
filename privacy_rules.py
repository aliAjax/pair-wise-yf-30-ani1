"""隐私处置规则层。

与数据存储(app.Repository)和 HTTP 接口(app.Handler / static)分开维护:
- STATUS_* / STATUS_LABELS: 处置单状态与页面文案(待处理 / 已脱敏)
- SCRUB_POLICY: 执行脱敏时各表字段的处置方式
- pseudonym_for: 由 HMAC 密钥派生不可逆患者代号
- blocker_reasons: 由未结清报告生成阻塞原因文案
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any

STATUS_PENDING = "pending"
STATUS_EXECUTED = "executed"

STATUS_LABELS = {
    STATUS_PENDING: "待处理",
    STATUS_EXECUTED: "已脱敏",
}

PSEUDONYM_PREFIX = "ANON"
KEY_NAME = "pseudonym_hmac_key"
CLEARED_MARKER = "[已按隐私处置单清除]"

# 执行脱敏时的字段策略: pseudonym=替换为不可逆代号, clear=清除原始录入内容。
# 案例、报告、提交记录与审计行本身保留, 不在此策略内。
SCRUB_POLICY: dict[str, dict[str, str]] = {
    "cases": {"patient_ref": "pseudonym"},
    "intakes": {"payload_json": "clear"},
    "followups": {"content": "clear"},
}


def new_key() -> str:
    """生成新的 HMAC 密钥(十六进制)。密钥销毁后代号不可再推导。"""
    return secrets.token_hex(32)


def pseudonym_for(key_hex: str, patient_ref: str) -> str:
    """同一患者标识派生同一代号, 无法从代号反推原标识。"""
    digest = hmac.new(
        bytes.fromhex(key_hex), patient_ref.strip().encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{PSEUDONYM_PREFIX}-{digest[:20].upper()}"


def blocker_reasons(open_reports: list[dict[str, Any]]) -> list[str]:
    """把未完成报告/待发监管动作转成页面展示的阻塞原因。"""
    return [
        f"案例 {r['case_no']} 的 {r['country']} 报告(#{r['report_id']})未提交"
        f"(状态 {r['status']}, 到期 {r['due_at']})"
        for r in open_reports
    ]
