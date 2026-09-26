"""SQLite persistence for pharmacovigilance records."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from errors import ApiError
from rules import REDACTED_TEXT, SUBMITTED


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    current = value or utcnow()
    return current.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str | None, default: datetime | None = None) -> datetime:
    if not value:
        if default is None:
            raise ApiError(400, "missing_time", "必须提供 ISO 8601 时间")
        return default
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiError(400, "invalid_time", f"时间格式错误: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class Repository:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.init_schema()

    @contextmanager
    def tx(self):
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_no TEXT NOT NULL UNIQUE,
                patient_ref TEXT NOT NULL,
                region TEXT NOT NULL,
                product TEXT NOT NULL,
                event_term TEXT NOT NULL,
                onset_at TEXT,
                received_at TEXT NOT NULL,
                serious INTEGER NOT NULL DEFAULT 0,
                fatal INTEGER NOT NULL DEFAULT 0,
                causality TEXT,
                report_due_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                revision INTEGER NOT NULL DEFAULT 1,
                merged_into INTEGER REFERENCES cases(id),
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS intakes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER REFERENCES cases(id),
                source TEXT NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                received_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS followups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id),
                content TEXT NOT NULL,
                source TEXT NOT NULL,
                received_at TEXT NOT NULL,
                revision INTEGER NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(case_id, revision)
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id),
                country TEXT NOT NULL,
                due_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                submitted_at TEXT,
                submitted_by TEXT,
                late INTEGER NOT NULL DEFAULT 0,
                UNIQUE(case_id, country)
            );
            CREATE TABLE IF NOT EXISTS medical_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id),
                case_revision INTEGER NOT NULL,
                serious INTEGER NOT NULL,
                fatal INTEGER NOT NULL,
                causality TEXT NOT NULL,
                rationale TEXT NOT NULL,
                reviewer TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(case_id, case_revision)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                actor TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS privacy_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_no TEXT NOT NULL UNIQUE,
                patient_ref TEXT,
                patient_key_hash TEXT NOT NULL UNIQUE,
                pseudonym TEXT UNIQUE,
                status TEXT NOT NULL CHECK(status IN ('pending','anonymized')),
                order_json TEXT NOT NULL,
                result_json TEXT,
                requested_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                anonymized_at TEXT
            );
            CREATE TABLE IF NOT EXISTS privacy_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                privacy_request_id INTEGER NOT NULL REFERENCES privacy_requests(id),
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cases_patient_ref ON cases(patient_ref);
            CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
            """
        )
        columns = self.conn.execute("PRAGMA table_info(privacy_requests)").fetchall()
        if columns and not any(column["name"] == "patient_key_hash" for column in columns):
            self.conn.execute("ALTER TABLE privacy_requests ADD COLUMN patient_key_hash TEXT")
        self.conn.execute(
            "UPDATE privacy_requests SET patient_key_hash='legacy-'||lower(hex(randomblob(16))) WHERE patient_key_hash IS NULL"
        )
        self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_privacy_patient_key ON privacy_requests(patient_key_hash)"
        )

    @staticmethod
    def audit(conn: sqlite3.Connection, case_id: int | None, actor: str, role: str, action: str, detail: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO audit_log(case_id,actor,role,action,detail_json,created_at) VALUES(?,?,?,?,?,?)",
            (case_id, actor, role, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), iso()),
        )

    @staticmethod
    def row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    def get_case(self, conn: sqlite3.Connection, case_id: int) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not row:
            raise ApiError(404, "case_not_found", "案例不存在")
        return row

    def cases_for_patient(self, conn: sqlite3.Connection, patient_ref: str) -> list[sqlite3.Row]:
        return list(conn.execute(
            "SELECT * FROM cases WHERE patient_ref=? ORDER BY received_at,id",
            (patient_ref,),
        ))

    def unfinished_reports_for_cases(self, conn: sqlite3.Connection, case_ids: list[int]) -> list[sqlite3.Row]:
        if not case_ids:
            return []
        marks = ",".join("?" for _ in case_ids)
        return list(conn.execute(
            f"""SELECT r.*,c.case_no FROM reports r JOIN cases c ON c.id=r.case_id
                WHERE r.status!=? AND r.case_id IN ({marks}) ORDER BY r.due_at,r.id""",
            [SUBMITTED, *case_ids],
        ))

    def submitted_case_ids(self, conn: sqlite3.Connection, case_ids: list[int]) -> set[int]:
        if not case_ids:
            return set()
        marks = ",".join("?" for _ in case_ids)
        rows = conn.execute(
            f"SELECT DISTINCT case_id FROM reports WHERE status=? AND case_id IN ({marks})",
            [SUBMITTED, *case_ids],
        ).fetchall()
        return {row["case_id"] for row in rows}

    def privacy_request_by_patient(self, conn: sqlite3.Connection, patient_key: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM privacy_requests WHERE patient_key_hash=? ORDER BY id LIMIT 1",
            (patient_key,),
        ).fetchone()

    def privacy_request_by_id(self, conn: sqlite3.Connection, request_id: int) -> sqlite3.Row | None:
        return conn.execute("SELECT * FROM privacy_requests WHERE id=?", (request_id,)).fetchone()

    def list_privacy_requests(self, conn: sqlite3.Connection) -> list[sqlite3.Row]:
        return list(conn.execute("SELECT * FROM privacy_requests ORDER BY id DESC"))

    def privacy_events(self, conn: sqlite3.Connection, request_id: int) -> list[sqlite3.Row]:
        return list(conn.execute(
            "SELECT id,actor,action,detail_json,created_at FROM privacy_events WHERE privacy_request_id=? ORDER BY id",
            (request_id,),
        ))

    def insert_privacy_request(self, conn: sqlite3.Connection, values: dict[str, Any]) -> int:
        cursor = conn.execute(
            """INSERT INTO privacy_requests(request_no,patient_ref,patient_key_hash,pseudonym,status,order_json,
               result_json,requested_by,created_at,updated_at,anonymized_at)
               VALUES(:request_no,:patient_ref,:patient_key_hash,:pseudonym,:status,:order_json,:result_json,
                      :requested_by,:created_at,:updated_at,:anonymized_at)""",
            values,
        )
        return int(cursor.lastrowid)

    def add_privacy_event(self, conn: sqlite3.Connection, request_id: int, actor: str,
                          action: str, detail: dict[str, Any]) -> None:
        conn.execute(
            "INSERT INTO privacy_events(privacy_request_id,actor,action,detail_json,created_at) VALUES(?,?,?,?,?)",
            (request_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), iso()),
        )

    def update_privacy_request(self, conn: sqlite3.Connection, request_id: int, values: dict[str, Any]) -> None:
        values["id"] = request_id
        conn.execute(
            """UPDATE privacy_requests SET patient_ref=:patient_ref,pseudonym=:pseudonym,status=:status,
               order_json=:order_json,result_json=:result_json,updated_at=:updated_at,
               anonymized_at=:anonymized_at WHERE id=:id""",
            values,
        )

    def anonymize_patient_records(self, conn: sqlite3.Connection, patient_ref: str,
                                  pseudonym: str, redacted_payload: dict[str, Any], at: str) -> list[int]:
        case_rows = self.cases_for_patient(conn, patient_ref)
        case_ids = [row["id"] for row in case_rows]
        if not case_ids:
            return []
        marks = ",".join("?" for _ in case_ids)
        conn.execute(
            f"UPDATE cases SET patient_ref=?,revision=revision+1,updated_at=? WHERE patient_ref=? AND id IN ({marks})",
            [pseudonym, at, patient_ref, *case_ids],
        )
        conn.execute(
            f"""UPDATE intakes SET payload_json=?,dedupe_key='REDACTED-'||id
                WHERE case_id IN ({marks})""",
            [json.dumps(redacted_payload, ensure_ascii=False), *case_ids],
        )
        conn.execute(
            f"UPDATE followups SET content=? WHERE case_id IN ({marks})",
            [REDACTED_TEXT, *case_ids],
        )
        conn.execute(
            f"UPDATE medical_reviews SET rationale=? WHERE case_id IN ({marks})",
            [REDACTED_TEXT, *case_ids],
        )
        return case_ids
