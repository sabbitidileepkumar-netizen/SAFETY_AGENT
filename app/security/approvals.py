"""SQLite-backed role assignments, approval records, and simulated emergency state."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterator
import uuid

from app.security.permissions import Permission, UserRole, has_permission


class ApprovalError(ValueError):
    """An approval is absent, invalid, or already consumed."""


class ApprovalStore:
    ALLOWED_ACTIONS = {"LOCKDOWN", "RESET_LOCKDOWN", "QUARANTINE_FILE"}

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._memory_connection: sqlite3.Connection | None = None
        if db_path == ":memory:":
            self._memory_connection = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_connection.row_factory = sqlite3.Row
        else:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._memory_connection or sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            if connection is not self._memory_connection:
                connection.close()

    def _initialize(self) -> None:
        with self._lock, self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS security_roles (
                    role TEXT PRIMARY KEY
                );
                CREATE TABLE IF NOT EXISTS user_roles (
                    user_id TEXT PRIMARY KEY,
                    role TEXT NOT NULL REFERENCES security_roles(role),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS action_approvals (
                    approval_id TEXT PRIMARY KEY,
                    requester_user_id TEXT NOT NULL,
                    approver_user_id TEXT,
                    action TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    approved_at TEXT,
                    executed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS emergency_status (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    is_active INTEGER NOT NULL DEFAULT 0,
                    lockdown_level TEXT NOT NULL DEFAULT 'STANDARD',
                    reason TEXT NOT NULL DEFAULT 'None',
                    updated_at TEXT,
                    updated_by TEXT
                );
                CREATE TABLE IF NOT EXISTS quarantine_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    approval_id TEXT NOT NULL UNIQUE,
                    target_identifier TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'SIMULATED',
                    created_at TEXT NOT NULL
                );
                INSERT OR IGNORE INTO security_roles(role) VALUES ('USER'), ('ADMIN');
                INSERT OR IGNORE INTO emergency_status(id) VALUES (1);
                """
            )

    def ensure_user_role(self, user_id: str) -> UserRole:
        with self._lock, self._connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO user_roles(user_id, role, created_at) VALUES (?, 'USER', ?)",
                (user_id, datetime.now(timezone.utc).isoformat()),
            )
            row = conn.execute("SELECT role FROM user_roles WHERE user_id = ?", (user_id,)).fetchone()
            return UserRole(row["role"])

    def assign_role(self, user_id: str, role: UserRole) -> None:
        """Internal provisioning hook; no client request can grant roles."""
        with self._lock, self._connection() as conn:
            conn.execute(
                "INSERT INTO user_roles(user_id, role, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET role = excluded.role",
                (user_id, role.value, datetime.now(timezone.utc).isoformat()),
            )

    def request_approval(self, user_id: str, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        if action not in self.ALLOWED_ACTIONS:
            raise ApprovalError("Unsupported high-impact action")
        role = self.ensure_user_role(user_id)
        if not has_permission(role, Permission.REQUEST_HIGH_IMPACT_ACTION):
            raise ApprovalError("Role cannot request this action")
        approval_id = f"apr-{uuid.uuid4().hex}"
        requested_at = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connection() as conn:
            conn.execute(
                "INSERT INTO action_approvals(approval_id, requester_user_id, action, payload_json, status, requested_at) "
                "VALUES (?, ?, ?, ?, 'pending', ?)",
                (approval_id, user_id, action, json.dumps(payload, sort_keys=True), requested_at),
            )
        return {
            "mode": "SIMULATED",
            "approval_id": approval_id,
            "action": action,
            "status": "pending",
            "requested_at": requested_at,
            "message": "Action is pending an authenticated approval. No system changes have been made.",
        }

    def approve(self, approval_id: str, approver_user_id: str) -> dict[str, Any]:
        role = self.ensure_user_role(approver_user_id)
        if not has_permission(role, Permission.APPROVE_HIGH_IMPACT_ACTION):
            raise ApprovalError("Role cannot approve this action")
        approved_at = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT action, status FROM action_approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if not row:
                raise ApprovalError("Approval request not found")
            if row["status"] != "pending":
                raise ApprovalError("Only pending approval requests can be approved")
            conn.execute(
                "UPDATE action_approvals SET status = 'approved', approver_user_id = ?, approved_at = ? "
                "WHERE approval_id = ? AND status = 'pending'",
                (approver_user_id, approved_at, approval_id),
            )
        return {
            "mode": "SIMULATED",
            "approval_id": approval_id,
            "action": row["action"],
            "status": "approved",
            "approved_at": approved_at,
            "approved_by": approver_user_id,
            "message": "Approval is recorded. Execution remains simulated.",
        }

    def execute(self, approval_id: str, user_id: str) -> dict[str, Any]:
        role = self.ensure_user_role(user_id)
        if not has_permission(role, Permission.EXECUTE_APPROVED_ACTION):
            raise ApprovalError("Role cannot execute this action")
        executed_at = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM action_approvals WHERE approval_id = ?", (approval_id,)
            ).fetchone()
            if not row:
                raise ApprovalError("Approval request not found")
            if row["requester_user_id"] != user_id:
                raise ApprovalError("Only the requesting account can execute this approval")
            if row["status"] != "approved" or row["executed_at"] is not None:
                raise ApprovalError("A current, unused approval is required")
            changed = conn.execute(
                "UPDATE action_approvals SET status = 'executed', executed_at = ? "
                "WHERE approval_id = ? AND status = 'approved' AND executed_at IS NULL",
                (executed_at, approval_id),
            ).rowcount
            if changed != 1:
                raise ApprovalError("Approval has already been used")
            action = row["action"]
            payload = json.loads(row["payload_json"])
            if action == "LOCKDOWN":
                conn.execute(
                    "UPDATE emergency_status SET is_active = 1, lockdown_level = ?, reason = ?, updated_at = ?, updated_by = ? WHERE id = 1",
                    (payload["level"], payload["reason"], executed_at, user_id),
                )
                result: dict[str, Any] = {"status": "ACTIVE", "level": payload["level"], "reason": payload["reason"]}
            elif action == "RESET_LOCKDOWN":
                conn.execute(
                    "UPDATE emergency_status SET is_active = 0, lockdown_level = 'STANDARD', reason = 'Simulated reset', updated_at = ?, updated_by = ? WHERE id = 1",
                    (executed_at, user_id),
                )
                result = {"status": "RESET", "level": "STANDARD"}
            else:
                conn.execute(
                    "INSERT INTO quarantine_records(approval_id, target_identifier, reason, created_at) VALUES (?, ?, ?, ?)",
                    (approval_id, payload["target"], payload["reason"], executed_at),
                )
                record = conn.execute("SELECT last_insert_rowid() AS id").fetchone()
                result = {"status": "QUARANTINE_RECORDED", "record_id": record["id"], "target": payload["target"]}
        return {
            "mode": "SIMULATED",
            "approval_id": approval_id,
            "action": action,
            "executed_at": executed_at,
            "result": result,
            "message": "SIMULATED only: no host, file, process, or network state was changed.",
        }

    def status(self) -> dict[str, Any]:
        with self._lock, self._connection() as conn:
            row = conn.execute("SELECT * FROM emergency_status WHERE id = 1").fetchone()
            return {
                "mode": "SIMULATED",
                "is_active": bool(row["is_active"]),
                "lockdown_level": row["lockdown_level"],
                "reason": row["reason"],
                "updated_at": row["updated_at"],
                "updated_by": row["updated_by"],
            }

    def quarantine_records(self) -> dict[str, Any]:
        with self._lock, self._connection() as conn:
            rows = conn.execute("SELECT * FROM quarantine_records ORDER BY id DESC").fetchall()
            return {
                "mode": "SIMULATED",
                "count": len(rows),
                "quarantined_items": [dict(row) for row in rows],
            }

    def approvals_for(self, user_id: str) -> dict[str, Any]:
        with self._lock, self._connection() as conn:
            rows = conn.execute(
                "SELECT approval_id, action, status, requested_at, approved_at, executed_at "
                "FROM action_approvals WHERE requester_user_id = ? ORDER BY requested_at DESC",
                (user_id,),
            ).fetchall()
        return {"mode": "SIMULATED", "approvals": [dict(row) for row in rows]}
