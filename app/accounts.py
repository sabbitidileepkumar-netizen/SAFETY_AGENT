from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any
import uuid

from app.config import Settings
from app.crypto.engine import CryptoEngine
from app.models import (
    AccountResponse,
    AuthResponse,
    CredentialsRequest,
    OrderResponse,
    PaymentVerification,
    PlanName,
    UsageInfo,
    UserResponse,
)


@dataclass
class FamilyMember:
    id: str
    owner_id: str
    email: str
    relationship: str
    status: str
    created_at: str


@dataclass
class FamilyApprovalRequest:
    request_id: str
    owner_id: str
    requester_email: str
    target_url: str
    risk_level: str
    status: str  # "pending", "approved", "rejected"
    decision: str | None
    created_at: str


class AccountService:
    """Manages user accounts, plans, Razorpay payments, usage limits, and family circles."""

    PLAN_PRICING = {
        "pro_monthly": 19900,     # ₹199 in paise
        "pro_yearly": 199900,     # ₹1999 in paise
        "family_monthly": 34900,  # ₹349 in paise
    }

    def __init__(self, db_path: str = "./safenest_cache.db", settings: Settings | None = None) -> None:
        self.settings = settings or Settings.from_env()
        self.db_path = db_path
        self._lock = threading.Lock()
        self._shared_memory_conn: sqlite3.Connection | None = None

        if self.db_path == ":memory:":
            self._shared_memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_memory_conn.row_factory = sqlite3.Row
        else:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_memory_conn is not None:
            return self._shared_memory_conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        plan TEXT NOT NULL DEFAULT 'free',
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS sessions (
                        token TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS daily_checks (
                        identifier TEXT NOT NULL,
                        check_date TEXT NOT NULL,
                        count INTEGER NOT NULL DEFAULT 1,
                        PRIMARY KEY (identifier, check_date)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS family_members (
                        id TEXT PRIMARY KEY,
                        owner_id TEXT NOT NULL,
                        email TEXT NOT NULL,
                        relationship TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (owner_id) REFERENCES users(id)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS family_approvals (
                        request_id TEXT PRIMARY KEY,
                        owner_id TEXT NOT NULL,
                        requester_email TEXT NOT NULL,
                        target_url TEXT NOT NULL,
                        risk_level TEXT NOT NULL,
                        status TEXT NOT NULL,
                        decision TEXT,
                        created_at TEXT NOT NULL
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS privacy_settings (
                        user_id TEXT PRIMARY KEY,
                        allow_sms_to_gemini INTEGER NOT NULL DEFAULT 0,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                    """
                )
                conn.commit()

    # -------------------------------------------------------------------------
    # Authentication & Registration
    # -------------------------------------------------------------------------
    def register(self, credentials: CredentialsRequest) -> AuthResponse:
        salt = os.urandom(16)
        pwd_key, _ = CryptoEngine.derive_key_pbkdf2(credentials.password, salt=salt, iterations=100_000)
        pwd_hash = pwd_key.hex()
        user_id = f"usr-{uuid.uuid4().hex[:10]}"
        now_str = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id FROM users WHERE email = ?", (credentials.email,))
                if cur.fetchone():
                    raise ValueError("An account with this email already exists")

                cur.execute(
                    "INSERT INTO users (id, email, password_hash, salt, plan, created_at) VALUES (?, ?, ?, ?, 'free', ?)",
                    (user_id, credentials.email, pwd_hash, salt.hex(), now_str),
                )
                conn.commit()

        return self.login(credentials)

    def login(self, credentials: CredentialsRequest) -> AuthResponse:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id, email, password_hash, salt, plan FROM users WHERE email = ?", (credentials.email,))
                row = cur.fetchone()
                if not row:
                    raise ValueError("Invalid email or password")

                salt_bytes = bytes.fromhex(row["salt"])
                derived_key, _ = CryptoEngine.derive_key_pbkdf2(credentials.password, salt=salt_bytes, iterations=100_000)
                if derived_key.hex() != row["password_hash"]:
                    raise ValueError("Invalid email or password")

                token = f"tok-{uuid.uuid4().hex}{os.urandom(8).hex()}"
                expires_at = datetime.now(timezone.utc).timestamp() + self.settings.session_ttl_seconds
                cur.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)", (token, row["id"], expires_at))
                conn.commit()

                return AuthResponse(
                    access_token=token,
                    user=UserResponse(id=row["id"], email=row["email"], plan=row["plan"]),
                )

    def authenticate_token(self, token: str) -> UserResponse | None:
        now_ts = datetime.now(timezone.utc).timestamp()
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT u.id, u.email, u.plan, s.expires_at 
                    FROM sessions s JOIN users u ON s.user_id = u.id 
                    WHERE s.token = ?
                    """,
                    (token,),
                )
                row = cur.fetchone()
                if not row or row["expires_at"] < now_ts:
                    return None
                return UserResponse(id=row["id"], email=row["email"], plan=row["plan"])

    def get_privacy_settings(self, user_id: str) -> dict[str, bool]:
        """Return per-account external text-sharing preferences (deny by default)."""
        with self._lock:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT allow_sms_to_gemini FROM privacy_settings WHERE user_id = ?",
                    (user_id,),
                ).fetchone()
                return {"allow_sms_to_gemini": bool(row["allow_sms_to_gemini"]) if row else False}

    def set_sms_gemini_permission(self, user_id: str, enabled: bool) -> dict[str, bool]:
        """Persist explicit account consent before any SMS text is sent to Gemini."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO privacy_settings(user_id, allow_sms_to_gemini, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(user_id) DO UPDATE SET allow_sms_to_gemini = excluded.allow_sms_to_gemini, updated_at = excluded.updated_at",
                    (user_id, int(enabled), now),
                )
                conn.commit()
        return {"allow_sms_to_gemini": enabled}

    # -------------------------------------------------------------------------
    # Usage & Free Limit Enforcement
    # -------------------------------------------------------------------------
    def check_and_increment_usage(
        self,
        user: UserResponse | None,
        client_ip: str,
    ) -> tuple[bool, UsageInfo]:
        """Enforces 10 checks/day limit for free users; unlimited for Pro/Family."""
        plan: PlanName = user.plan if user else "free"
        identifier = f"usr:{user.id}" if user else f"ip:{client_ip}"
        today_str = date.today().isoformat()
        limit = self.settings.free_checks_per_day

        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT count FROM daily_checks WHERE identifier = ? AND check_date = ?",
                    (identifier, today_str),
                )
                row = cur.fetchone()
                used = row["count"] if row else 0

                if plan == "free" and used >= limit:
                    return False, UsageInfo(
                        plan=plan,
                        checks_used_today=used,
                        checks_remaining_today=0,
                    )

                new_count = used + 1
                cur.execute(
                    """
                    INSERT INTO daily_checks (identifier, check_date, count) 
                    VALUES (?, ?, 1)
                    ON CONFLICT(identifier, check_date) DO UPDATE SET count = count + 1
                    """,
                    (identifier, today_str),
                )
                conn.commit()

                remaining = None if plan != "free" else max(0, limit - new_count)
                return True, UsageInfo(
                    plan=plan,
                    checks_used_today=new_count,
                    checks_remaining_today=remaining,
                )

    # -------------------------------------------------------------------------
    # Payments & Razorpay Integration
    # -------------------------------------------------------------------------
    def create_order(
        self,
        user: UserResponse,
        plan_choice: str,
    ) -> OrderResponse:
        amount = self.PLAN_PRICING.get(plan_choice)
        if not amount:
            raise ValueError(f"Unknown plan selection: {plan_choice}")

        order_id = f"order_{uuid.uuid4().hex[:14]}"
        demo_mode = self.settings.payments_demo_mode or not self.settings.razorpay_enabled

        return OrderResponse(
            order_id=order_id,
            amount=amount,
            currency="INR",
            plan=plan_choice,  # type: ignore[arg-type]
            key_id=self.settings.razorpay_key_id,
            demo=demo_mode,
        )

    def verify_payment_and_upgrade(
        self,
        user: UserResponse,
        verification: PaymentVerification,
        target_plan: PlanName,
    ) -> bool:
        if self.settings.razorpay_webhook_secret:
            expected_payload = f"{verification.order_id}|{verification.payment_id}".encode("utf-8")
            expected_signature = hmac.new(
                self.settings.razorpay_webhook_secret.encode("utf-8"),
                expected_payload,
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected_signature, verification.signature):
                raise ValueError("Payment signature verification failed")

        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("UPDATE users SET plan = ? WHERE id = ?", (target_plan, user.id))
                conn.commit()
                return cur.rowcount > 0

    # -------------------------------------------------------------------------
    # Family Circle Module
    # -------------------------------------------------------------------------
    def invite_family_member(self, owner_id: str, email: str, relationship: str) -> FamilyMember:
        member_id = f"fam-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "INSERT INTO family_members (id, owner_id, email, relationship, status, created_at) VALUES (?, ?, ?, ?, 'active', ?)",
                    (member_id, owner_id, email, relationship, now_str),
                )
                conn.commit()
        return FamilyMember(member_id, owner_id, email, relationship, "active", now_str)

    def get_family_members(self, owner_id: str) -> list[dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM family_members WHERE owner_id = ?", (owner_id,))
                return [dict(r) for r in cur.fetchall()]

    def request_family_approval(
        self,
        owner_id: str,
        requester_email: str,
        target_url: str,
        risk_level: str,
    ) -> FamilyApprovalRequest:
        req_id = f"appr-{uuid.uuid4().hex[:8]}"
        now_str = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO family_approvals (request_id, owner_id, requester_email, target_url, risk_level, status, decision, created_at)
                    VALUES (?, ?, ?, ?, ?, 'pending', NULL, ?)
                    """,
                    (req_id, owner_id, requester_email, target_url, risk_level, now_str),
                )
                conn.commit()
        return FamilyApprovalRequest(req_id, owner_id, requester_email, target_url, risk_level, "pending", None, now_str)

    def resolve_family_approval(self, request_id: str, decision: str) -> dict[str, Any]:
        """decision: 'Looks fine' or 'Don't do it'"""
        valid_decisions = ["Looks fine", "Don't do it"]
        if decision not in valid_decisions:
            raise ValueError(f"Decision must be one of {valid_decisions}")

        status = "approved" if decision == "Looks fine" else "rejected"
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE family_approvals SET status = ?, decision = ? WHERE request_id = ?",
                    (status, decision, request_id),
                )
                conn.commit()

        voice_msg = (
            f"Family circle update: Decision is '{decision}'."
            if decision == "Looks fine"
            else "Family circle warning: Your family advises: 'Don't do it'. Do not proceed."
        )

        return {
            "request_id": request_id,
            "status": status,
            "decision": decision,
            "voice_notification": voice_msg,
        }
