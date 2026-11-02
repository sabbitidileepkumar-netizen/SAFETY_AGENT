from __future__ import annotations

from dataclasses import asdict
import os
from pathlib import Path
from typing import Any, Literal

from fastapi import Body, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.accounts import AccountService
from app.agents.controller import ControllerAI
from app.blockchain.service import AuditLedgerService
from app.checker import Checker
from app.config import Settings
from app.crypto.engine import CryptoEngine
from app.models import (
    AccountResponse,
    AuthResponse,
    CheckRequest,
    CheckResponse,
    CredentialsRequest,
    DemoPaymentRequest,
    OrderResponse,
    PaymentVerification,
    PlanRequest,
    UsageInfo,
    UserResponse,
)
from app.pipeline import run_pipeline
from app.rate_limit import RateLimiter
from app.security.isolation_chamber import IsolationChamberManager
from app.security.approvals import ApprovalError, ApprovalStore
from app.security.permissions import Permission, has_permission
from app.security.private_space import PrivateSpaceManager
from app.security.sandbox import SandboxInspectionEngine


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------
class TriageRequest(BaseModel):
    url: str | None = None
    text: str | None = None


class PrivateTabOpenRequest(BaseModel):
    initial_url: str = "about:blank"


class PrivateTabNavigateRequest(BaseModel):
    tab_id: str
    url: str


class IsolationLaunchRequest(BaseModel):
    url: str
    allow_clipboard: bool = False


class EncryptRequest(BaseModel):
    plaintext: str
    associated_data: str | None = None


class DecryptRequest(BaseModel):
    ciphertext_b64: str
    nonce_b64: str
    associated_data: str | None = None


class MazeSealRequest(BaseModel):
    plaintext: str
    compartment_size: int = 128


class MazeSolveRequest(BaseModel):
    artifact: dict[str, Any]
    recovery_shares: list[str] | None = None


class AnnounceRequest(BaseModel):
    risk_level: str
    reason: str
    action_taken: str = "INSPECTED"
    telugu_reason: str | None = None


class PrivacySettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allow_sms_to_gemini: bool


class EmergencyApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(pattern=r"^(LOCKDOWN|RESET_LOCKDOWN|QUARANTINE_FILE)$")
    level: str = Field(default="HEIGHTENED", pattern=r"^(HEIGHTENED|FULL_CONTAINMENT)$")
    reason: str = Field(default="User requested simulated lockdown", max_length=500)
    target: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def require_quarantine_target(self) -> "EmergencyApprovalRequest":
        if self.action == "QUARANTINE_FILE" and not (self.target or "").strip():
            raise ValueError("target is required for a simulated file quarantine")
        return self


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern=r"^approve$")


class WiFiAssessmentRequest(BaseModel):
    ssid: str = Field(min_length=1, max_length=128)
    security_protocol: str = Field(default="OPEN", max_length=40)
    is_open: bool = False
    duplicate_ssid_count: int = Field(default=1, ge=1, le=100)
    captive_portal: bool = False
    dns_servers: list[str] = Field(default_factory=list, max_length=16)


class PipelineEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["link", "download", "wifi"]
    value: str = Field(min_length=1, max_length=4096)
    source: str = Field(min_length=1, max_length=80)


# -----------------------------------------------------------------------------
# Application Factory
# -----------------------------------------------------------------------------
def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_env()
    checker = Checker(active_settings)
    limiter = RateLimiter(active_settings.request_limit_per_minute)

    # Initialize Audit Ledger DB path
    if active_settings.database_path == ":memory:":
        audit_db_path = ":memory:"
    else:
        audit_db_path = str(Path(active_settings.database_path).with_name("safenest_audit_ledger.db"))

    crypto_engine = CryptoEngine()
    audit_ledger = AuditLedgerService(db_path=audit_db_path, crypto_engine=crypto_engine)
    accounts = AccountService(db_path=active_settings.database_path, settings=active_settings)
    approval_store = ApprovalStore(db_path=active_settings.database_path)
    private_space = PrivateSpaceManager()
    isolation_chamber = IsolationChamberManager()
    sandbox_engine = SandboxInspectionEngine()

    controller = ControllerAI(
        audit_ledger=audit_ledger,
        crypto_engine=crypto_engine,
        private_space=private_space,
        isolation_chamber=isolation_chamber,
        sandbox_engine=sandbox_engine,
        checker=checker,
    )

    api = FastAPI(
        title="Guard AI — Cybersecurity & Privacy Command Centre",
        version="2.0.0",
        description="Autonomous AI Cybersecurity Platform featuring Private Space, Isolation Chamber, Sandbox Lab, Cryptographic Maze, and Blockchain Audit.",
    )

    allowed_origins = [
        origin.strip()
        for origin in active_settings.cors_allowed_origins.split(",")
        if origin.strip()
    ] or ["*"]

    api.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount Static Directory if exists
    static_dir = Path("app/static")
    if static_dir.exists():
        api.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # -------------------------------------------------------------------------
    # Core Endpoints (Preserved)
    # -------------------------------------------------------------------------
    @api.get("/", response_class=HTMLResponse)
    def index() -> Any:
        template_file = Path("app/templates/index.html")
        if template_file.exists():
            return FileResponse(template_file)
        return HTMLResponse("<h1>Guard AI Command Centre Initialized</h1>")

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @api.post("/check", response_model=CheckResponse)
    def check(payload: CheckRequest, request: Request) -> CheckResponse:
        client_host = request.client.host if request.client else "unknown"
        if not limiter.allow(client_host):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        auth_header = request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else ""
        current_user = accounts.authenticate_token(token) if token else None

        allowed, usage_info = accounts.check_and_increment_usage(current_user, client_host)
        if not allowed:
            raise HTTPException(status_code=429, detail="Daily check limit reached (10 checks/day on free plan). Upgrade to Pro.")
        try:
            allow_sms = bool(
                current_user
                and accounts.get_privacy_settings(current_user.id)["allow_sms_to_gemini"]
            )
            result = checker.check(payload, allow_sms_to_gemini=allow_sms)
            result.usage = usage_info
            return result
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    # -------------------------------------------------------------------------
    # Central Orchestrator & Telemetry
    # -------------------------------------------------------------------------
    @api.get("/api/status")
    def get_status() -> dict[str, Any]:
        return controller.get_ecosystem_status()

    @api.post("/api/triage")
    def triage(payload: TriageRequest, request: Request) -> dict[str, Any]:
        if not payload.url and not payload.text:
            raise HTTPException(status_code=422, detail="Provide either 'url' or 'text'")
        user = authenticated_user(request)
        allow_sms = bool(user and accounts.get_privacy_settings(user.id)["allow_sms_to_gemini"])
        return controller.orchestrate_inspection(
            url=payload.url,
            text=payload.text,
            allow_sms_to_gemini=allow_sms,
        )

    @api.post("/api/pipeline/event")
    def pipeline_event(payload: PipelineEventRequest, request: Request) -> dict[str, Any]:
        client_host = request.client.host if request.client else "unknown"
        if not limiter.allow(client_host):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        return run_pipeline(controller, payload.type, payload.value, payload.source)

    @api.post("/api/wifi/assess")
    def assess_wifi(payload: WiFiAssessmentRequest) -> dict[str, Any]:
        return controller.wifi_agent.scan_network(
            ssid=payload.ssid,
            security_protocol=payload.security_protocol,
            is_open=payload.is_open,
            duplicate_ssid_count=payload.duplicate_ssid_count,
            captive_portal=payload.captive_portal,
            dns_servers=payload.dns_servers,
        )

    @api.get("/api/events")
    def get_events(limit: int = 50) -> list[dict[str, Any]]:
        return controller.bus.get_recent_events(limit)

    # -------------------------------------------------------------------------
    # Private Space Endpoints
    # -------------------------------------------------------------------------
    @api.post("/api/private-space/tabs")
    def open_private_tab(payload: PrivateTabOpenRequest) -> dict[str, Any]:
        tab = controller.private_space.open_tab(payload.initial_url)
        return asdict(tab)

    @api.get("/api/private-space/tabs")
    def list_private_tabs() -> dict[str, Any]:
        return controller.private_space.get_status()

    @api.post("/api/private-space/navigate")
    def navigate_private_tab(payload: PrivateTabNavigateRequest) -> dict[str, Any]:
        return controller.private_space.navigate_tab(payload.tab_id, payload.url)

    @api.delete("/api/private-space/tabs/{tab_id}")
    def close_private_tab(tab_id: str) -> dict[str, Any]:
        return controller.private_space.close_tab(tab_id)

    @api.post("/api/private-space/clear")
    def clear_private_space() -> dict[str, Any]:
        return controller.private_space.clear_all_sessions()

    # -------------------------------------------------------------------------
    # Isolation Chamber Endpoints
    # -------------------------------------------------------------------------
    @api.post("/api/isolation/launch")
    def launch_isolation(payload: IsolationLaunchRequest) -> dict[str, Any]:
        session = controller.isolation_chamber.launch_session(
            target_url=payload.url,
            allow_clipboard=payload.allow_clipboard,
        )
        return asdict(session)

    @api.get("/api/isolation/sessions")
    def list_isolation_sessions() -> dict[str, Any]:
        return controller.isolation_chamber.get_status()

    @api.get("/api/isolation/render/{session_id}")
    def render_isolated_page(session_id: str) -> dict[str, Any]:
        return controller.isolation_chamber.render_isolated_page(session_id)

    @api.post("/api/isolation/terminate/{session_id}")
    def terminate_isolation_session(session_id: str) -> dict[str, Any]:
        return controller.isolation_chamber.terminate_and_incinerate(session_id)

    # -------------------------------------------------------------------------
    # Sandbox Lab Endpoints
    # -------------------------------------------------------------------------
    @api.post("/api/sandbox/inspect")
    async def inspect_uploaded_file(file: UploadFile = File(...)) -> dict[str, Any]:
        contents = await file.read()
        if len(contents) > 25 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File exceeds 25MB analysis boundary")
        
        filename = file.filename or "submitted_payload.bin"
        report = controller.sandbox.inspect_file(contents, filename)
        return asdict(report)

    @api.get("/api/sandbox/reports")
    def list_sandbox_reports() -> list[dict[str, Any]]:
        return controller.sandbox.get_all_reports()

    @api.get("/api/sandbox/reports/{report_id}")
    def get_sandbox_report(report_id: str) -> dict[str, Any]:
        report = controller.sandbox.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Sandbox report not found")
        return asdict(report)

    # -------------------------------------------------------------------------
    # Cryptographic Engine & Maze Endpoints
    # -------------------------------------------------------------------------
    @api.post("/api/crypto/encrypt")
    def crypto_encrypt(payload: EncryptRequest) -> dict[str, Any]:
        ad_bytes = payload.associated_data.encode("utf-8") if payload.associated_data else None
        return controller.crypto.encrypt_aes_gcm(payload.plaintext, associated_data=ad_bytes)

    @api.post("/api/crypto/decrypt")
    def crypto_decrypt(payload: DecryptRequest) -> dict[str, Any]:
        ad_bytes = payload.associated_data.encode("utf-8") if payload.associated_data else None
        try:
            pt = controller.crypto.decrypt_aes_gcm(
                ciphertext_b64=payload.ciphertext_b64,
                nonce_b64=payload.nonce_b64,
                associated_data=ad_bytes,
            )
            return {"decrypted": pt.decode("utf-8", errors="replace")}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.post("/api/crypto/maze/seal")
    def maze_seal(payload: MazeSealRequest) -> dict[str, Any]:
        artifact = controller.defence.protect_payload_maze(payload.plaintext, compartment_size=payload.compartment_size)
        return asdict(artifact)

    @api.post("/api/crypto/maze/solve")
    def maze_solve(payload: MazeSolveRequest) -> dict[str, Any]:
        try:
            pt = controller.defence.solve_maze_payload(
                artifact=payload.artifact,
                recovery_shares=payload.recovery_shares,
            )
            return {
                "success": True,
                "decrypted_text": pt.decode("utf-8", errors="replace"),
                "integrity_status": "Verified Core Vault Signature & Segment Seals",
            }
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Cryptographic Maze Authentication Failed: {exc}") from exc

    @api.post("/api/crypto/rotate-key")
    def crypto_rotate_key() -> dict[str, Any]:
        record = controller.crypto.rotate_key("Manual administrator rotation")
        return asdict(record)

    @api.get("/api/crypto/keys")
    def crypto_get_keys() -> dict[str, Any]:
        return {
            "rotation_history": controller.crypto.get_rotation_history(),
            "system_public_key": controller.crypto.system_public_key_hex,
        }

    # -------------------------------------------------------------------------
    # Blockchain & Audit Registry Endpoints
    # -------------------------------------------------------------------------
    @api.get("/api/blockchain/records")
    def get_blockchain_records(limit: int = 50) -> list[dict[str, Any]]:
        return controller.audit.get_recent_records(limit)

    @api.get("/api/blockchain/verify-chain")
    def verify_audit_chain() -> dict[str, Any]:
        return controller.audit.verify_entire_chain()

    @api.post("/api/blockchain/tamper-demo")
    def tamper_demo() -> dict[str, Any]:
        records = controller.audit.get_recent_records(5)
        if not records:
            # Create a record first
            rec = controller.audit.register_security_event("BENCHMARK_EVENT", {"status": "seeded for tamper demo"})
            target_id = rec.record_id
        else:
            target_id = records[0]["record_id"]

        success = controller.audit.simulate_tampering_for_demo(target_id)
        return {
            "success": success,
            "tampered_record_id": target_id,
            "message": "Record was intentionally altered in the ledger DB. Run chain verification to witness cryptographic tamper detection.",
        }

    # -------------------------------------------------------------------------
    # Informer AI Voice Endpoints
    # -------------------------------------------------------------------------
    @api.post("/api/informer/announce")
    def generate_voice_announcement(payload: AnnounceRequest) -> dict[str, Any]:
        return controller.informer.generate_announcement(
            risk_level=payload.risk_level,
            reason=payload.reason,
            action_taken=payload.action_taken,
            telugu_reason=payload.telugu_reason,
        )

    # -------------------------------------------------------------------------
    # Accounts, Plans, & Family Circle Endpoints
    # -------------------------------------------------------------------------
    @api.post("/api/auth/register", response_model=AuthResponse)
    def register(payload: CredentialsRequest) -> AuthResponse:
        try:
            return accounts.register(payload)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.post("/api/auth/login", response_model=AuthResponse)
    def login(payload: CredentialsRequest) -> AuthResponse:
        try:
            return accounts.login(payload)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def authenticated_user(request: Request) -> UserResponse | None:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return None
        return accounts.authenticate_token(token.strip())

    def require_authenticated_user(request: Request) -> UserResponse:
        user = authenticated_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="A valid logged-in user token is required")
        approval_store.ensure_user_role(user.id)
        return user

    def require_emergency_user(request: Request) -> UserResponse:
        user = authenticated_user(request)
        if not user:
            raise HTTPException(
                status_code=401,
                detail={"mode": "SIMULATED", "error": "A valid logged-in user token is required"},
            )
        approval_store.ensure_user_role(user.id)
        return user

    @api.get("/api/settings/privacy")
    def get_privacy_settings(request: Request) -> dict[str, Any]:
        user = require_authenticated_user(request)
        return {"settings": accounts.get_privacy_settings(user.id)}

    @api.put("/api/settings/privacy")
    def update_privacy_settings(payload: PrivacySettingsUpdate, request: Request) -> dict[str, Any]:
        user = require_authenticated_user(request)
        return {
            "settings": accounts.set_sms_gemini_permission(user.id, payload.allow_sms_to_gemini)
        }

    @api.get("/api/emergency/status")
    def get_emergency_status(request: Request) -> dict[str, Any]:
        user = require_emergency_user(request)
        role = approval_store.ensure_user_role(user.id)
        if not has_permission(role, Permission.VIEW_EMERGENCY):
            raise HTTPException(status_code=403, detail={"mode": "SIMULATED", "error": "Role cannot view emergency status"})
        return approval_store.status()

    @api.get("/api/emergency/quarantine")
    def get_simulated_quarantine(request: Request) -> dict[str, Any]:
        require_emergency_user(request)
        return approval_store.quarantine_records()

    @api.get("/api/emergency/approvals")
    def get_emergency_approvals(request: Request) -> dict[str, Any]:
        user = require_emergency_user(request)
        return approval_store.approvals_for(user.id)

    @api.post("/api/emergency/approvals")
    def request_emergency_approval(payload: EmergencyApprovalRequest, request: Request) -> dict[str, Any]:
        user = require_emergency_user(request)
        action_payload = {
            "level": payload.level,
            "reason": payload.reason,
            "target": payload.target,
        }
        try:
            return approval_store.request_approval(user.id, payload.action, action_payload)
        except ApprovalError as exc:
            raise HTTPException(status_code=403, detail={"mode": "SIMULATED", "error": str(exc)}) from exc

    @api.post("/api/emergency/approvals/{approval_id}/approve")
    def approve_emergency_action(
        approval_id: str,
        payload: ApprovalDecisionRequest,
        request: Request,
    ) -> dict[str, Any]:
        user = require_emergency_user(request)
        try:
            return approval_store.approve(approval_id, user.id)
        except ApprovalError as exc:
            raise HTTPException(status_code=403, detail={"mode": "SIMULATED", "error": str(exc)}) from exc

    @api.post("/api/emergency/actions/{approval_id}/execute")
    def execute_emergency_action(approval_id: str, request: Request) -> dict[str, Any]:
        user = require_emergency_user(request)
        try:
            result = approval_store.execute(approval_id, user.id)
        except ApprovalError as exc:
            raise HTTPException(status_code=403, detail={"mode": "SIMULATED", "error": str(exc)}) from exc
        simulated = controller.offence.simulate_approved_action(
            action=result["action"],
            approval_id=approval_id,
            details=result["result"],
        )
        result["offence_agent"] = simulated
        return result

    @api.get("/api/auth/me", response_model=AccountResponse)
    def get_me(request: Request) -> AccountResponse:
        auth_header = request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else ""
        user = accounts.authenticate_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Unauthorized")
        client_host = request.client.host if request.client else "unknown"
        _, usage = accounts.check_and_increment_usage(user, client_host)
        return AccountResponse(
            user=user,
            checks_used_today=usage.checks_used_today - 1,  # Read-only check
            checks_remaining_today=usage.checks_remaining_today,
        )

    @api.post("/api/payments/order", response_model=OrderResponse)
    def create_payment_order(payload: PlanRequest, request: Request) -> OrderResponse:
        auth_header = request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else ""
        user = accounts.authenticate_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required to upgrade plan")
        try:
            return accounts.create_order(user, payload.plan)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.post("/api/payments/verify")
    def verify_payment(payload: PaymentVerification, plan: str, request: Request) -> dict[str, Any]:
        auth_header = request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else ""
        user = accounts.authenticate_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        target_plan: Any = "family" if "family" in plan else "pro"
        try:
            success = accounts.verify_payment_and_upgrade(user, payload, target_plan)
            return {"success": success, "upgraded_plan": target_plan}
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.post("/api/payments/demo-confirm")
    def confirm_demo_payment(payload: DemoPaymentRequest, plan: str, request: Request) -> dict[str, Any]:
        auth_header = request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else ""
        user = accounts.authenticate_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        target_plan: Any = "family" if "family" in plan else "pro"
        dummy_verif = PaymentVerification(
            order_id=payload.order_id,
            payment_id="pay_demo12345678",
            signature="0000000000000000000000000000000000000000000000000000000000000000",
        )
        success = accounts.verify_payment_and_upgrade(user, dummy_verif, target_plan)
        return {"success": success, "upgraded_plan": target_plan, "demo_mode": True}

    @api.post("/api/family/invite")
    def invite_family(payload: dict[str, str], request: Request) -> dict[str, Any]:
        auth_header = request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else ""
        user = accounts.authenticate_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        email = payload.get("email", "").strip()
        rel = payload.get("relationship", "Member").strip()
        if not email:
            raise HTTPException(status_code=422, detail="Member email required")
        member = accounts.invite_family_member(user.id, email, rel)
        return asdict(member)

    @api.get("/api/family/members")
    def list_family(request: Request) -> list[dict[str, Any]]:
        auth_header = request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else ""
        user = accounts.authenticate_token(token)
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        return accounts.get_family_members(user.id)

    @api.post("/api/family/ask-approval")
    def ask_approval(payload: dict[str, str], request: Request) -> dict[str, Any]:
        auth_header = request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else ""
        user = accounts.authenticate_token(token)
        owner_id = user.id if user else "guest_family"
        req_email = user.email if user else "user@safenest.local"
        url = payload.get("url", "")
        risk = payload.get("risk", "Careful")
        req = accounts.request_family_approval(owner_id, req_email, url, risk)
        return asdict(req)

    @api.post("/api/family/respond")
    def respond_approval(payload: dict[str, str]) -> dict[str, Any]:
        req_id = payload.get("request_id", "")
        decision = payload.get("decision", "Looks fine")
        try:
            return accounts.resolve_family_approval(req_id, decision)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # -------------------------------------------------------------------------
    # Platform Capabilities & Limitations
    # -------------------------------------------------------------------------
    @api.get("/api/platform/capabilities")
    def get_platform_capabilities() -> dict[str, Any]:
        return {
            "windows": {
                "antivirus_integration": "Windows Defender CLI (MpCmdRun.exe) where available",
                "filesystem_boundary": "Isolated ephemeral staging directories, explicit scrubbing",
                "network_boundary": "Anti-SSRF RFC1918 & cloud metadata filtering",
                "limitations": "Application-level sandbox; does not claim kernel driver interception",
            },
            "android": {
                "process_model": "Linux UID per-app sandbox isolation",
                "key_management": "AndroidKeyStore hardware security module compatibility",
                "network_interception": "Requires user-consented VpnService or AccessibilityService",
                "limitations": "Cannot inspect arbitrary app storage or bypass system sandboxes",
            },
        }

    return api


app = create_app()
