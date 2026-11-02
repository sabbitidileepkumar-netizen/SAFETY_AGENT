from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def client() -> TestClient:
    return TestClient(create_app(Settings(
        enable_network_lookups=False,
        enable_gemini_explanations=False,
        database_path=":memory:",
        request_limit_per_minute=100,
    )))


def test_pipeline_safe_link_is_allowed_and_audited() -> None:
    response = client().post("/api/pipeline/event", json={
        "type": "link", "value": "https://www.example.com", "source": "test"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk"] == "Safe"
    assert data["action"] == "allow"
    assert any(step["name"] == "informer" for step in data["steps"])
    assert all(step["audit_record_id"] for step in data["steps"])


def test_pipeline_careful_link_returns_restricted_viewer() -> None:
    response = client().post("/api/pipeline/event", json={
        "type": "link", "value": "http://example.com/login", "source": "test"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk"] == "Careful"
    assert data["action"] == "isolate"
    assert data["viewer_url"].startswith("/api/isolation/render/")
    assert next(step for step in data["steps"] if step["name"] == "offence")["execution"] == "waiting_for_approval"


def test_pipeline_danger_link_is_blocked() -> None:
    response = client().post("/api/pipeline/event", json={
        "type": "link", "value": "http://sbi-login.example/verify-otp", "source": "test"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk"] == "Danger"
    assert data["action"] == "block"
    assert not any(step["name"] == "isolation" for step in data["steps"])


def test_pipeline_download_runs_static_scan_without_execution(monkeypatch) -> None:
    import app.pipeline as pipeline
    from app.security.sandbox import SandboxInspectionEngine

    monkeypatch.setattr(pipeline, "fetch_download_for_static_scan", lambda _url: (b"plain harmless sample", "sample.txt"))
    monkeypatch.setattr(SandboxInspectionEngine, "_query_windows_defender", lambda _self, _path: "Not scanned (isolated test)")
    response = client().post("/api/pipeline/event", json={
        "type": "download", "value": "https://downloads.example/sample.txt", "source": "test"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["risk"] == "Safe"
    assert data["action"] == "inspect_static_bytes"
    assert any(step["name"] == "sandbox" for step in data["steps"])
    assert next(step for step in data["steps"] if step["name"] == "defence")["result"]["action"] == "download_not_executed"


def test_pipeline_download_blocks_private_hosts_before_fetch() -> None:
    import pytest
    from app.pipeline import fetch_download_for_static_scan

    with pytest.raises(ValueError, match="non-public"):
        fetch_download_for_static_scan("http://127.0.0.1/secret")


def test_tamper_demo_is_detected_on_ephemeral_ledger() -> None:
    app_client = client()
    tamper = app_client.post("/api/blockchain/tamper-demo")
    assert tamper.status_code == 200
    assert tamper.json()["success"] is True
    verification = app_client.get("/api/blockchain/verify-chain")
    assert verification.status_code == 200
    assert verification.json()["intact"] is False


def test_defender_exit_code_two_without_detection_is_inconclusive() -> None:
    from app.security.sandbox import SandboxInspectionEngine

    result = SandboxInspectionEngine._interpret_defender_result(2, "Scan completed with errors")
    assert result.startswith("Inconclusive")
    assert "Threat Detected" not in result


def test_defender_requires_explicit_threat_output_to_report_detection() -> None:
    from app.security.sandbox import SandboxInspectionEngine

    result = SandboxInspectionEngine._interpret_defender_result(2, "Threat detected: Example.Trojan")
    assert result.startswith("Threat Detected")
