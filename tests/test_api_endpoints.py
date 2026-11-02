from __future__ import annotations

import io
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def get_client() -> TestClient:
    app = create_app(
        Settings(
            enable_network_lookups=False,
            database_path=":memory:",
            request_limit_per_minute=100,
        )
    )
    return TestClient(app)


def test_index_and_status() -> None:
    client = get_client()
    # Test index HTML response
    resp = client.get("/")
    assert resp.status_code == 200
    assert "GUARD AI" in resp.text

    # Test status endpoint
    status_resp = client.get("/api/status")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert "controller" in data
    assert "agents" in data
    assert "engines" in data
    assert data["agents"]["finder"]["status"] == "MONITORING"
    assert data["agents"]["defence"]["status"] == "MONITORING"


def test_triage_endpoint() -> None:
    client = get_client()
    resp = client.post("/api/triage", json={"url": "https://sbi-verify.example/kyc"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision_type"] == "URL_OR_TEXT_TRIAGE"
    assert body["risk_level"] == "Danger"
    assert body["action_taken"] == "BLOCKED"
    assert body["recommended_environment"] == "Isolation Chamber"
    assert "voice" in body["announcement"]


def test_private_space_endpoints() -> None:
    client = get_client()
    open_resp = client.post("/api/private-space/tabs", json={"initial_url": "about:blank"})
    assert open_resp.status_code == 200
    tab = open_resp.json()
    assert tab["tab_id"].startswith("ptab-")

    # List tabs
    list_resp = client.get("/api/private-space/tabs")
    assert list_resp.status_code == 200
    assert list_resp.json()["active_tab_count"] == 1

    # Delete tab
    del_resp = client.delete(f"/api/private-space/tabs/{tab['tab_id']}")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True

    # Clear all
    clear_resp = client.post("/api/private-space/clear")
    assert clear_resp.status_code == 200
    assert clear_resp.json()["active_tabs"] == 0


def test_crypto_and_maze_endpoints() -> None:
    client = get_client()

    # AES-GCM Encrypt & Decrypt
    enc_resp = client.post("/api/crypto/encrypt", json={"plaintext": "SecretToken123"})
    assert enc_resp.status_code == 200
    enc_data = enc_resp.json()
    assert enc_data["ciphertext_b64"]
    assert enc_data["nonce_b64"]

    dec_resp = client.post(
        "/api/crypto/decrypt",
        json={"ciphertext_b64": enc_data["ciphertext_b64"], "nonce_b64": enc_data["nonce_b64"]},
    )
    assert dec_resp.status_code == 200
    assert dec_resp.json()["decrypted"] == "SecretToken123"

    # Maze Seal & Solve
    seal_resp = client.post("/api/crypto/maze/seal", json={"plaintext": "VaultPayload", "compartment_size": 4})
    assert seal_resp.status_code == 200
    artifact = seal_resp.json()
    assert artifact["layer_count"] == 3
    assert len(artifact["segments"]) >= 3

    solve_resp = client.post("/api/crypto/maze/solve", json={"artifact": artifact})
    assert solve_resp.status_code == 200
    assert solve_resp.json()["decrypted_text"] == "VaultPayload"

    # Rotate Key
    rot_resp = client.post("/api/crypto/rotate-key")
    assert rot_resp.status_code == 200
    assert rot_resp.json()["status"] == "active"


def test_blockchain_and_tamper_demo_endpoints() -> None:
    client = get_client()

    # Seed an event
    client.post("/api/triage", json={"url": "https://example.com"})

    # Check records
    records_resp = client.get("/api/blockchain/records")
    assert records_resp.status_code == 200
    records = records_resp.json()
    assert len(records) >= 1

    # Verify chain
    verif_resp = client.get("/api/blockchain/verify-chain")
    assert verif_resp.status_code == 200
    assert verif_resp.json()["intact"] is True

    # Tamper demo
    tamper_resp = client.post("/api/blockchain/tamper-demo")
    assert tamper_resp.status_code == 200
    assert tamper_resp.json()["success"] is True

    # Re-verify chain: must catch the tampering!
    tampered_verif = client.get("/api/blockchain/verify-chain")
    assert tampered_verif.status_code == 200
    assert tampered_verif.json()["intact"] is False


def test_sandbox_inspect_file_endpoint() -> None:
    client = get_client()
    dummy_file = io.BytesIO(b"%PDF-1.5\n/JavaScript (app.alert('xss'))\nendobj")
    resp = client.post(
        "/api/sandbox/inspect",
        files={"file": ("invoice.pdf.exe", dummy_file, "application/octet-stream")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["filename"] == "invoice.pdf.exe"
    assert body["double_extension_detected"] is True
    assert body["risk_level"] == "Malicious"
    assert body["sha256"]
    assert "Verified Cleaned" in body["cleanup_status"]


def test_platform_capabilities_endpoint() -> None:
    client = get_client()
    resp = client.get("/api/platform/capabilities")
    assert resp.status_code == 200
    data = resp.json()
    assert "windows" in data
    assert "android" in data
    assert "antivirus_integration" in data["windows"]
    assert "process_model" in data["android"]
