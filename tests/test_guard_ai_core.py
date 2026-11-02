from __future__ import annotations

import base64
import os
import pytest

from app.agents.base import AgentBus, SecurityEvent
from app.agents.controller import ControllerAI
from app.blockchain.service import AuditLedgerService
from app.crypto.engine import CryptoEngine
from app.crypto.maze import CryptographicMaze
from app.security.isolation_chamber import IsolationChamberManager
from app.security.private_space import PrivateSpaceManager
from app.security.sandbox import SandboxInspectionEngine


# -----------------------------------------------------------------------------
# 1. Cryptographic Engine Tests
# -----------------------------------------------------------------------------
def test_aes_gcm_encryption_and_tampering() -> None:
    engine = CryptoEngine()
    plaintext = "TopSecretSecurityPayload2026"
    encrypted = engine.encrypt_aes_gcm(plaintext)
    
    assert encrypted["algorithm"] == "AES-256-GCM"
    assert encrypted["nonce_b64"]
    assert encrypted["ciphertext_b64"]
    assert encrypted["authenticated"] == "true"

    # Decrypt normally
    decrypted = engine.decrypt_aes_gcm(
        ciphertext_b64=encrypted["ciphertext_b64"],
        nonce_b64=encrypted["nonce_b64"],
    )
    assert decrypted.decode("utf-8") == plaintext

    # Tampering test: alter one byte of ciphertext
    raw_ct = base64.b64decode(encrypted["ciphertext_b64"])
    tampered_ct = bytes([raw_ct[0] ^ 0xFF]) + raw_ct[1:]
    tampered_b64 = base64.b64encode(tampered_ct).decode("ascii")

    with pytest.raises(ValueError, match="Cryptographic verification failed"):
        engine.decrypt_aes_gcm(
            ciphertext_b64=tampered_b64,
            nonce_b64=encrypted["nonce_b64"],
        )


def test_ed25519_signatures() -> None:
    engine = CryptoEngine()
    message = "AuditRecord:Evt-10029:Sha256Digest"
    sig_info = engine.sign_event(message)

    assert sig_info["algorithm"] == "Ed25519"
    assert sig_info["signature_hex"]
    assert sig_info["public_key_hex"] == engine.system_public_key_hex

    # Verification passes
    assert engine.verify_event_signature(message, sig_info["signature_hex"]) is True

    # Tampered message fails
    assert engine.verify_event_signature("AlteredMessage", sig_info["signature_hex"]) is False


def test_key_separation_and_rotation() -> None:
    engine = CryptoEngine()
    master = os.urandom(32)
    keys = engine.derive_separated_keys(master)

    assert len(keys["data_encryption_key"]) == 32
    assert len(keys["mac_integrity_key"]) == 32
    assert len(keys["blind_index_key"]) == 32
    assert keys["data_encryption_key"] != keys["mac_integrity_key"]
    assert keys["data_encryption_key"] != keys["blind_index_key"]

    # Key rotation
    initial_version = engine._current_version
    record = engine.rotate_key("Routine 90-day key rotation")
    assert record.version == initial_version + 1
    assert record.status == "active"
    history = engine.get_rotation_history()
    assert len(history) >= 2


# -----------------------------------------------------------------------------
# 2. Cryptographic Maze Tests
# -----------------------------------------------------------------------------
def test_cryptographic_maze_sealing_and_recovery() -> None:
    engine = CryptoEngine()
    maze = CryptographicMaze(engine)
    secret_text = "Confidential Banking Credentials in Maze"

    # Seal with small compartment size to ensure multi-segment partitioning
    artifact = maze.create_maze(secret_text, compartment_size=10)
    assert artifact.layer_count == 3
    assert len(artifact.segments) >= 4
    assert artifact.integrity_seal
    assert len(artifact.recovery_shares) == 2

    # Standard Solve
    solved = maze.solve_maze(artifact)
    assert solved.decode("utf-8") == secret_text

    # Emergency Dual Recovery Share Solve
    solved_via_recovery = maze.solve_maze(artifact, override_recovery_shares=artifact.recovery_shares)
    assert solved_via_recovery.decode("utf-8") == secret_text


# -----------------------------------------------------------------------------
# 3. Blockchain & Audit Ledger Tests
# -----------------------------------------------------------------------------
def test_blockchain_hash_chain_and_tamper_detection() -> None:
    ledger = AuditLedgerService(db_path=":memory:")

    r1 = ledger.register_security_event("LOGIN_ATTEMPT", {"user": "admin", "result": "success"})
    r2 = ledger.register_security_event("URL_BLOCKED", {"url": "https://malicious.example", "risk": "Danger"})
    r3 = ledger.register_security_event("FILE_QUARANTINED", {"hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"})

    assert r1.index == 0
    assert r1.prev_hash == AuditLedgerService.GENESIS_HASH
    assert r2.index == 1
    assert r2.prev_hash == r1.record_hash
    assert r3.index == 2
    assert r3.prev_hash == r2.record_hash

    # Chain verification
    verif = ledger.verify_entire_chain()
    assert verif["intact"] is True
    assert verif["total_records"] == 3

    # Tampering demonstration
    tampered = ledger.simulate_tampering_for_demo(r1.record_id)
    assert tampered is True

    verif_after = ledger.verify_entire_chain()
    assert verif_after["intact"] is False
    assert "Content tampering detected" in verif_after["reason"]


# -----------------------------------------------------------------------------
# 4. Guard Private Space Tests
# -----------------------------------------------------------------------------
def test_private_space_lifecycle() -> None:
    ps = PrivateSpaceManager(base_cache_dir="./test_pytest_ps_cache")
    try:
        tab = ps.open_tab("about:blank")
        assert tab.status == "active"
        assert tab.tab_id.startswith("ptab-")

        status = ps.get_status()
        assert status["active_tab_count"] == 1
        assert "NOTICE" in status["disclaimer"]

        # Close tab scrubs session
        close_res = ps.close_tab(tab.tab_id)
        assert close_res["success"] is True
        assert close_res["status"] == "scrubbed_and_closed"

        assert ps.get_status()["active_tab_count"] == 0
    finally:
        ps.clear_all_sessions()


# -----------------------------------------------------------------------------
# 5. Guard Isolation Chamber Tests
# -----------------------------------------------------------------------------
def test_isolation_chamber_network_boundaries_and_incinerate() -> None:
    iso = IsolationChamberManager(chamber_root="./test_pytest_iso_runs")
    try:
        # Loopback URL is blocked by Anti-SSRF boundary
        session = iso.launch_session("http://127.0.0.1:8080/admin")
        assert session.status == "failure"
        assert session.isolation_health == "Failure"
        assert any("Anti-SSRF" in log for log in session.failure_log)

        # Terminate and incinerate
        res = iso.terminate_and_incinerate(session.session_id)
        assert res["cleanup_verified"] is True
    finally:
        import shutil
        shutil.rmtree("./test_pytest_iso_runs", ignore_errors=True)


# -----------------------------------------------------------------------------
# 6. Guard Sandbox Lab Tests
# -----------------------------------------------------------------------------
def test_sandbox_file_inspection() -> None:
    sbx = SandboxInspectionEngine(sandbox_staging_dir="./test_pytest_sbx_staging")
    try:
        # File masquerading as pdf but having double extension and embedded executable payload marker
        payload = b"MZ\x90\x00\x03\x00\x00\x00powershell.exe -enc dGVzdA== CreateRemoteThread"
        report = sbx.inspect_file(payload, "tax_invoice.pdf.exe")

        assert report.double_extension_detected is True
        assert report.risk_level == "Malicious"
        assert report.risk_score >= 50
        assert report.sha256
        assert report.sha1
        assert report.md5
        assert "Verified Cleaned" in report.cleanup_status
        assert any(ind["rule"] == "double_extension_spoofing" for ind in report.indicators)
        assert any(ind["rule"] == "suspicious_code_pattern" for ind in report.indicators)
    finally:
        import shutil
        shutil.rmtree("./test_pytest_sbx_staging", ignore_errors=True)


# -----------------------------------------------------------------------------
# 7. Controller AI Orchestration & Informer Voice Tests
# -----------------------------------------------------------------------------
def test_controller_ai_ecosystem_and_voice() -> None:
    controller = ControllerAI(audit_ledger=AuditLedgerService(db_path=":memory:"))

    # Orchestrate dangerous Indian lookalike link
    decision = controller.orchestrate_inspection(url="https://sbi-login.example/verify-otp")
    assert decision["recommended_environment"] == "Isolation Chamber"
    assert decision["risk_level"] == "Danger"
    assert decision["action_taken"] == "BLOCKED"
    assert "english" in decision["announcement"]["voice"]
    assert "telugu" in decision["announcement"]["voice"]
    assert decision["announcement"]["voice"]["english"]["lang"] == "en-IN"
    assert decision["announcement"]["voice"]["telugu"]["lang"] == "te-IN"

    # Orchestrate safe URL
    safe_dec = controller.orchestrate_inspection(url="https://www.example.com")
    assert safe_dec["risk_level"] == "Safe"
    assert safe_dec["action_taken"] == "ALLOWED"
    assert safe_dec["recommended_environment"] == "Private Space"

    # Ecosystem telemetry
    eco = controller.get_ecosystem_status()
    assert eco["telemetry"]["decisions_count"] == 2
    assert "finder" in eco["agents"]
    assert "defence" in eco["agents"]
    assert "offence" in eco["agents"]
    assert "informer" in eco["agents"]
    assert "wifi" in eco["agents"]
