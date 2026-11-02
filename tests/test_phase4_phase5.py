from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def get_client() -> TestClient:
    return TestClient(
        create_app(
            Settings(
                enable_network_lookups=False,
                database_path=":memory:",
                request_limit_per_minute=200,
                free_checks_per_day=3,
                payments_demo_mode=True,
            )
        )
    )


def test_auth_registration_and_login() -> None:
    client = get_client()

    # Register
    reg_resp = client.post(
        "/api/auth/register",
        json={"email": "family.admin@example.com", "password": "SuperSecretPassword123!"},
    )
    assert reg_resp.status_code == 200
    token = reg_resp.json()["access_token"]
    assert token.startswith("tok-")

    # Login
    login_resp = client.post(
        "/api/auth/login",
        json={"email": "family.admin@example.com", "password": "SuperSecretPassword123!"},
    )
    assert login_resp.status_code == 200
    assert login_resp.json()["user"]["plan"] == "free"

    # Profile
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["user"]["email"] == "family.admin@example.com"


def test_free_limit_enforcement() -> None:
    # Limit set to 3 checks/day in fixture
    client = get_client()

    # Checks 1, 2, 3 succeed
    for i in range(3):
        res = client.post("/check", json={"url": f"https://example{i}.org"})
        assert res.status_code == 200
        assert res.json()["usage"]["checks_used_today"] == i + 1

    # 4th check exceeds free limit
    exceeded_res = client.post("/check", json={"url": "https://example-extra.org"})
    assert exceeded_res.status_code == 429
    assert "Daily check limit reached" in exceeded_res.json()["detail"]


def test_payment_demo_and_upgrade() -> None:
    client = get_client()
    reg = client.post(
        "/api/auth/register",
        json={"email": "upgrader@example.com", "password": "PasswordStrong123!"},
    ).json()
    token = reg["access_token"]

    # Create Order
    order_res = client.post(
        "/api/payments/order",
        json={"plan": "pro_monthly"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert order_res.status_code == 200
    order = order_res.json()
    assert order["amount"] == 19900
    assert order["demo"] is True

    # Confirm Demo Payment
    confirm_res = client.post(
        f"/api/payments/demo-confirm?plan=pro_monthly",
        json={"order_id": order["order_id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert confirm_res.status_code == 200
    assert confirm_res.json()["upgraded_plan"] == "pro"

    # Verify user plan is now pro
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["user"]["plan"] == "pro"


def test_family_circle_workflow() -> None:
    client = get_client()
    reg = client.post(
        "/api/auth/register",
        json={"email": "parent@example.com", "password": "PasswordStrong123!"},
    ).json()
    token = reg["access_token"]

    # Invite Member
    inv_res = client.post(
        "/api/family/invite",
        json={"email": "child@example.com", "relationship": "Daughter"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert inv_res.status_code == 200
    assert inv_res.json()["email"] == "child@example.com"

    # List Members
    list_res = client.get("/api/family/members", headers={"Authorization": f"Bearer {token}"})
    assert list_res.status_code == 200
    assert len(list_res.json()) == 1

    # Ask family approval
    ask_res = client.post(
        "/api/family/ask-approval",
        json={"url": "https://sbi-offers.example/bonus", "risk": "Danger"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ask_res.status_code == 200
    req_id = ask_res.json()["request_id"]

    # Family responds "Don't do it"
    resp_res = client.post(
        "/api/family/respond",
        json={"request_id": req_id, "decision": "Don't do it"},
    )
    assert resp_res.status_code == 200
    assert resp_res.json()["status"] == "rejected"
    assert "Don't do it" in resp_res.json()["voice_notification"]
