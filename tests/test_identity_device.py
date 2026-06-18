from fastapi.testclient import TestClient

from app.main import app


def test_device_enrollment_and_policy_bundle():
    client = TestClient(app)
    enroll = client.post(
        "/v1/control/device/enroll",
        headers={"x-secureai-enrollment-token": "dev-enroll-token-change-me"},
        json={"user": "steve@example.com", "device_name": "Test Mac", "platform": "macOS"},
    )
    assert enroll.status_code == 200
    data = enroll.json()

    headers = {
        "x-secureai-user": "steve@example.com",
        "x-secureai-device": data["device_id"],
        "x-secureai-device-token": data["device_token"],
        "x-secureai-groups": "security,engineering",
    }
    identity = client.get("/v1/control/identity/me", headers=headers)
    assert identity.status_code == 200
    assert identity.json()["device_trusted"] is True

    bundle = client.get("/v1/control/policy/bundle", headers=headers)
    assert bundle.status_code == 200
    payload = bundle.json()["payload"]
    assert payload["user"] == "steve@example.com"
    assert payload["device_trusted"] is True
    assert "security" in payload["groups"]
