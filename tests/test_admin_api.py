from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_admin_overview_and_policy_validate():
    overview = client.get('/v1/admin/overview')
    assert overview.status_code == 200
    assert 'policy_version' in overview.json()

    policy = client.get('/v1/admin/policy')
    assert policy.status_code == 200
    policy_yaml = policy.json()['policy_yaml']

    validate = client.post('/v1/admin/policy/validate', json={'policy_yaml': policy_yaml})
    assert validate.status_code == 200
    assert validate.json()['valid'] is True


def test_admin_simulate_blocks_secret():
    fake_key = 'AK' + 'IAABCDEFGHIJKLMNOP'
    response = client.post('/v1/admin/simulate', json={'model': 'auto-secure', 'messages': [{'role': 'user', 'content': fake_key}]})
    assert response.status_code == 200
    assert response.json()['decision'] == 'block'
