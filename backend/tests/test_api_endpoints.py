from fastapi.testclient import TestClient
from app.main import app
from app.services.auth_service import create_access_token
from app.database.session import SessionLocal

client = TestClient(app)


def test_root_and_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_auth_login_admin():
    response = client.post("/api/auth/login", json={
        "email": "admin@agentshield.ai",
        "password": "Admin@123456"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["email"] == "admin@agentshield.ai"
    assert data["user"]["role"] == "admin"


def get_admin_token():
    res = client.post("/api/auth/login", json={
        "email": "admin@agentshield.ai",
        "password": "Admin@123456"
    })
    return res.json()["access_token"]


def test_list_agents_authenticated():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/api/agents", headers=headers)
    assert response.status_code == 200
    agents = response.json()
    assert len(agents) == 4
    agent_keys = [a["key"] for a in agents]
    assert "research_agent" in agent_keys
    assert "file_agent" in agent_keys
    assert "data_analysis_agent" in agent_keys
    assert "mail_agent" in agent_keys


def test_dashboard_metrics_real_data():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/api/dashboard/metrics", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert data["metrics"]["total_agents"] == 4
    assert data["metrics"]["active_agents"] == 4
    assert isinstance(data["events_over_time"], list)
    assert isinstance(data["recent_activity"], list)


def test_protection_policies_and_update():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}"}

    # 1. List policies
    response = client.get("/api/protection/policies", headers=headers)
    assert response.status_code == 200
    policies = response.json()
    assert len(policies) >= 5
    
    # 2. Update a policy
    target_policy = policies[0]
    update_res = client.patch(
        f"/api/protection/policies/{target_policy['id']}",
        json={"is_enabled": True, "changes_summary": "Policy verified in automated test"},
        headers=headers
    )
    assert update_res.status_code == 200
    updated = update_res.json()
    assert updated["version"] == target_policy["version"] + 1

    # 3. Check version history
    ver_res = client.get(f"/api/protection/policies/{target_policy['id']}/versions", headers=headers)
    assert ver_res.status_code == 200
    versions = ver_res.json()
    assert len(versions) >= 2
