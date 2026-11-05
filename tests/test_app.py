import os
import re
import tempfile

_temp = tempfile.TemporaryDirectory()
os.environ["APP_SECRET"] = "test-secret-value-that-is-long-enough-for-unit-tests"
from passlib.context import CryptContext
os.environ["ADMIN_PASSWORD_HASH"] = CryptContext(schemes=["argon2"]).hash("test-password")
os.environ["DATABASE_PATH"] = os.path.join(_temp.name, "test.db")

from fastapi.testclient import TestClient
from app import app

def csrf_from(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

def test_admin_campaign_tracking_and_export():
    with TestClient(app) as client:
        page = client.get("/login")
        assert page.status_code == 200
        assert client.post("/login", data={"password": "test-password", "csrf": "bad"}).status_code == 403
        page = client.get("/login")
        response = client.post("/login", data={"password": "test-password", "csrf": csrf_from(page.text)})
        assert response.status_code == 303
        dashboard = client.get("/admin")
        assert dashboard.status_code == 200
        response = client.post("/campaigns", data={"name": "Test", "count": "2", "csrf": csrf_from(dashboard.text)})
        assert response.status_code == 200
        assert "P0001" in response.text and "P0002" in response.text
        token = re.search(r"http://127\.0\.0\.1:8000/r/([A-Za-z0-9_-]+)", response.text).group(1)
        landing = client.get(f"/r/{token}")
        assert landing.status_code == 200
        assert "wachtwoorden" in landing.text
        assert client.post(f"/r/{token}/confirm").status_code == 200
        report = client.get("/campaigns/1/export.csv")
        assert report.status_code == 200
        assert "confirmed_human_click" in report.text
        assert "P0001,0,1,1" in report.text

def test_home_redirects_to_login():
    with TestClient(app) as client:
        assert client.get("/", follow_redirects=False).headers["location"] == "/login"
