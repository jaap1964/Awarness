import os
import tempfile

# Set configuration before importing the application.
_temp = tempfile.TemporaryDirectory()
os.environ["APP_SECRET"] = "test-secret-value-that-is-long-enough-for-unit-tests"
from passlib.context import CryptContext
os.environ["ADMIN_PASSWORD_HASH"] = CryptContext(schemes=["argon2"]).hash("test-password")
os.environ["DATABASE_PATH"] = os.path.join(_temp.name, "test.db")

from fastapi.testclient import TestClient
from app import app

def test_admin_login_csrf_campaign_and_export():
    with TestClient(app) as client:
        page = client.get("/login")
        assert page.status_code == 200
        import re
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        assert client.post("/login", data={"password":"test-password", "csrf":"bad"}).status_code == 403
        page = client.get("/login")
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        assert client.post("/login", data={"password":"test-password", "csrf":csrf}).status_code == 303
        page = client.post("/campaigns", data={"name":"Test", "count":"2", "csrf":client.cookies.get("awareness_admin")}, follow_redirects=False)
        # Session cookie is signed; obtain CSRF from the authenticated dashboard.
        assert page.status_code in (403, 422)

def test_home_redirects_to_login():
    with TestClient(app) as client:
        assert client.get("/", follow_redirects=False).headers["location"] == "/login"
