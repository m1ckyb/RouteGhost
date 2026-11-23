"""Tests for the /redir/<slug> short-link and protected RouteGhost service redirect feature."""
import hashlib
import os
import sys
import tempfile
import shutil

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

TEST_API_KEY = "redir-test-api-key"
TEST_API_KEY_HASH = hashlib.sha256(TEST_API_KEY.encode()).hexdigest()


@pytest.fixture(scope="session", autouse=True)
def _setup_test_env():
    os.environ.setdefault("DATA_DIR", tempfile.mkdtemp())
    os.environ.setdefault("CF_API_TOKEN", "test")
    os.environ.setdefault("CF_ZONE_ID", "test")
    os.environ.setdefault("DOMAIN_ROOT", "test.example.com")
    yield
    data_dir = os.environ.get("DATA_DIR")
    if data_dir and os.path.isdir(data_dir):
        shutil.rmtree(data_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def app():
    from main import app as flask_app
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    flask_app.config["SESSION_COOKIE_SECURE"] = False
    yield flask_app


@pytest.fixture(autouse=True)
def _clear_rate_limits():
    from main import LOGIN_ATTEMPTS
    LOGIN_ATTEMPTS.clear()
    yield
    LOGIN_ATTEMPTS.clear()


@pytest.fixture
def db(app):
    import database as _db
    return _db


@pytest.fixture
def auth_headers(db):
    from werkzeug.security import generate_password_hash
    uid = db.add_user("redir_admin")
    db.update_user_password(uid, generate_password_hash("StrongPass1!"))
    db.add_api_key(uid, TEST_API_KEY_HASH, "redir-key")
    yield {"X-API-Key": TEST_API_KEY}
    db.delete_user(uid)


class TestStaticUrlRedirects:
    def test_create_and_follow_random_slug_redirect(self, app, db, auth_headers):
        client = app.test_client()
        resp = client.post(
            "/api/redirects",
            json={"target_type": "url", "target_url": "https://microsoft.com"},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        redir = resp.get_json()["redirect"]
        slug = redir["slug"]
        assert len(slug) >= 6
        assert redir["has_passcode"] is False
        assert "passcode_hash" not in redir

        try:
            # Public visit without auth immediately 302 redirects
            r = client.get(f"/redir/{slug}", follow_redirects=False)
            assert r.status_code == 302
            assert r.headers["Location"] == "https://microsoft.com"
            assert "no-store" in r.headers.get("Cache-Control", "")

            # Hit count incremented
            stored = db.get_redirect(redir["id"])
            assert stored["hit_count"] == 1
        finally:
            db.delete_redirect(redir["id"])

    def test_rejects_javascript_scheme_and_bad_slug(self, app, auth_headers):
        client = app.test_client()
        r1 = client.post(
            "/api/redirects",
            json={"slug": "xss", "target_type": "url", "target_url": "javascript:alert(1)"},
            headers=auth_headers,
        )
        assert r1.status_code == 400

        r2 = client.post(
            "/api/redirects",
            json={"slug": "../etc/passwd", "target_type": "url", "target_url": "https://example.com"},
            headers=auth_headers,
        )
        assert r2.status_code == 400


def _extract_csrf(html):
    import re
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    assert m, "CSRF token missing from redir_gate.html"
    return m.group(1)


class TestProtectedServiceRedirects:
    def test_service_redirect_requires_pin_and_follows_dynamic_hostname(self, app, db, auth_headers):
        sid = db.add_service(
            name="FuelApp",
            router_name="fuelapp-r",
            service_name="fuelapp-s",
            target_url="http://192.168.10.50:5000",
            subdomain_prefix="fa",
        )
        db.update_service_status(sid, True, "fa-2cnm0oxi.micky.id.au", 44123)
        client = app.test_client()
        resp = client.post(
            "/api/redirects",
            json={
                "slug": "FuelApp",
                "target_type": "service",
                "service_id": sid,
                "passcode": "4829",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201
        redir = resp.get_json()["redirect"]
        assert redir["has_passcode"] is True

        try:
            # Case-insensitive GET shows PIN gate and does NOT leak target hostname
            gate = client.get("/redir/fuelapp", follow_redirects=False)
            assert gate.status_code == 200
            body = gate.get_data(as_text=True)
            assert "Protected Link" in body
            assert "fa-2cnm0oxi.micky.id.au" not in body
            csrf_token = _extract_csrf(body)

            # Wrong PIN -> 401
            bad = client.post("/redir/FuelApp", data={"csrf_token": csrf_token, "passcode": "0000"}, follow_redirects=False)
            assert bad.status_code == 401

            # Correct PIN -> 302 to live rotating URL
            ok = client.post("/redir/FuelApp", data={"csrf_token": csrf_token, "passcode": "4829"}, follow_redirects=False)
            assert ok.status_code == 302
            assert ok.headers["Location"] == "https://fa-2cnm0oxi.micky.id.au"

            # After rotation, same /redir/FuelApp points to the NEW rotating URL!
            db.update_service_status(sid, True, "fa-new99999.micky.id.au", 44123)
            ok2 = client.post("/redir/FuelApp", data={"csrf_token": csrf_token, "passcode": "4829"}, follow_redirects=False)
            assert ok2.status_code == 302
            assert ok2.headers["Location"] == "https://fa-new99999.micky.id.au"

            # When service is offline -> 503 after valid PIN
            db.update_service_status(sid, False, None, None)
            offline = client.post("/redir/FuelApp", data={"csrf_token": csrf_token, "passcode": "4829"}, follow_redirects=False)
            assert offline.status_code == 503
            assert "offline" in offline.get_data(as_text=True).lower()
        finally:
            db.delete_service(sid)  # Also tests ON DELETE CASCADE

    def test_pin_gate_rate_limiting(self, app, db, auth_headers):
        client = app.test_client()
        resp = client.post(
            "/api/redirects",
            json={"slug": "pinlimit", "target_type": "url", "target_url": "https://example.com", "passcode": "9999"},
            headers=auth_headers,
        )
        redir_id = resp.get_json()["redirect"]["id"]
        try:
            gate = client.get("/redir/pinlimit")
            csrf_token = _extract_csrf(gate.get_data(as_text=True))
            for _ in range(5):
                r = client.post("/redir/pinlimit", data={"csrf_token": csrf_token, "passcode": "1111"})
                assert r.status_code == 401
            # 6th attempt -> 429 Too Many Requests
            r6 = client.post("/redir/pinlimit", data={"csrf_token": csrf_token, "passcode": "9999"})
            assert r6.status_code == 429
        finally:
            db.delete_redirect(redir_id)

    def test_disable_and_expire_redirect(self, app, db, auth_headers):
        client = app.test_client()
        resp = client.post(
            "/api/redirects",
            json={"slug": "temp-link", "target_type": "url", "target_url": "https://example.com"},
            headers=auth_headers,
        )
        redir_id = resp.get_json()["redirect"]["id"]
        try:
            # Toggle off -> 404
            t = client.post(f"/api/redirects/{redir_id}/toggle", json={"enabled": False}, headers=auth_headers)
            assert t.status_code == 200
            assert client.get("/redir/temp-link").status_code == 404

            # Re-enable with past expiry -> 410 Gone
            u = client.put(
                f"/api/redirects/{redir_id}",
                json={
                    "slug": "temp-link",
                    "target_type": "url",
                    "target_url": "https://example.com",
                    "enabled": True,
                    "expires_at": "2020-01-01T00:00",
                },
                headers=auth_headers,
            )
            assert u.status_code == 200
            assert client.get("/redir/temp-link").status_code == 410
        finally:
            db.delete_redirect(redir_id)
