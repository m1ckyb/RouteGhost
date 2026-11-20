"""Regression tests for security, reliability, and concurrency audit fixes."""
import hashlib
import os
import sys
import tempfile
import shutil
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


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


def _create_user(db_mod, username, password="StrongPass1!"):
    from werkzeug.security import generate_password_hash
    uid = db_mod.add_user(username)
    db_mod.update_user_password(uid, generate_password_hash(password))
    return uid


class TestRegistrationLockdown:
    def test_register_blocked_when_user_exists(self, app, db):
        """Registration MUST be rejected with 403 once any user exists."""
        uid = _create_user(db, "audit_existing_admin")
        try:
            client = app.test_client()
            resp = client.post(
                "/auth/register/begin",
                json={"username": "attacker"},
                headers={"X-API-Key": "bypass-csrf"},
            )
            assert resp.status_code == 403
            assert "closed" in resp.get_json()["error"].lower()

            resp2 = client.post(
                "/auth/register/complete",
                json={"credential": {"id": "fake"}},
                headers={"X-API-Key": "bypass-csrf"},
            )
            assert resp2.status_code == 403
        finally:
            db.delete_user(uid)


class TestPasswordSecurity:
    def test_change_password_requires_current_password(self, app, db):
        uid = _create_user(db, "audit_pw_user", "StrongPass1!")
        try:
            client = app.test_client()
            client.post(
                "/auth/login/password",
                json={"username": "audit_pw_user", "password": "StrongPass1!"},
                headers={"X-API-Key": "bypass-csrf"},
            )
            # Missing current password -> 400
            resp = client.post(
                "/auth/password/change",
                json={"new_password": "NewValid2!"},
                headers={"X-API-Key": "bypass-csrf"},
            )
            assert resp.status_code == 400

            # Wrong current password -> 403
            resp2 = client.post(
                "/auth/password/change",
                json={"current_password": "WrongPass1!", "new_password": "NewValid2!"},
                headers={"X-API-Key": "bypass-csrf"},
            )
            assert resp2.status_code == 403
        finally:
            db.delete_user(uid)

    def test_reset_password_blocks_api_key_and_other_users(self, app, db):
        uid1 = _create_user(db, "audit_owner", "StrongPass1!")
        uid2 = _create_user(db, "audit_victim", "StrongPass1!")
        api_key = "secret-api-key-audit"
        db.add_api_key(uid1, hashlib.sha256(api_key.encode()).hexdigest(), "audit-key")
        try:
            # API key alone cannot reset passwords (requires session login)
            client_api = app.test_client()
            resp_api = client_api.post(
                "/api/users/audit_victim/reset-password",
                headers={"X-API-Key": api_key},
            )
            assert resp_api.status_code == 302  # redirected to login

            # Logged-in user cannot reset another user's password
            client = app.test_client()
            client.post(
                "/auth/login/password",
                json={"username": "audit_owner", "password": "StrongPass1!"},
                headers={"X-API-Key": "bypass-csrf"},
            )
            resp_idor = client.post(
                "/api/users/audit_victim/reset-password",
                headers={"X-API-Key": "bypass-csrf"},
            )
            assert resp_idor.status_code == 403
        finally:
            db.delete_user(uid1)
            db.delete_user(uid2)


class TestSecretEncryptionAndMasking:
    def test_sensitive_setting_encrypted_at_rest(self, db):
        db.set_setting("CF_API_TOKEN", "super-secret-cf-token")
        # Raw DB row must be encrypted with enc:v1:
        with db.get_db() as conn:
            raw = conn.execute("SELECT value FROM settings WHERE key = 'CF_API_TOKEN'").fetchone()["value"]
        assert raw.startswith("enc:v1:")
        assert "super-secret-cf-token" not in raw
        # get_setting transparently decrypts
        assert db.get_setting("CF_API_TOKEN") == "super-secret-cf-token"

    def test_backup_omits_sensitive_secrets(self, app, db):
        uid = _create_user(db, "audit_backup_user")
        db.set_setting("CF_API_TOKEN", "super-secret-cf-token")
        db.set_setting("DOMAIN_ROOT", "safe.example.com")
        try:
            client = app.test_client()
            client.post(
                "/auth/login/password",
                json={"username": "audit_backup_user", "password": "StrongPass1!"},
                headers={"X-API-Key": "bypass-csrf"},
            )
            resp = client.get("/api/settings/backup")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data.get("DOMAIN_ROOT") == "safe.example.com"
            assert "CF_API_TOKEN" not in data
        finally:
            db.delete_user(uid)

    def test_settings_page_does_not_echo_plaintext_secrets(self, app, db):
        uid = _create_user(db, "audit_settings_dom")
        db.set_setting("CF_API_TOKEN", "do-not-leak-in-html-999")
        try:
            client = app.test_client()
            client.post(
                "/auth/login/password",
                json={"username": "audit_settings_dom", "password": "StrongPass1!"},
                headers={"X-API-Key": "bypass-csrf"},
            )
            resp = client.get("/settings")
            assert resp.status_code == 200
            html = resp.get_data(as_text=True)
            assert "do-not-leak-in-html-999" not in html
        finally:
            db.delete_user(uid)


class TestSSRFAndValidation:
    def test_discord_webhook_validation(self):
        from main import _is_valid_discord_webhook
        assert _is_valid_discord_webhook("https://discord.com/api/webhooks/12345/abcdef")
        assert _is_valid_discord_webhook("https://discordapp.com/api/webhooks/12345/abcdef")
        assert not _is_valid_discord_webhook("http://127.0.0.1:5001/api/status")
        assert not _is_valid_discord_webhook("https://evil.com/api/webhooks/123/abc")
        assert not _is_valid_discord_webhook("http://discord.com/api/webhooks/123/abc")

    def test_validate_target_url_checks_all_resolved_ips(self):
        from main import validate_target_url
        fake_addrinfo = [
            (2, 1, 6, "", ("192.168.10.50", 0)),
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=fake_addrinfo):
            with pytest.raises(ValueError, match="Loopback"):
                validate_target_url("http://dual.internal:8080")


class TestReliabilityFixes:
    def test_count_active_routers_when_redis_none(self):
        from main import count_active_routers
        with patch("main.get_redis", return_value=None):
            assert count_active_routers() == 0

    def test_clear_redis_routes_when_empty_returns_200(self, app, db):
        uid = _create_user(db, "audit_redis_user")
        try:
            client = app.test_client()
            client.post(
                "/auth/login/password",
                json={"username": "audit_redis_user", "password": "StrongPass1!"},
                headers={"X-API-Key": "bypass-csrf"},
            )
            mock_r = MagicMock()
            mock_r.scan_iter.return_value = iter([])
            with patch("main.get_redis", return_value=mock_r):
                resp = client.post(
                    "/api/test/redis/clear",
                    headers={"X-API-Key": "bypass-csrf"},
                )
            assert resp.status_code == 200
            assert "No Traefik entries" in resp.get_json()["message"]
        finally:
            db.delete_user(uid)

    def test_2fa_enforcement_blocks_session_api_calls(self, app, db):
        uid = _create_user(db, "audit_2fa_enforced")
        old_enforce = db.get_setting("ENFORCE_2FA")
        db.set_setting("ENFORCE_2FA", "1")
        try:
            client = app.test_client()
            client.post(
                "/auth/login/password",
                json={"username": "audit_2fa_enforced", "password": "StrongPass1!"},
                headers={"X-API-Key": "bypass-csrf"},
            )
            # Browser session call to /api/* WITHOUT X-API-Key must be blocked (403)
            resp = client.get("/api/system")
            assert resp.status_code == 403
            assert "Two-Factor" in resp.get_json()["error"]
        finally:
            db.set_setting("ENFORCE_2FA", old_enforce or "0")
            db.delete_user(uid)
