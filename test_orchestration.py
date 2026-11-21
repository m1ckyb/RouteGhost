"""Unit and integration tests for core service orchestration, UniFi sync, VPS routing, MQTT, and 2FA/settings security."""
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


@pytest.fixture
def db(app):
    import database as _db
    return _db


def _create_user(db_mod, username, password="StrongPass1!"):
    from werkzeug.security import generate_password_hash
    uid = db_mod.add_user(username)
    db_mod.update_user_password(uid, generate_password_hash(password))
    return uid


class TestBogusApiKeyCannotBypass2FA:
    def test_bogus_api_key_still_blocked_by_2fa_enforcement(self, app, db):
        uid = _create_user(db, "orch_2fa_user")
        old_enforce = db.get_setting("ENFORCE_2FA")
        db.set_setting("ENFORCE_2FA", "1")
        try:
            client = app.test_client()
            client.post(
                "/auth/login/password",
                json={"username": "orch_2fa_user", "password": "StrongPass1!"},
                headers={"X-API-Key": "csrf-bypass"},
            )
            # Bogus X-API-Key must NOT bypass ENFORCE_2FA on @login_required /api/* routes
            resp = client.get("/api/settings/backup", headers={"X-API-Key": "not-a-real-key"})
            assert resp.status_code == 403
            assert "Two-Factor" in resp.get_json()["error"]
        finally:
            db.set_setting("ENFORCE_2FA", old_enforce or "0")
            db.delete_user(uid)


class TestUnifiAndOrchestration:
    def test_toggle_unifi_skips_put_when_port_matches_as_string(self, db):
        import main
        db.set_setting("FIREWALL_TYPE", "unifi")
        db.set_setting("UNIFI_RULE_NAME", "RouteGhost")

        mock_session = MagicMock()
        get_resp = MagicMock(status_code=200)
        get_resp.json.return_value = {
            "data": [{"_id": "rule1", "name": "RouteGhost", "enabled": True, "dst_port": "23456"}]
        }

        with patch("main.unifi_request", return_value=get_resp) as mock_req:
            ok = main.toggle_unifi(True, forward_port=23456, session=mock_session, base_url="https://192.168.1.1")
            assert ok is True
            # Only GET should have been called — NO redundant PUT because "23456" == str(23456)
            assert mock_req.call_count == 1
            assert mock_req.call_args[0][1] == "GET"

    def test_turn_on_rolls_back_unifi_if_cloudflare_dns_fails(self, db):
        import main
        db.set_setting("DOMAIN_ROOT", "example.com")
        db.set_setting("FIREWALL_TYPE", "unifi")
        db.set_setting("UNIFI_HOST", "192.168.1.1")
        db.set_setting("UNIFI_USER", "admin")
        db.set_setting("UNIFI_PASS", "pass")
        db.set_setting("UNIFI_RULE_NAME", "RouteGhost")

        sid = db.add_service(
            name="RollbackSvc",
            router_name="rb-router",
            service_name="rb-svc",
            target_url="http://192.168.10.50:8080",
            subdomain_prefix="rb",
            routing_mode="unifi",
        )
        try:
            mock_redis = MagicMock()
            login_resp = MagicMock(status_code=200, headers={"x-csrf-token": "tok"})
            with patch("main.get_redis", return_value=mock_redis), \
                 patch("main.login_unifi_with_retry", return_value=login_resp), \
                 patch("main.toggle_unifi", return_value=True) as mock_toggle, \
                 patch("main.get_public_ip", return_value="1.2.3.4"), \
                 patch("main.cf_request", return_value=None), \
                 patch("main.logout_unifi"):
                res = main.turn_on_service(sid)
                assert "error" in res
                assert "DNS" in res["error"]
                # First call opened port (True), second call rolled it back (False)
                assert mock_toggle.call_count == 2
                assert mock_toggle.call_args_list[0][0][0] is True
                assert mock_toggle.call_args_list[1][0][0] is False
        finally:
            db.delete_service(sid)

    def test_turn_off_vps_keeps_wireguard_when_another_vps_service_active(self, db):
        import main
        s1 = db.add_service("VPS1", "vps-r1", "vps-s1", "http://192.168.10.51:8080", "v1", routing_mode="vps")
        s2 = db.add_service("VPS2", "vps-r2", "vps-s2", "http://192.168.10.52:8080", "v2", routing_mode="vps")
        db.update_service_status(s1, True, "v1-aaaa1111.example.com", 40001)
        db.update_service_status(s2, True, "v2-bbbb2222.example.com", 40001)
        try:
            mock_redis = MagicMock()
            with patch("main.get_redis", return_value=mock_redis), \
                 patch("main.cf_request", return_value={"result": []}), \
                 patch("routing.VPSManager.cleanup_port_forward") as mock_cleanup, \
                 patch("routing.WireGuardManager.down") as mock_wg_down:
                res = main.turn_off_service(s1)
                assert "message" in res
                # s2 is still active in VPS mode, so port 443 and WireGuard MUST NOT be torn down
                mock_cleanup.assert_not_called()
                mock_wg_down.assert_not_called()
        finally:
            db.delete_service(s1)
            db.delete_service(s2)

    def test_mqtt_handler_dispatches_service_and_global_commands(self):
        from mqtt_handler import MQTTHandler
        callback = MagicMock()
        handler = MQTTHandler(command_callback=callback)

        msg1 = MagicMock(topic="routeghost/service/7/set", payload=b"on")
        handler.on_message(None, None, msg1)
        callback.assert_called_with(7, "ON")

        msg2 = MagicMock(topic="routeghost/global/set", payload=b"ROTATE_PORT")
        handler.on_message(None, None, msg2)
        callback.assert_called_with("global", "ROTATE_PORT")

    def test_api_save_setting_clears_vps_host_key_on_host_change(self, app, db):
        uid = _create_user(db, "orch_settings_user")
        db.set_setting("VPS_HOST", "1.1.1.1")
        db.set_setting("VPS_SSH_HOST_KEY", "old-fingerprint")
        try:
            client = app.test_client()
            client.post(
                "/auth/login/password",
                json={"username": "orch_settings_user", "password": "StrongPass1!"},
                headers={"X-API-Key": "csrf-bypass"},
            )
            resp = client.post(
                "/api/settings",
                json={"key": "VPS_HOST", "value": "2.2.2.2"},
                headers={"X-API-Key": "csrf-bypass"},
            )
            assert resp.status_code == 200
            assert db.get_setting("VPS_SSH_HOST_KEY") is None
        finally:
            db.delete_user(uid)
