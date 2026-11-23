"""Redirect Service Blueprint (/redir/<slug>, /redirects UI, and /api/redirects CRUD)."""
import os
import re
import secrets
import string
from datetime import datetime, timezone
from urllib.parse import urlparse

import redis
from flask import Blueprint, jsonify, make_response, redirect, render_template, request
from flask_login import login_required
from werkzeug.security import check_password_hash, generate_password_hash

import database as db
from logging_config import get_logger

logger = get_logger("routeghost.redirects")

redirects_bp = Blueprint("redirects", __name__)


def _generate_random_slug(length=7):
    """Generate a unique URL-safe random slug for redirects."""
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(20):
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if not db.get_redirect_by_slug(candidate):
            return candidate
    return secrets.token_hex(6)


def validate_redirect_slug(slug):
    """Validate custom slug or generate a random one if blank."""
    if not slug or not str(slug).strip():
        return _generate_random_slug()
    slug = str(slug).strip()
    if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", slug):
        raise ValueError("Slug must be 1-64 characters containing only letters, numbers, hyphens, and underscores.")
    return slug


def validate_redirect_url(url):
    """Validate external redirect destination URL (blocks javascript:, data:, CRLF, embedded creds)."""
    if not url or not str(url).strip():
        raise ValueError("Destination URL is required for external URL redirects.")
    url = str(url).strip()
    if len(url) > 2048 or "\r" in url or "\n" in url:
        raise ValueError("Invalid destination URL.")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Destination URL must start with http:// or https:// and include a hostname.")
    if "@" in parsed.netloc:
        raise ValueError("URLs with embedded credentials are not allowed.")
    return url


def validate_expires_at(value):
    """Validate an optional ISO-8601 expiration timestamp (UTC)."""
    if not value or not str(value).strip():
        return None
    raw = str(value).strip()
    try:
        datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Invalid expiration timestamp (expected ISO-8601 format, e.g. 2026-12-31T23:59).")
    return raw


def _is_redirect_expired(redir):
    """Check if a redirect has passed its UTC expiration timestamp."""
    expires_at = redir.get("expires_at")
    if not expires_at:
        return False
    try:
        exp_str = str(expires_at).strip().replace("Z", "+00:00")
        exp_dt = datetime.fromisoformat(exp_str)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= exp_dt
    except (ValueError, TypeError):
        return True  # Fail closed if an unparseable expiration timestamp somehow exists


def _resolve_redirect_destination(redir):
    """Resolve the live destination URL for a redirect. Returns (url, error_msg)."""
    if redir.get("target_type") == "service":
        service = db.get_service(redir.get("service_id"))
        if not service:
            return None, "The target service no longer exists."
        if not service.get("enabled") or not service.get("current_hostname"):
            return None, f"'{service['name']}' is currently offline."
        return f"https://{service['current_hostname']}", None
    return redir.get("target_url"), None


def _no_cache_response(resp):
    """Ensure redirect responses and PIN gates are never cached by browsers or proxies."""
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


def _serialize_redirect(r):
    """Strip passcode_hash before returning redirect objects over API."""
    out = dict(r)
    out["has_passcode"] = bool(out.pop("passcode_hash", None))
    return out


def _parse_redirect_payload(data, existing=None):
    """Shared validation/parsing for redirect create and update requests."""
    if existing:
        slug = validate_redirect_slug(data.get("slug") or existing["slug"])
        conflict = db.get_redirect_by_slug(slug)
        if conflict and conflict["id"] != existing["id"]:
            return None, (jsonify({"error": f"Slug '{slug}' is already in use."}), 409)
        target_type = data.get("target_type", existing["target_type"])
    else:
        slug = validate_redirect_slug(data.get("slug"))
        if db.get_redirect_by_slug(slug):
            return None, (jsonify({"error": f"Slug '{slug}' is already in use."}), 409)
        target_type = data.get("target_type", "url")

    if target_type not in ("url", "service"):
        return None, (jsonify({"error": "target_type must be 'url' or 'service'."}), 400)

    target_url = None
    service_id = None
    if target_type == "url":
        target_url = validate_redirect_url(data.get("target_url"))
    else:
        raw_sid = data.get("service_id")
        if not raw_sid:
            return None, (jsonify({"error": "A RouteGhost service must be selected."}), 400)
        service_id = int(raw_sid)
        if not db.get_service(service_id):
            return None, (jsonify({"error": "Selected service does not exist."}), 404)

    passcode = (data.get("passcode") or "").strip()
    clear_passcode = bool(data.get("clear_passcode", False))
    if existing:
        if clear_passcode:
            keep_passcode = False
            passcode_hash = None
        elif passcode:
            keep_passcode = False
            passcode_hash = generate_password_hash(passcode)
        else:
            keep_passcode = True
            passcode_hash = None
        enabled = existing["enabled"] if "enabled" not in data else (1 if data.get("enabled") else 0)
    else:
        keep_passcode = False
        passcode_hash = generate_password_hash(passcode) if passcode else None
        enabled = 1 if data.get("enabled", True) else 0

    expires_at = validate_expires_at(data.get("expires_at"))

    return {
        "slug": slug,
        "target_type": target_type,
        "target_url": target_url,
        "service_id": service_id,
        "passcode_hash": passcode_hash,
        "keep_passcode": keep_passcode,
        "enabled": enabled,
        "expires_at": expires_at,
    }, None


def register_redirect_routes(app, api_key_or_login_required, check_rate_limit_redis, get_redis, cache_lock, login_attempts):
    """Register redirect routes onto the Blueprint with injected auth/rate-limit helpers."""

    @redirects_bp.route("/redir/<slug>", methods=["GET", "POST"])
    def handle_redirect(slug):
        """Public redirect endpoint supporting external URLs and PIN/password-protected RouteGhost services."""
        redir = db.get_redirect_by_slug(slug)
        if not redir or not redir.get("enabled"):
            resp = make_response(
                render_template(
                    "redir_gate.html",
                    error_title="Link Not Found",
                    error_icon="🔍",
                    error_message="This redirect link does not exist or has been disabled.",
                ),
                404,
            )
            return _no_cache_response(resp)

        if _is_redirect_expired(redir):
            resp = make_response(
                render_template(
                    "redir_gate.html",
                    error_title="Link Expired",
                    error_icon="⏳",
                    error_message="This redirect link has expired.",
                ),
                410,
            )
            return _no_cache_response(resp)

        # Check PIN / Password protection BEFORE revealing whether a service is online/offline
        if redir.get("passcode_hash"):
            if request.method == "GET":
                resp = make_response(render_template("redir_gate.html", slug=redir["slug"], error=None), 200)
                return _no_cache_response(resp)

            rate_id = f"{request.remote_addr}:{redir['id']}"
            if not check_rate_limit_redis("redir", rate_id, limit=5, window=60):
                resp = make_response(
                    render_template(
                        "redir_gate.html",
                        slug=redir["slug"],
                        error="Too many attempts. Please wait a minute and try again.",
                    ),
                    429,
                )
                return _no_cache_response(resp)

            passcode = request.form.get("passcode", "")
            if not passcode or not check_password_hash(redir["passcode_hash"], passcode):
                resp = make_response(
                    render_template(
                        "redir_gate.html",
                        slug=redir["slug"],
                        error="Invalid PIN or password.",
                    ),
                    401,
                )
                return _no_cache_response(resp)

            # Clear rate-limit counter on valid unlock so legitimate repeat visits aren't blocked
            r = get_redis()
            if r:
                try:
                    r.delete(f"rate_limit:redir:{rate_id}")
                except redis.RedisError:
                    pass
            with cache_lock:
                login_attempts.pop(f"redir:{rate_id}", None)

        destination, err_msg = _resolve_redirect_destination(redir)
        if err_msg or not destination:
            resp = make_response(
                render_template(
                    "redir_gate.html",
                    error_title="Service Offline",
                    error_icon="💤",
                    error_message=err_msg or "Target destination is unavailable.",
                ),
                503,
            )
            return _no_cache_response(resp)

        db.record_redirect_hit(redir["id"])
        resp = make_response(redirect(destination, code=302))
        return _no_cache_response(resp)

    @redirects_bp.route("/redirects", methods=["GET"])
    @login_required
    def redirects_page():
        """Web UI for managing URL and service redirects."""
        redirects_list = db.get_all_redirects()
        services = db.get_all_services()
        base_url = os.environ.get("ORIGIN", request.host_url).rstrip("/")
        return render_template("redirects.html", redirects=redirects_list, services=services, base_url=base_url)

    @redirects_bp.route("/api/redirects", methods=["GET"])
    @api_key_or_login_required
    def api_list_redirects():
        """List all configured redirects."""
        return jsonify([_serialize_redirect(r) for r in db.get_all_redirects()])

    @redirects_bp.route("/api/redirects", methods=["POST"])
    @api_key_or_login_required
    def api_create_redirect():
        """Create a new redirect (external URL or RouteGhost service)."""
        data = request.get_json(silent=True) or {}
        try:
            parsed, err_resp = _parse_redirect_payload(data, existing=None)
            if err_resp:
                return err_resp

            new_id = db.add_redirect(
                slug=parsed["slug"],
                target_type=parsed["target_type"],
                target_url=parsed["target_url"],
                service_id=parsed["service_id"],
                passcode_hash=parsed["passcode_hash"],
                enabled=parsed["enabled"],
                expires_at=parsed["expires_at"],
            )
            created = db.get_redirect(new_id)
            return jsonify({
                "message": f"Redirect '/redir/{parsed['slug']}' created successfully!",
                "redirect": _serialize_redirect(created),
            }), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error("Error creating redirect: %s", e)
            return jsonify({"error": "Failed to create redirect."}), 500

    @redirects_bp.route("/api/redirects/<int:redir_id>", methods=["PUT"])
    @api_key_or_login_required
    def api_update_redirect(redir_id):
        """Update an existing redirect."""
        existing = db.get_redirect(redir_id)
        if not existing:
            return jsonify({"error": "Redirect not found."}), 404

        data = request.get_json(silent=True) or {}
        try:
            parsed, err_resp = _parse_redirect_payload(data, existing=existing)
            if err_resp:
                return err_resp

            db.update_redirect(
                redir_id,
                slug=parsed["slug"],
                target_type=parsed["target_type"],
                target_url=parsed["target_url"],
                service_id=parsed["service_id"],
                passcode_hash=parsed["passcode_hash"],
                keep_passcode=parsed["keep_passcode"],
                enabled=parsed["enabled"],
                expires_at=parsed["expires_at"],
            )
            updated = db.get_redirect(redir_id)
            return jsonify({
                "message": f"Redirect '/redir/{parsed['slug']}' updated successfully!",
                "redirect": _serialize_redirect(updated),
            })
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.error("Error updating redirect: %s", e)
            return jsonify({"error": "Failed to update redirect."}), 500

    @redirects_bp.route("/api/redirects/<int:redir_id>/toggle", methods=["POST"])
    @api_key_or_login_required
    def api_toggle_redirect(redir_id):
        """Enable or disable a redirect."""
        existing = db.get_redirect(redir_id)
        if not existing:
            return jsonify({"error": "Redirect not found."}), 404

        data = request.get_json(silent=True) or {}
        new_state = not bool(existing["enabled"]) if "enabled" not in data else bool(data["enabled"])
        db.set_redirect_enabled(redir_id, new_state)
        state_label = "enabled" if new_state else "disabled"
        return jsonify({"message": f"Redirect '/redir/{existing['slug']}' {state_label}.", "enabled": new_state})

    @redirects_bp.route("/api/redirects/<int:redir_id>", methods=["DELETE"])
    @api_key_or_login_required
    def api_delete_redirect(redir_id):
        """Delete a redirect."""
        existing = db.get_redirect(redir_id)
        if not existing:
            return jsonify({"error": "Redirect not found."}), 404
        db.delete_redirect(redir_id)
        return jsonify({"message": f"Redirect '/redir/{existing['slug']}' deleted."})

    app.register_blueprint(redirects_bp)
