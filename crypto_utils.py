"""Symmetric encryption utilities for sensitive settings stored at rest in SQLite.

Uses Fernet (AES-128-CBC + HMAC-SHA256) with a key derived from
ROUTEGHOST_ENCRYPTION_KEY or DATA_DIR/.secret_key. Values are prefixed with
'enc:v1:' so existing plaintext values remain transparently readable until
migrated.
"""
import base64
import hashlib
import os
from cryptography.fernet import Fernet, InvalidToken

ENCRYPTED_PREFIX = "enc:v1:"

SENSITIVE_SETTINGS = frozenset({
    "CF_API_TOKEN",
    "UNIFI_PASS",
    "REDIS_PASS",
    "VPS_SSH_KEY",
    "WG_PRIVATE_KEY",
    "MQTT_PASS",
    "DISCORD_WEBHOOK_URL",
})

_fernet_cache = {}


def _get_secret_material(data_dir):
    """Load or create raw key material for deriving the Fernet key."""
    env_key = os.environ.get("ROUTEGHOST_ENCRYPTION_KEY")
    if env_key:
        return env_key.encode("utf-8")

    os.makedirs(data_dir, exist_ok=True)
    secret_key_file = os.path.join(data_dir, ".secret_key")
    if os.path.exists(secret_key_file):
        with open(secret_key_file, "rb") as f:
            raw = f.read()
        if raw:
            return raw

    raw = os.urandom(32)
    with open(secret_key_file, "wb") as f:
        f.write(raw)
    try:
        os.chmod(secret_key_file, 0o600)
    except OSError:
        pass
    return raw


def get_fernet(data_dir):
    """Return a cached Fernet instance bound to data_dir / env key."""
    cache_key = (data_dir, os.environ.get("ROUTEGHOST_ENCRYPTION_KEY", ""))
    cached = _fernet_cache.get(cache_key)
    if cached is not None:
        return cached

    material = _get_secret_material(data_dir)
    derived = base64.urlsafe_b64encode(hashlib.sha256(material).digest())
    fernet = Fernet(derived)
    _fernet_cache[cache_key] = fernet
    return fernet


def is_encrypted(value):
    """Return True if value already carries the encrypted prefix."""
    return isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX)


def encrypt_value(value, data_dir):
    """Encrypt a plaintext string; returns empty/None or already-encrypted values unchanged."""
    if not value or is_encrypted(value):
        return value
    token = get_fernet(data_dir).encrypt(str(value).encode("utf-8")).decode("ascii")
    return f"{ENCRYPTED_PREFIX}{token}"


def decrypt_value(value, data_dir):
    """Decrypt an 'enc:v1:' string; passes plaintext values through unchanged."""
    if not value or not is_encrypted(value):
        return value
    token = value[len(ENCRYPTED_PREFIX):].encode("ascii")
    try:
        return get_fernet(data_dir).decrypt(token).decode("utf-8")
    except InvalidToken:
        # Return empty string rather than crashing if key rotated unexpectedly
        return ""
