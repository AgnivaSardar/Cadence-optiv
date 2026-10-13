"""Cryptographic utilities for the TPRM pipeline.

All keys are loaded from environment variables, never from config YAML.
HMAC comparisons use hmac.compare_digest() for constant-time safety.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from base64 import urlsafe_b64decode
from pathlib import Path
from typing import Final

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

from tprm.common.errors import VaultError

# ── Constants ─────────────────────────────────────────────────────────────────

_TOKEN_HEX_LEN: Final[int] = 8  # 8 hex chars = 32-bit token suffix


# ── Key loading ───────────────────────────────────────────────────────────────


def _load_dotenv_value(name: str) -> str:
    """Read a single key from the .env file closest to the repo root.

    Used as a last-resort fallback when the env var isn't exported to the
    process — e.g. when uvicorn is started without ``dotenv`` loading.
    """
    # Walk up from this file (src/tprm/common/) to find .env
    search = Path(__file__).parents[3]  # tprm/ project root
    for candidate in (search / ".env", search.parent / ".env"):
        if candidate.exists():
            try:
                for line in candidate.read_text().splitlines():
                    line = line.strip()
                    if line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    if key.strip() == name:
                        return val.strip()
            except OSError:
                pass
    return ""


def _require_env(name: str) -> str:
    """Load a required environment variable; raise at call site if missing."""
    # ``BaseSettings`` reads .env for application settings, but that does not
    # populate os.environ. Load the project env file here because cryptographic
    # callers (including the CLI) access secrets directly from the environment.
    env_file = Path(__file__).parents[3] / ".env"
    load_dotenv(dotenv_path=env_file, override=False)
    val = os.environ.get(name, "").strip()
    if not val:
        # Fallback: read directly from .env (handles bare uvicorn without dotenv loader)
        val = _load_dotenv_value(name)
    if not val:
        raise VaultError(
            f"Required environment variable {name!r} is not set. "
            "Set it before starting the application."
        )
    return val


def load_vault_key() -> bytes:
    """Load the Fernet vault key from TPRM_VAULT_KEY env var.

    The key must be a URL-safe base64-encoded 32-byte value (Fernet format).
    """
    raw = _require_env("TPRM_VAULT_KEY")
    try:
        decoded = urlsafe_b64decode(raw + "==")  # pad for robustness
        if len(decoded) != 32:
            raise VaultError("TPRM_VAULT_KEY must decode to exactly 32 bytes")
    except Exception as exc:
        raise VaultError(f"TPRM_VAULT_KEY is not valid base64: {exc}") from exc
    return raw.encode()


def load_gate_signing_key() -> bytes:
    """Load the gate HMAC signing key from GATE_SIGNING_KEY env var.

    Accepts any non-empty string; internally UTF-8 encoded.
    """
    return _require_env("GATE_SIGNING_KEY").encode()


def generate_fernet_key() -> str:
    """Generate a new random Fernet key (for dev/testing only)."""
    return Fernet.generate_key().decode()


# ── Fernet encryption / decryption ────────────────────────────────────────────


def fernet_encrypt(plaintext: str, key: bytes) -> bytes:
    """Encrypt a string value with Fernet.  Returns ciphertext bytes."""
    try:
        f = Fernet(key)
        return f.encrypt(plaintext.encode())
    except Exception as exc:
        raise VaultError("Fernet encryption failed") from exc


def fernet_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Decrypt Fernet ciphertext back to a string.  Raises VaultError on failure."""
    try:
        f = Fernet(key)
        return f.decrypt(ciphertext).decode()
    except InvalidToken as exc:
        raise VaultError("Fernet decryption failed: invalid token or wrong key") from exc
    except Exception as exc:
        raise VaultError("Fernet decryption failed") from exc


# ── HMAC signing ──────────────────────────────────────────────────────────────


def hmac_sign(data: bytes, key: bytes) -> str:
    """Return HMAC-SHA256 hex digest of ``data`` under ``key``."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(data: bytes, key: bytes, expected_signature: str) -> bool:
    """Constant-time HMAC-SHA256 verification.  Returns True iff valid."""
    actual = hmac_sign(data, key)
    return hmac.compare_digest(actual, expected_signature)


# ── Deterministic token derivation ────────────────────────────────────────────


def derive_token(entity_text: str, entity_type: str, assessment_salt: str) -> str:
    """Derive a deterministic, assessment-scoped token for an entity value.

    The token is:
        ``<<ENTITY_TYPE_xxxxxxxx>>``
    where ``xxxxxxxx`` is the first 8 hex characters of:
        HMAC-SHA256(key=assessment_salt, msg=entity_type + ":" + entity_text)

    Properties:
    - Deterministic within a vendor assessment (same salt → same token)
    - Non-deterministic across assessments (different salt → different token)
    - NEVER includes the raw entity value in the output
    """
    msg = f"{entity_type}:{entity_text}".encode()
    digest = hmac.new(assessment_salt.encode(), msg, hashlib.sha256).hexdigest()
    token_suffix = digest[:_TOKEN_HEX_LEN]
    # Sanitise entity_type to uppercase + underscores for the token prefix
    safe_type = entity_type.upper().replace(" ", "_").replace("-", "_")
    return f"<<{safe_type}_{token_suffix}>>"


def derive_assessment_salt(vendor_id: str, assessment_id: str, master_key: bytes) -> str:
    """Derive a per-assessment HMAC salt from the master vault key.

    Ensures tokens from one assessment cannot be mapped to another vendor.
    """
    msg = f"salt:{vendor_id}:{assessment_id}".encode()
    return hmac.new(master_key, msg, hashlib.sha256).hexdigest()


# ── Shannon entropy ───────────────────────────────────────────────────────────


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy in bits/character for ``text``.

    Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0
    length = len(text)
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    import math

    return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)


def max_window_entropy(text: str, window: int = 20) -> float:
    """Return the maximum Shannon entropy over all windows of ``window`` chars."""
    if len(text) < window:
        return shannon_entropy(text)
    return max(shannon_entropy(text[i : i + window]) for i in range(len(text) - window + 1))
