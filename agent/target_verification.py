"""Exact-host ownership verification for live scans."""
from __future__ import annotations

import hashlib
import hmac
import base64
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from .net_safety import NetworkSafetyError, request_url

KV_URL = (os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""
STATE_DIR = Path(os.environ.get("VIBE_AGENT_VERIFY_DIR", "/tmp/vibeagent_verify"))
CHALLENGE_TTL = int(os.environ.get("VIBE_AGENT_VERIFY_CHALLENGE_TTL", "900"))
VERIFIED_TTL = int(os.environ.get("VIBE_AGENT_VERIFIED_TTL", "604800"))
VERIFY_PATH = "/.well-known/vibeagent-verification.txt"
STATELESS_PREFIX = "vibeagent-v1"


class VerificationError(RuntimeError):
    pass


def _verification_secret() -> bytes:
    value = (os.environ.get("VIBE_AGENT_VERIFICATION_SECRET") or "").strip()
    return value.encode("utf-8")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    """Reject non-canonical encodings, including altered unused trailing bits."""
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if not value or _b64url_encode(raw) != value:
        raise ValueError("non-canonical base64url token")
    return raw


def _signed_token(kind: str, host: str, ttl: int) -> str:
    secret = _verification_secret()
    if len(secret) < 32:
        raise VerificationError("VIBE_AGENT_VERIFICATION_SECRET must contain at least 32 characters")
    payload = json.dumps(
        {
            "v": 1,
            "kind": kind,
            "host": host,
            "exp": int(time.time()) + ttl,
            "nonce": secrets.token_urlsafe(12),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = _b64url_encode(payload)
    signature = hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{STATELESS_PREFIX}.{encoded}.{_b64url_encode(signature)}"


def _verify_signed_token(token: str, *, kind: str, host: str) -> bool:
    secret = _verification_secret()
    if len(secret) < 32:
        return False
    parts = (token or "").strip().split(".")
    if len(parts) != 3 or parts[0] != STATELESS_PREFIX:
        return False
    try:
        expected = hmac.new(secret, parts[1].encode("ascii"), hashlib.sha256).digest()
        supplied = _b64url_decode(parts[2])
        if not hmac.compare_digest(supplied, expected):
            return False
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        return bool(
            payload.get("v") == 1
            and payload.get("kind") == kind
            and payload.get("host") == host
            and int(payload.get("exp") or 0) >= int(time.time())
        )
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return False


def _kv_enabled() -> bool:
    return bool(KV_URL and KV_TOKEN)


def _kv_command(*args: Any) -> Any:
    body = json.dumps(list(args)).encode("utf-8")
    req = urllib.request.Request(
        KV_URL,
        data=body,
        headers={"Authorization": f"Bearer {KV_TOKEN}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8")).get("result")


def _host_key(prefix: str, host: str) -> str:
    digest = hashlib.sha256(host.encode("utf-8")).hexdigest()
    return f"vibeagent:{prefix}:{digest}"


def _write_state(key: str, value: Dict[str, Any], ttl: int) -> None:
    payload = json.dumps(value)
    if _kv_enabled():
        _kv_command("SET", key, payload, "EX", ttl)
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = STATE_DIR / (hashlib.sha256(key.encode("utf-8")).hexdigest() + ".json")
    path.write_text(json.dumps({"expires": time.time() + ttl, "value": value}), encoding="utf-8")


def _read_state(key: str) -> Optional[Dict[str, Any]]:
    if _kv_enabled():
        raw = _kv_command("GET", key)
        if not raw:
            return None
        return json.loads(raw) if isinstance(raw, str) else raw
    path = STATE_DIR / (hashlib.sha256(key.encode("utf-8")).hexdigest() + ".json")
    if not path.exists():
        return None
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        if float(record.get("expires") or 0) < time.time():
            path.unlink(missing_ok=True)
            return None
        value = record.get("value")
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _exact_https_target(target: str) -> tuple[str, str]:
    raw = (target or "").strip()
    if "*" in raw:
        raise VerificationError("wildcard targets cannot be ownership-verified")
    parsed = urllib.parse.urlsplit(raw if "://" in raw else "https://" + raw)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        raise VerificationError("ownership verification requires an exact HTTPS target")
    return host, "https://" + host


def approve_operator_target(target: str) -> Dict[str, Any]:
    """Issue an ordinary exact-host proof for a deployment-admin approved host.

    This never checks target pages and never grants a wildcard or CIDR range.
    The HTTP caller must separately prove possession of the operator token.
    The host approval list is configured only by the deployment operator.
    """
    host, _ = _exact_https_target(target)
    raw = (target or "").strip()
    try:
        parsed = urllib.parse.urlsplit(raw if "://" in raw else "https://" + raw)
        port = parsed.port
    except ValueError as exc:
        raise VerificationError("invalid target port") from exc
    if port not in (None, 443):
        raise VerificationError("operator approval supports only the standard HTTPS port")
    approved = {
        item.strip().lower().rstrip(".")
        for item in os.environ.get("VIBE_AGENT_OWNER_APPROVED_HOSTS", "").split(",")
        if item.strip() and "*" not in item and "/" not in item and ":" not in item
    }
    if not approved or host not in approved:
        raise VerificationError("hostname is not approved by this deployment's operator")
    if len(_verification_secret()) < 32:
        raise VerificationError("a strong VIBE_AGENT_VERIFICATION_SECRET is required")
    approval_ttl = min(3600, VERIFIED_TTL)  # Re-approval required after one hour.
    return {
        "host": host,
        "verified": True,
        "expires_in": approval_ttl,
        "proof": _signed_token("proof", host, approval_ttl),
        "mode": "operator-approved",
    }


def create_challenge(target: str) -> Dict[str, Any]:
    host, origin = _exact_https_target(target)
    if _verification_secret():
        token = _signed_token("challenge", host, CHALLENGE_TTL)
        return {
            "host": host,
            "token": token,
            "path": VERIFY_PATH,
            "verification_url": origin + VERIFY_PATH,
            "expires_in": CHALLENGE_TTL,
            "mode": "stateless",
        }
    token = "vibeagent-" + secrets.token_urlsafe(24)
    record = {"host": host, "token": token, "created_at": int(time.time())}
    _write_state(_host_key("verify-challenge", host), record, CHALLENGE_TTL)
    return {
        "host": host,
        "token": token,
        "path": VERIFY_PATH,
        "verification_url": origin + VERIFY_PATH,
        "expires_in": CHALLENGE_TTL,
    }


def _fetch_verification(url: str) -> str:
    try:
        response = request_url(
            url,
            headers={"User-Agent": "VibeAgent-OwnershipVerifier/1.0", "Accept": "text/plain"},
            timeout=10,
            max_bytes=4096,
            require_https=True,
        )
    except NetworkSafetyError as exc:
        raise VerificationError(str(exc)) from exc
    if response.status != 200:
        raise VerificationError(f"verification URL returned HTTP {response.status}")
    return response.body.decode("utf-8", errors="replace").strip()


def confirm_challenge(target: str) -> Dict[str, Any]:
    host, origin = _exact_https_target(target)
    if _verification_secret():
        actual = _fetch_verification(origin + VERIFY_PATH)
        if not _verify_signed_token(actual, kind="challenge", host=host):
            raise VerificationError("verification token did not match, expired, or was issued for another host")
        return {
            "host": host,
            "verified": True,
            "expires_in": VERIFIED_TTL,
            "proof": _signed_token("proof", host, VERIFIED_TTL),
            "mode": "stateless",
        }
    record = _read_state(_host_key("verify-challenge", host))
    if not record:
        raise VerificationError("no active verification challenge for this host")
    expected = str(record.get("token") or "")
    actual = _fetch_verification(origin + VERIFY_PATH)
    if not expected or not hmac.compare_digest(actual, expected):
        raise VerificationError("verification token did not match")
    verified = {"host": host, "verified_at": int(time.time())}
    _write_state(_host_key("verified-host", host), verified, VERIFIED_TTL)
    return {"host": host, "verified": True, "expires_in": VERIFIED_TTL}


def is_target_verified(target: str, proof: Optional[str] = None) -> bool:
    try:
        host, _ = _exact_https_target(target)
    except VerificationError:
        return False
    if proof and _verify_signed_token(proof, kind="proof", host=host):
        return True
    record = _read_state(_host_key("verified-host", host))
    return bool(record and record.get("host") == host)
