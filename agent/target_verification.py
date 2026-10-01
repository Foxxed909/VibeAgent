"""Ownership verification for native-worker targets.

Verification is intentionally limited to exact hostnames already approved by the
server-side native-worker allowlist, preventing this endpoint from becoming a
general-purpose SSRF primitive.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from .worker_client import get_worker_config, target_host, target_is_worker_allowed

KV_URL = (os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""
STATE_DIR = Path(os.environ.get("VIBE_AGENT_VERIFY_DIR", "/tmp/vibeagent_verify"))
CHALLENGE_TTL = int(os.environ.get("VIBE_AGENT_VERIFY_CHALLENGE_TTL", "900"))
VERIFIED_TTL = int(os.environ.get("VIBE_AGENT_VERIFIED_TTL", "604800"))
VERIFY_PATH = "/.well-known/vibeagent-verification.txt"


class VerificationError(RuntimeError):
    pass


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


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
    cfg = get_worker_config()
    if not cfg or not target_is_worker_allowed("https://" + host, cfg):
        raise VerificationError("target is not approved by the native-worker allowlist")
    return host, "https://" + host


def create_challenge(target: str) -> Dict[str, Any]:
    host, origin = _exact_https_target(target)
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
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "VibeAgent-OwnershipVerifier/1.0", "Accept": "text/plain"},
        method="GET",
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirectHandler(),
    )
    try:
        with opener.open(req, timeout=10) as resp:
            body = resp.read(4097)
            if len(body) > 4096:
                raise VerificationError("verification file is too large")
            if resp.status != 200:
                raise VerificationError(f"verification URL returned HTTP {resp.status}")
    except urllib.error.HTTPError as exc:
        raise VerificationError(f"verification URL returned HTTP {exc.code}") from exc
    except VerificationError:
        raise
    except Exception as exc:
        raise VerificationError("verification URL could not be reached") from exc
    return body.decode("utf-8", errors="replace").strip()


def confirm_challenge(target: str) -> Dict[str, Any]:
    host, origin = _exact_https_target(target)
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


def is_target_verified(target: str) -> bool:
    try:
        host, _ = _exact_https_target(target)
    except VerificationError:
        return False
    record = _read_state(_host_key("verified-host", host))
    return bool(record and record.get("host") == host)
