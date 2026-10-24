"""Local Sign in with ChatGPT support for the VibeAgent CLI.

This module intentionally binds OAuth to a loopback callback and stores credentials
on the user's device. It is not used by Vercel's hosted API handlers.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .request_context import (
    reset_chatgpt_plan_context,
    set_chatgpt_plan_context,
)

ISSUER = "https://auth.openai.com"
AUTHORIZATION_URL = "https://auth.openai.com/api/accounts/authorize"
TOKEN_URL = "https://auth.openai.com/api/accounts/oauth/token"
JWKS_URL = "https://auth.openai.com/.well-known/jwks.json"
MODELS_URL = "https://api.openai.com/v1/models"
RESOURCE = "https://api.openai.com/v1"
PLAN_SCOPE = "chatgpt.tokens.use.direct"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
DYNAMIC_CLIENT_ID = "dynamic_agent_client"
AGENT_NAME = "VibeAgent"
JWKS_CACHE_SECONDS = 3600
MAX_AUTH_RESPONSE_BYTES = 1024 * 1024
_JWKS_CACHE: Tuple[float, Dict[str, Any]] = (0.0, {})


class ChatGPTAuthError(RuntimeError):
    """A safe, user-facing authentication or model-catalog error."""


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 16384:
        raise ChatGPTAuthError("OpenAI returned an invalid token.")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ChatGPTAuthError("OpenAI returned an invalid token.") from exc


def _random_value(size: int = 32) -> str:
    return _b64url_encode(secrets.token_bytes(size))


def _auth_path() -> Path:
    override = os.environ.get("VIBEAGENT_CHATGPT_AUTH_FILE", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "vibeagent" / "chatgpt_auth.json"


def _load_store(*, require_account: bool = True) -> Dict[str, Any]:
    path = _auth_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ChatGPTAuthError("No ChatGPT account is connected. Run: python -m agent.cli auth login")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ChatGPTAuthError("The local ChatGPT credential file is unreadable. Sign in again.") from exc
    if not isinstance(data, dict):
        raise ChatGPTAuthError("The local ChatGPT credential file is invalid. Sign in again.")
    if require_account and not isinstance(data.get("account"), dict):
        raise ChatGPTAuthError("The local ChatGPT credential file is invalid. Sign in again.")
    return data


def _save_store(data: Dict[str, Any]) -> None:
    path = _auth_path()
    parent = path.parent
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
        fd, tmp_path = tempfile.mkstemp(prefix=".chatgpt-auth-", dir=str(parent))
        try:
            try:
                os.fchmod(fd, 0o600)
            except (AttributeError, OSError):
                pass
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, separators=(",", ":"), ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
    except OSError as exc:
        raise ChatGPTAuthError("Could not safely save ChatGPT credentials on this device.") from exc


def _http_json(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read(MAX_AUTH_RESPONSE_BYTES + 1)
            if len(raw) > MAX_AUTH_RESPONSE_BYTES:
                raise ChatGPTAuthError("OpenAI authentication response exceeded the size limit.")
    except urllib.error.HTTPError as exc:
        code = exc.code
        raise ChatGPTAuthError(f"OpenAI authentication request failed with HTTP {code}.") from exc
    except urllib.error.URLError as exc:
        raise ChatGPTAuthError("Could not reach OpenAI authentication. Check the network and retry.") from exc
    except TimeoutError as exc:
        raise ChatGPTAuthError("OpenAI authentication timed out. Retry the sign-in.") from exc
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ChatGPTAuthError("OpenAI returned an invalid authentication response.") from exc
    if not isinstance(result, dict):
        raise ChatGPTAuthError("OpenAI returned an invalid authentication response.")
    return result


def _post_form(url: str, fields: Dict[str, str]) -> Dict[str, Any]:
    body = urllib.parse.urlencode(fields).encode("utf-8")
    return _http_json(
        url,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=body,
        timeout=45,
    )


def _get_jwks(*, force: bool = False) -> Dict[str, Any]:
    global _JWKS_CACHE
    now = time.time()
    cached_at, cached = _JWKS_CACHE
    if not force and cached and now - cached_at < JWKS_CACHE_SECONDS:
        return cached
    data = _http_json(JWKS_URL, headers={"Accept": "application/json"})
    keys = data.get("keys")
    if not isinstance(keys, list):
        raise ChatGPTAuthError("OpenAI returned invalid signing keys.")
    by_kid = {
        key.get("kid"): key
        for key in keys
        if isinstance(key, dict) and isinstance(key.get("kid"), str)
    }
    if not by_kid:
        raise ChatGPTAuthError("OpenAI returned no usable signing keys.")
    _JWKS_CACHE = (now, by_kid)
    return by_kid


_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _verify_rs256_signature(signing_input: bytes, signature: bytes, jwk: Dict[str, Any]) -> bool:
    try:
        modulus = int.from_bytes(_b64url_decode(jwk["n"]), "big")
        exponent = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    except (KeyError, TypeError, ValueError, ChatGPTAuthError):
        return False
    if modulus.bit_length() < 2048 or exponent < 3 or exponent % 2 == 0:
        return False
    size = (modulus.bit_length() + 7) // 8
    if len(signature) != size:
        return False
    signature_int = int.from_bytes(signature, "big")
    if signature_int >= modulus:
        return False
    encoded = pow(signature_int, exponent, modulus).to_bytes(size, "big")
    digest_info = _SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
    if size < len(digest_info) + 11:
        return False
    padding = b"\xff" * (size - len(digest_info) - 3)
    expected = b"\x00\x01" + padding + b"\x00" + digest_info
    return hmac.compare_digest(encoded, expected)


def _verify_id_token(
    token: str,
    *,
    client_id: str,
    nonce: Optional[str] = None,
    expected_subject: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("segments")
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        signature = _b64url_decode(parts[2])
    except (ValueError, UnicodeError, json.JSONDecodeError, ChatGPTAuthError) as exc:
        raise ChatGPTAuthError("OpenAI returned an invalid identity token.") from exc
    if (
        not isinstance(header, dict)
        or header.get("alg") != "RS256"
        or header.get("crit")
        or header.get("b64") is False
    ):
        raise ChatGPTAuthError("OpenAI returned an unsupported identity token.")
    if not isinstance(claims, dict):
        raise ChatGPTAuthError("OpenAI returned an invalid identity token.")
    kid = header.get("kid")
    jwk = _get_jwks().get(kid)
    if not jwk and kid:
        jwk = _get_jwks(force=True).get(kid)
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        raise ChatGPTAuthError("Could not verify OpenAI's identity token.")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    if not _verify_rs256_signature(signing_input, signature, jwk):
        raise ChatGPTAuthError("Could not verify OpenAI's identity token.")

    now = time.time()
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    exp = claims.get("exp")
    nbf = claims.get("nbf")
    issued_at = claims.get("iat")
    valid_time_claims = (
        isinstance(exp, (int, float)) and not isinstance(exp, bool) and exp > now
        and (nbf is None or (isinstance(nbf, (int, float)) and not isinstance(nbf, bool) and nbf <= now + 60))
        and (issued_at is None or (
            isinstance(issued_at, (int, float))
            and not isinstance(issued_at, bool)
            and issued_at <= now + 300
        ))
    )
    valid_audience = (
        isinstance(audiences, list)
        and bool(audiences)
        and all(isinstance(value, str) for value in audiences)
        and client_id in audiences
    )
    if (
        claims.get("iss") != ISSUER
        or not valid_audience
        or not isinstance(claims.get("sub"), str)
        or not claims.get("sub")
        or not valid_time_claims
    ):
        raise ChatGPTAuthError("OpenAI's identity token failed validation.")
    if len(audiences) > 1 and claims.get("azp") != client_id:
        raise ChatGPTAuthError("OpenAI's identity token failed validation.")
    if nonce is not None and (
        not isinstance(claims.get("nonce"), str)
        or not hmac.compare_digest(claims["nonce"], nonce)
    ):
        raise ChatGPTAuthError("OpenAI's identity token nonce did not match.")
    if expected_subject and not hmac.compare_digest(claims["sub"], expected_subject):
        raise ChatGPTAuthError("The signed-in ChatGPT account did not match the selected account.")
    return claims


class _CallbackServer(http.server.HTTPServer):
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], state: str):
        super().__init__(address, _CallbackHandler)
        self.expected_state = state
        self.callback: Optional[Dict[str, str]] = None


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/auth/callback":
            self.send_error(404)
            return
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        received_state = (query.get("state") or [""])[0]
        if not hmac.compare_digest(received_state, self.server.expected_state):
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b"State check failed. Return to the VibeAgent terminal and retry.")
            return
        self.server.callback = {
            "state": received_state,
            "code": (query.get("code") or [""])[0],
            "client_id": (query.get("client_id") or [""])[0],
            "scope": (query.get("scope") or [""])[0],
            "error": (query.get("error") or [""])[0],
        }
        self.send_response(200 if self.server.callback["code"] else 400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.server.callback["code"]:
            self.wfile.write(
                b"<!doctype html><meta charset=utf-8><title>VibeAgent sign-in</title>"
                b"<p>Sign-in received. Return to the VibeAgent terminal.</p>"
            )
        else:
            self.wfile.write(
                b"<!doctype html><meta charset=utf-8><title>VibeAgent sign-in</title>"
                b"<p>Sign-in was not completed. Return to the VibeAgent terminal.</p>"
            )

    def log_message(self, format: str, *args: Any) -> None:
        return



def _expires_at(token_response: Dict[str, Any]) -> float:
    value = token_response.get("expires_in", 3600)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0 or value > 86400:
        raise ChatGPTAuthError("OpenAI returned an invalid token lifetime.")
    return time.time() + int(value)

def login() -> Dict[str, Any]:
    """Run the official local OAuth flow and save one user's ChatGPT plan session."""
    store = {}
    try:
        existing = _load_store(require_account=False)
        store = existing
    except ChatGPTAuthError as exc:
        if "No ChatGPT account is connected" not in str(exc):
            raise
    host_id = store.get("ext_agent_host_id")
    if not isinstance(host_id, str) or not host_id:
        host_id = "urn:uuid:" + str(uuid.uuid4())
        store["ext_agent_host_id"] = host_id
        _save_store({**store, "ext_agent_host_id": host_id})
    existing_account = store.get("account")
    if not isinstance(existing_account, dict):
        existing_account = None
    if existing_account and (
        not isinstance(existing_account.get("client_id"), str)
        or not existing_account.get("client_id")
        or not isinstance(existing_account.get("subject"), str)
        or not existing_account.get("subject")
    ):
        raise ChatGPTAuthError("The saved ChatGPT registration is invalid. Run auth logout and sign in again.")

    state = _random_value()
    nonce = _random_value()
    verifier = _random_value(48)
    challenge = _b64url_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    server = _CallbackServer(("127.0.0.1", 0), state)
    redirect_uri = f"http://127.0.0.1:{server.server_port}/auth/callback"
    auth_query = {
        "client_id": (
            existing_account.get("client_id")
            if existing_account
            else DYNAMIC_CLIENT_ID
        ),
        "ext_agent_host_id": host_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": SCOPES,
        "resource": RESOURCE,
        "state": state,
        "nonce": nonce,
        "code_challenge_method": "S256",
        "code_challenge": challenge,
    }
    if existing_account:
        if isinstance(existing_account.get("id_token"), str):
            auth_query["id_token_hint"] = existing_account["id_token"]
        if isinstance(existing_account.get("email"), str) and existing_account["email"]:
            auth_query["login_hint"] = existing_account["email"]
    else:
        auth_query["agent_name_hint"] = AGENT_NAME
    url = AUTHORIZATION_URL + "?" + urllib.parse.urlencode(auth_query)
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print("Opening Sign in with ChatGPT in your browser.")
    print("If it does not open, visit this URL:")
    print(url)
    opened = False
    try:
        opened = bool(webbrowser.open(url, new=1, autoraise=True))
    except Exception:
        opened = False
    if not opened:
        print("Open the URL manually in a browser on this same device.")
    try:
        deadline = time.monotonic() + 300
        while server.callback is None and time.monotonic() < deadline:
            time.sleep(0.1)
        callback = server.callback
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    if callback is None:
        raise ChatGPTAuthError("Sign-in timed out after five minutes.")
    if callback.get("error"):
        raise ChatGPTAuthError("Sign-in was cancelled or denied.")
    code = callback.get("code") or ""
    returned_client_id = callback.get("client_id") or ""
    if existing_account:
        client_id = existing_account.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise ChatGPTAuthError("The saved ChatGPT client registration is invalid. Sign in again.")
        if returned_client_id and returned_client_id != client_id:
            raise ChatGPTAuthError("OpenAI returned a different client registration than the selected account.")
    else:
        client_id = returned_client_id
        if not client_id or client_id == DYNAMIC_CLIENT_ID:
            raise ChatGPTAuthError("OpenAI did not finish the dynamic client registration.")
    if not code:
        raise ChatGPTAuthError("OpenAI did not return an authorization code.")
    token_data = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "resource": RESOURCE,
        },
    )
    scopes = str(token_data.get("scope") or "").split()
    if PLAN_SCOPE not in scopes:
        raise ChatGPTAuthError(
            "Sign-in succeeded, but ChatGPT plan usage was not authorized. Retry and enable plan use."
        )
    id_token = token_data.get("id_token")
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not all(isinstance(value, str) and value for value in (id_token, access_token, refresh_token)):
        raise ChatGPTAuthError("OpenAI returned an incomplete sign-in response.")
    claims = _verify_id_token(
        id_token,
        client_id=client_id,
        nonce=nonce,
        expected_subject=(
            str(existing_account.get("subject") or "")
            if existing_account
            else None
        ),
    )
    account = {
        "issuer": ISSUER,
        "subject": claims["sub"],
        "email": claims.get("email") if isinstance(claims.get("email"), str) else None,
        "name": claims.get("name") if isinstance(claims.get("name"), str) else None,
        "client_id": client_id,
        "ext_agent_host_id": host_id,
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_at": _expires_at(token_data),
        "scopes": sorted(set(scopes)),
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    store["version"] = 1
    store["ext_agent_host_id"] = host_id
    store["account"] = account
    _save_store(store)
    return account


def logout() -> None:
    path = _auth_path()
    try:
        store = _load_store(require_account=False)
    except ChatGPTAuthError as exc:
        if "No ChatGPT account is connected" in str(exc):
            return
        raise
    store.pop("account", None)
    _save_store(store)


def account_status() -> Dict[str, Any]:
    account = _load_store()["account"]
    return {
        "email": account.get("email"),
        "name": account.get("name"),
        "chatgpt_plan_usage": PLAN_SCOPE in (account.get("scopes") or []),
        "expires_at": account.get("expires_at"),
        "credential_file": str(_auth_path()),
    }


def get_access_token() -> str:
    store = _load_store()
    account = store["account"]
    if PLAN_SCOPE not in (account.get("scopes") or []):
        raise ChatGPTAuthError("This account has not authorized ChatGPT plan usage. Run sign-in again.")
    token = account.get("access_token")
    expiry = account.get("expires_at")
    if isinstance(token, str) and token and isinstance(expiry, (int, float)) and expiry > time.time() + 90:
        return token
    refresh_token = account.get("refresh_token")
    client_id = account.get("client_id")
    if not isinstance(refresh_token, str) or not refresh_token or not isinstance(client_id, str) or not client_id:
        raise ChatGPTAuthError("ChatGPT sign-in expired. Run: python -m agent.cli auth login")
    refreshed = _post_form(
        TOKEN_URL,
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
            "resource": RESOURCE,
        },
    )
    new_scope = refreshed.get("scope")
    scopes = sorted(set(str(new_scope).split())) if isinstance(new_scope, str) and new_scope.strip() else account.get("scopes", [])
    if PLAN_SCOPE not in scopes:
        raise ChatGPTAuthError("ChatGPT plan-use permission is no longer available. Sign in again.")
    new_access = refreshed.get("access_token")
    new_refresh = refreshed.get("refresh_token") or refresh_token
    if not isinstance(new_access, str) or not new_access:
        raise ChatGPTAuthError("OpenAI did not refresh the ChatGPT session. Sign in again.")
    updated = dict(account)
    updated["access_token"] = new_access
    updated["refresh_token"] = new_refresh
    updated["expires_at"] = _expires_at(refreshed)
    updated["scopes"] = scopes
    updated["saved_at"] = datetime.now(timezone.utc).isoformat()
    refreshed_id = refreshed.get("id_token")
    if isinstance(refreshed_id, str) and refreshed_id:
        claims = _verify_id_token(
            refreshed_id,
            client_id=client_id,
            expected_subject=str(account.get("subject") or ""),
        )
        updated["id_token"] = refreshed_id
        updated["email"] = claims.get("email") or updated.get("email")
        updated["name"] = claims.get("name") or updated.get("name")
    store["account"] = updated
    _save_store(store)
    return new_access


def list_models(access_token: Optional[str] = None) -> List[Dict[str, str]]:
    token = access_token or get_access_token()
    req = urllib.request.Request(
        MODELS_URL,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            raw = response.read(MAX_AUTH_RESPONSE_BYTES + 1)
            if len(raw) > MAX_AUTH_RESPONSE_BYTES:
                raise ChatGPTAuthError("OpenAI model catalog exceeded the size limit.")
    except urllib.error.HTTPError as exc:
        raise ChatGPTAuthError(f"Could not load this account's ChatGPT models (HTTP {exc.code}).") from exc
    except urllib.error.URLError as exc:
        raise ChatGPTAuthError("Could not load ChatGPT models. Check the network and retry.") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ChatGPTAuthError("OpenAI returned an invalid model catalog.") from exc
    entries = data.get("models") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        entries = data.get("data") if isinstance(data, dict) else None
    result = []
    seen = set()
    for item in entries or []:
        if not isinstance(item, dict) or item.get("visibility") != "list":
            continue
        slug = item.get("slug") or item.get("id")
        if not isinstance(slug, str) or not slug or slug in seen:
            continue
        seen.add(slug)
        result.append({
            "slug": slug,
            "display_name": str(item.get("display_name") or item.get("name") or slug),
        })
    return result


@contextmanager
def local_chatgpt_plan_session(selected_model: Optional[str] = None) -> Iterator[str]:
    token = get_access_token()
    catalog = list_models(token)
    slugs = [item["slug"] for item in catalog]
    if not slugs:
        raise ChatGPTAuthError("No ChatGPT models are available to this account.")
    model = selected_model or next(
        (candidate for candidate in ("gpt-6-luna", "gpt-6.1-sol", "gpt-6-sol") if candidate in slugs),
        slugs[0],
    )
    if model not in slugs:
        raise ChatGPTAuthError("That model is not available to the signed-in ChatGPT account.")
    context_token = set_chatgpt_plan_context(token, slugs, model)
    try:
        yield model
    finally:
        reset_chatgpt_plan_context(context_token)


def auth_command_main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m agent.cli auth")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("login", help="Sign in with ChatGPT and enable plan use")
    subparsers.add_parser("logout", help="Remove this device's saved ChatGPT credentials")
    subparsers.add_parser("status", help="Show the connected ChatGPT account")
    subparsers.add_parser("models", help="List models available to the connected ChatGPT account")
    args = parser.parse_args(argv)
    try:
        if args.command == "login":
            account = login()
            print("ChatGPT plan sign-in is ready.")
            if account.get("email"):
                print("Account:", account["email"])
            print("Run scans with --chatgpt-plan. Credentials are stored locally with owner-only file permissions.")
        elif args.command == "logout":
            logout()
            print("Removed local ChatGPT credentials.")
        elif args.command == "status":
            print(json.dumps(account_status(), indent=2))
        elif args.command == "models":
            for item in list_models():
                print(f"{item['slug']}\t{item['display_name']}")
        return 0
    except ChatGPTAuthError as exc:
        print(f"ChatGPT sign-in error: {exc}", file=sys.stderr)
        return 2
