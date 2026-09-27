"""Lightweight HTTP probes for Vercel (no VibeHacking install required)."""
from __future__ import annotations

import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .cf_detect import challenge_advice, is_challenge_page

UA = "VibeAgent/0.1 (+authorized-scan)"

API_GUESS_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2",
    "/api/health", "/api/v1/health", "/health", "/healthz", "/ready", "/readyz",
    "/status", "/api/status", "/ping", "/api/ping",
    "/graphql", "/api/graphql", "/graphiql",
    "/_next/data", "/.well-known/openid-configuration",
    "/swagger", "/swagger.json", "/openapi.json", "/api/docs", "/docs", "/redoc",
    "/v1", "/v2", "/rest", "/rpc",
    "/api/auth", "/api/login", "/api/user", "/api/users", "/api/me",
    "/api/config", "/api/version", "/version",
]


def _extra_headers() -> Dict[str, str]:
    h: Dict[str, str] = {}
    cookie = os.environ.get("VIBEAGENT_COOKIE", "").strip()
    if cookie:
        h["Cookie"] = cookie
    return h


def _fetch(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, timeout: int = 12) -> Tuple[int, str, Dict[str, str]]:
    req_headers = {"User-Agent": UA, "Accept": "*/*"}
    req_headers.update(_extra_headers())
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, method=method, headers=req_headers)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(200_000).decode("utf-8", errors="replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.getcode() or 0, body, hdrs
    except urllib.error.HTTPError as e:
        body = e.read(100_000).decode("utf-8", errors="replace") if e.fp else ""
        hdrs = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return e.code or 0, body, hdrs
    except Exception as e:
        return 0, str(e), {}


def _maybe_challenge_note(url: str, status: int, body: str, headers: Dict[str, str]) -> List[str]:
    if is_challenge_page(status, body, headers):
        return ["[CHALLENGE] " + challenge_advice(url)]
    return []


def tool_vibe_headers(url: str) -> str:
    status, body, headers = _fetch(url)
    lines = [f"URL: {url}", f"HTTP status: {status}"]
    lines.extend(_maybe_challenge_note(url, status, body, headers))
    interesting = [
        "server", "x-powered-by", "x-frame-options", "content-security-policy",
        "strict-transport-security", "x-content-type-options", "referrer-policy",
        "permissions-policy", "access-control-allow-origin", "x-vercel-id", "cf-ray",
    ]
    for h in interesting:
        if h in headers:
            lines.append(f"{h}: {headers[h]}")
        elif h in ("content-security-policy", "x-frame-options", "strict-transport-security", "x-content-type-options"):
            if not is_challenge_page(status, body, headers):
                lines.append(f"MISSING: {h}  [CRITICAL]")
    return "\n".join(lines)


def tool_ash(url: str) -> str:
    parsed = urlparse(url)
    lines = [f"Target: {url}", f"Host: {parsed.hostname}", f"Scheme: {parsed.scheme}"]
    status, body, headers = _fetch(url)
    lines.append(f"HTTP status: {status}")
    lines.extend(_maybe_challenge_note(url, status, body, headers))
    for h in ("server", "x-powered-by", "x-vercel-cache", "x-vercel-id", "cf-ray"):
        if h in headers:
            lines.append(f"{h}: {headers[h]}")
    if is_challenge_page(status, body, headers):
        return "\n".join(lines)
    base = url.rstrip("/")
    for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
        st, content, hdrs = _fetch(f"{base}/{path}")
        if is_challenge_page(st, content, hdrs):
            lines.append(f"{path}: challenge page")
            continue
        if st == 200 and content and "<!doctype html" not in content[:80].lower():
            lines.append(f"FOUND {path} ({len(content)} bytes)")
        elif st in (401, 403):
            lines.append(f"{path}: {st}")
    return "\n".join(lines)


def tool_ghost(url: str) -> str:
    base = url.rstrip("/")
    root_st, root_body, root_h = _fetch(base + "/")
    lines = [f"Root status: {root_st}"]
    lines.extend(_maybe_challenge_note(base + "/", root_st, root_body, root_h))
    if is_challenge_page(root_st, root_body, root_h):
        lines.append("Root is behind bot protection — sensitive-path checks deferred")
        return "\n".join(lines)
    ctrl_st, ctrl_body, _ = _fetch(base + "/__vibe_baseline_control_9f3a2c1e__")
    lines.append(f"Control status: {ctrl_st}")
    spa = False
    if root_body and ctrl_body and root_body[:200] == ctrl_body[:200] and "<!doctype html" in root_body[:200].lower():
        spa = True
        lines.append("SPA catch-all baseline active — ignoring shell clones")
    hits = 0
    for p in (".env", ".git/HEAD", "config.json", "wp-config.php", "backup.sql"):
        st, body, hdrs = _fetch(f"{base}/{p}")
        if is_challenge_page(st, body, hdrs):
            continue
        if st != 200 or not body:
            continue
        if spa and body[:200] == (root_body or "")[:200]:
            continue
        if "<!doctype html" in body[:80].lower() or "<html" in body[:80].lower():
            continue
        hits += 1
        lines.append(f"POSSIBLE exposure: /{p} status={st} bytes={len(body)}")
    if hits == 0:
        lines.append("No sensitive file exposures detected (evidence-based)")
    return "\n".join(lines)


def tool_api_finder(url: str, max_paths: int = 30) -> str:
    base = url.rstrip("/")
    root_st, root_body, root_h = _fetch(base + "/")
    lines = [f"Base: {base}", f"Probing up to {max_paths} common API paths…"]
    lines.extend(_maybe_challenge_note(base + "/", root_st, root_body, root_h))
    hits: List[str] = []
    for path in API_GUESS_PATHS[:max_paths]:
        target = urljoin(base + "/", path.lstrip("/"))
        if path.endswith("/") and not target.endswith("/"):
            target += "/"
        st, body, headers = _fetch(target)
        if st == 0:
            continue
        if is_challenge_page(st, body, headers):
            hits.append(f"{path} → CHALLENGE status={st}")
            continue
        ct = headers.get("content-type", "")
        if root_body and body and body[:120] == root_body[:120] and "text/html" in ct:
            continue
        interesting = (
            "json" in ct
            or st in (401, 403, 405, 301, 302)
            or (
                st == 200
                and body
                and not body.lstrip().lower().startswith("<!doctype")
                and not body.lstrip().lower().startswith("<html")
            )
        )
        if interesting:
            preview = (body or "").replace("\n", " ")[:80]
            hits.append(f"{path} → {st} ct={ct[:32]} preview={preview!r}")
    if hits:
        lines.append(f"Found {len(hits)} candidate(s) — follow up on non-challenge hits:")
        lines.extend(hits)
    else:
        lines.append("No non-SPA API endpoints confirmed from common path list")
    return "\n".join(lines)


def tool_senoria(url: str) -> str:
    status, body, headers = _fetch(url)
    lines = [f"Status: {status}", f"Body bytes: {len(body)}"]
    lines.extend(_maybe_challenge_note(url, status, body, headers))
    if is_challenge_page(status, body, headers):
        return "\n".join(lines)
    patterns = [
        ("sk-", "possible OpenAI-like key prefix"),
        ("api_key", "api_key string"),
        ("AWS_SECRET", "AWS secret marker"),
        ("BEGIN PRIVATE KEY", "private key block"),
    ]
    found = [label for needle, label in patterns if needle in body]
    if found:
        lines.append("Markers (review manually): " + ", ".join(found))
    else:
        lines.append("No high-confidence secret markers in first body chunk")
    return "\n".join(lines)


BUILTIN = {
    "vibe_headers": tool_vibe_headers,
    "ash": tool_ash,
    "ghost": tool_ghost,
    "api_finder": tool_api_finder,
    "senoria": tool_senoria,
}


def run_builtin(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    fn = BUILTIN.get(name)
    if not fn:
        return {"stub": True, "message": f"No builtin for {name}"}
    url = args.get("url") or ""
    if not url:
        return {"error": "url required"}
    try:
        if name == "api_finder":
            out = fn(url, max_paths=int(args.get("max_paths") or 30))
        else:
            out = fn(url)
        return {"returncode": 0, "stdout": out, "stderr": ""}
    except Exception as e:
        return {"returncode": 1, "stdout": "", "stderr": str(e)}
