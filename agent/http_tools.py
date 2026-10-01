"""Lightweight HTTP probes for Vercel (no VibeHacking checkout required)."""
from __future__ import annotations

import os
import re
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .cf_detect import challenge_advice, is_challenge_page

UA = "VibeAgent/0.2 (+authorized-scan)"

API_GUESS_PATHS = [
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2",
    "/api/health", "/api/v1/health", "/health", "/healthz", "/ready", "/readyz",
    "/status", "/api/status", "/ping", "/api/ping",
    "/graphql", "/api/graphql", "/graphiql",
    "/_next/data", "/.well-known/openid-configuration",
    "/swagger", "/swagger.json", "/openapi.json", "/api/openapi.json", "/api/docs", "/docs", "/redoc",
    "/v1", "/v2", "/rest", "/rpc",
    "/api/auth", "/api/login", "/api/user", "/api/users", "/api/me",
    "/api/config", "/api/version", "/version",
]

SCHEMA_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/docs/openapi.json",
)

PROTECTED_PATHS = (
    "/dashboard", "/billing", "/settings", "/admin", "/profile", "/account", "/api/admin",
)

ENV_PATHS = (
    "/.env", "/.env.local", "/api/config", "/api/debug", "/debug", "/server-status",
)

SECRET_MARKERS = (
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "JWT_SECRET",
    "BEGIN PRIVATE KEY",
)


def _extra_headers() -> Dict[str, str]:
    h: Dict[str, str] = {}
    cookie = os.environ.get("VIBEAGENT_COOKIE", "").strip()
    if cookie:
        h["Cookie"] = cookie
    return h


def _fetch(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 12,
) -> Tuple[int, str, Dict[str, str]]:
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


def _same_origin(base: str, candidate: str) -> bool:
    a = urlparse(base)
    b = urlparse(candidate)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


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
    for h in ("server", "x-powered-by", "x-vercel-cache", "x-vercel-id", "cf-ray", "via"):
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


def tool_cloud_scout(url: str) -> str:
    base = url.rstrip("/")
    status, body, headers = _fetch(base + "/")
    lines = [f"Target: {base}", f"HTTP status: {status}"]
    lines.extend(_maybe_challenge_note(base, status, body, headers))
    providers: List[str] = []
    if "cf-ray" in headers or "cf-cache-status" in headers or "cloudflare" in headers.get("server", "").lower():
        providers.append("Cloudflare")
    if "x-vercel-id" in headers or "x-vercel-cache" in headers or (urlparse(base).hostname or "").endswith(".vercel.app"):
        providers.append("Vercel")
    aws_markers = ("x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid", "x-amz-request-id")
    if any(h in headers for h in aws_markers) or "cloudfront" in headers.get("via", "").lower():
        providers.append("AWS")
    lines.append("Edge providers: " + (", ".join(sorted(set(providers))) if providers else "none confidently identified"))

    for path in ("/.well-known/security.txt", "/api/health", "/api/config"):
        st, content, hdrs = _fetch(base + path)
        if is_challenge_page(st, content, hdrs):
            lines.append(f"{path}: challenge")
            continue
        if st in (200, 401, 403):
            ct = hdrs.get("content-type", "")
            lines.append(f"{path}: {st} ct={ct[:40]} bytes={len(content)}")
    return "\n".join(lines)


def tool_spider(url: str, depth: int = 1) -> str:
    depth = max(1, min(int(depth or 1), 2))
    start = url.rstrip("/") + "/"
    queue: List[Tuple[str, int]] = [(start, 0)]
    seen = set()
    routes: List[str] = []
    forms: List[str] = []

    while queue and len(seen) < 20:
        current, level = queue.pop(0)
        if current in seen or level > depth:
            continue
        seen.add(current)
        st, body, headers = _fetch(current)
        if is_challenge_page(st, body, headers):
            continue
        routes.append(f"{st} {current}")
        ct = headers.get("content-type", "")
        if st != 200 or "html" not in ct.lower():
            continue

        for tag in re.findall(r"<form\b[^>]*>", body, re.IGNORECASE):
            action_m = re.search(r"action\s*=\s*[\"']([^\"']*)[\"']", tag, re.IGNORECASE)
            method_m = re.search(r"method\s*=\s*[\"']?([A-Za-z]+)", tag, re.IGNORECASE)
            action = urljoin(current, action_m.group(1) if action_m else current)
            if _same_origin(start, action):
                forms.append(f"{(method_m.group(1) if method_m else 'GET').upper()} {action}")

        for attr in ("href", "src"):
            pattern = attr + r"\s*=\s*[\"']([^\"'#]+)[\"']"
            for match in re.finditer(pattern, body, re.IGNORECASE):
                nxt = urljoin(current, match.group(1))
                if _same_origin(start, nxt) and nxt not in seen and level < depth:
                    queue.append((nxt, level + 1))

    lines = [f"Spider depth={depth}", f"Discovered {len(routes)} same-origin route(s)"]
    lines.extend("ROUTE " + r for r in routes[:20])
    lines.extend("FORM " + f for f in sorted(set(forms))[:10])
    return "\n".join(lines)


def tool_openapi_scout(url: str) -> str:
    base = url.rstrip("/")
    lines = [f"Schema scout: {base}"]
    schemas = 0
    for path in SCHEMA_PATHS:
        st, body, headers = _fetch(base + path)
        if is_challenge_page(st, body, headers) or st != 200 or not body:
            continue
        body_l = body.lstrip()
        if not body_l.startswith("{"):
            continue
        has_schema_marker = any(marker in body for marker in ('"openapi"', '"swagger"', '"paths"'))
        if not has_schema_marker:
            continue
        schemas += 1
        endpoint_count = len(re.findall(r'"\/(?:[^"\\]|\\.)*"\s*:', body))
        lines.append(f"SCHEMA {path}: exposed ({len(body)} bytes, ~{endpoint_count} path entries)")

    for path in ("/graphql", "/api/graphql"):
        st, body, headers = _fetch(base + path)
        if is_challenge_page(st, body, headers):
            continue
        if st in (200, 400, 405):
            lines.append(f"GRAPHQL candidate {path}: HTTP {st}")
    if not schemas:
        lines.append("No exposed OpenAPI/Swagger schema confirmed")
    return "\n".join(lines)


def tool_corscan(url: str) -> str:
    host = urlparse(url).hostname or "target.invalid"
    origins = ("https://evil.example", "null", f"https://{host}.evil.example")
    lines = [f"CORS audit: {url}"]
    for origin in origins:
        st, body, headers = _fetch(url, headers={"Origin": origin})
        if is_challenge_page(st, body, headers):
            lines.append(f"{origin}: challenge")
            continue
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()
        if not acao:
            lines.append(f"{origin}: no ACAO")
        elif acao == origin and acac == "true":
            lines.append(f"CRITICAL: reflected Origin with credentials=true ({origin})")
        elif acao == "*" and acac == "true":
            lines.append("CRITICAL: wildcard ACAO with credentials=true")
        elif acao in (origin, "*"):
            lines.append(f"POSSIBLE exposure: cross-origin reads allowed for {origin} (ACAO={acao!r})")
        else:
            lines.append(f"{origin}: constrained ACAO={acao!r}")
    return "\n".join(lines)


def tool_phantom(url: str) -> str:
    status, body, headers = _fetch(url)
    lines = [f"Session hygiene: {url}", f"HTTP status: {status}"]
    lines.extend(_maybe_challenge_note(url, status, body, headers))
    raw = headers.get("set-cookie", "")
    if raw:
        lower = raw.lower()
        name = raw.split("=", 1)[0].strip() or "(cookie)"
        issues = []
        if url.lower().startswith("https://") and "secure" not in lower:
            issues.append("Secure missing")
        if "httponly" not in lower:
            issues.append("HttpOnly missing")
        if "samesite" not in lower:
            issues.append("SameSite missing")
        if issues:
            lines.append(f"POSSIBLE exposure: cookie {name} missing " + ", ".join(issues))
        else:
            lines.append(f"Cookie {name}: Secure/HttpOnly/SameSite present")
    else:
        lines.append("No Set-Cookie header observed on this endpoint")

    jwt_like = re.findall(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", body or "")
    if jwt_like:
        lines.append(f"JWT-like token(s) present in response body: {min(len(jwt_like), 5)} (values redacted)")
    return "\n".join(lines)


def tool_leep(url: str) -> str:
    base = url.rstrip("/")
    lines = [f"Authorization boundary audit: {base}"]
    for path in PROTECTED_PATHS:
        st, body, headers = _fetch(base + path)
        if is_challenge_page(st, body, headers):
            continue
        text = (body or "").lower()
        if st == 200 and not any(x in text for x in ("login", "sign in", "unauthorized", "forbidden")):
            lines.append(f"POSSIBLE exposure: {path} returned 200 without an obvious login boundary")
        elif st in (401, 403):
            lines.append(f"{path}: protected ({st})")
        elif st == 404:
            continue
        else:
            lines.append(f"{path}: HTTP {st}")
    return "\n".join(lines)


def tool_env_probe(url: str) -> str:
    base = url.rstrip("/")
    lines = [f"Environment/config exposure audit: {base}"]
    hits = 0
    for path in ENV_PATHS:
        st, body, headers = _fetch(base + path)
        if is_challenge_page(st, body, headers) or st != 200 or not body:
            continue
        body_l = body.lower()
        if body_l.lstrip().startswith("<!doctype") or body_l.lstrip().startswith("<html"):
            continue
        found = [marker for marker in SECRET_MARKERS if marker.lower() in body_l]
        if found:
            hits += 1
            lines.append(f"POSSIBLE exposure: {path} contains sensitive configuration marker(s): {', '.join(found)} [values redacted]")
        elif path in ("/api/config", "/api/debug", "/debug", "/server-status"):
            lines.append(f"{path}: HTTP 200, non-HTML response ({len(body)} bytes); review manually")
    if hits == 0:
        lines.append("No high-confidence environment secret markers confirmed")
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
        ("sk-", "possible API key prefix"),
        ("api_key", "api_key string"),
        ("AWS_SECRET", "AWS secret marker"),
        ("BEGIN PRIVATE KEY", "private key block"),
    ]
    found = [label for needle, label in patterns if needle in body]
    if found:
        lines.append("Markers (values redacted; review manually): " + ", ".join(found))
    else:
        lines.append("No high-confidence secret markers in first body chunk")
    return "\n".join(lines)


BUILTIN = {
    "vibe_headers": tool_vibe_headers,
    "ash": tool_ash,
    "cloud_scout": tool_cloud_scout,
    "spider": tool_spider,
    "openapi_scout": tool_openapi_scout,
    "corscan": tool_corscan,
    "phantom": tool_phantom,
    "leep": tool_leep,
    "env_probe": tool_env_probe,
    "ghost": tool_ghost,
    "api_finder": tool_api_finder,
    "senoria": tool_senoria,
}


def run_builtin(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    fn = BUILTIN.get(name)
    if not fn:
        return {"stub": True, "message": f"No portable implementation for {name}"}
    url = args.get("url") or ""
    if not url:
        return {"error": "url required"}
    try:
        if name == "api_finder":
            out = fn(url, max_paths=int(args.get("max_paths") or 30))
        elif name == "spider":
            out = fn(url, depth=int(args.get("depth") or 1))
        else:
            out = fn(url)
        return {"returncode": 0, "stdout": out, "stderr": ""}
    except Exception as e:
        return {"returncode": 1, "stdout": "", "stderr": str(e)}
