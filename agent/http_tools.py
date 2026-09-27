"""Lightweight HTTP probes that run on Vercel without VibeHacking installed.

Used when VIBEHACKING_ROOT is unset so agents still produce real evidence.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin, urlparse

UA = "VibeAgent/0.1 (+authorized-scan)"


def _fetch(url: str, method: str = "GET", headers: Dict[str, str] | None = None, timeout: int = 12) -> Tuple[int, str, Dict[str, str]]:
    req_headers = {"User-Agent": UA, "Accept": "*/*"}
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


def tool_vibe_headers(url: str) -> str:
    status, body, headers = _fetch(url)
    lines = [f"URL: {url}", f"HTTP status: {status}"]
    interesting = [
        "server", "x-powered-by", "x-frame-options", "content-security-policy",
        "strict-transport-security", "x-content-type-options", "referrer-policy",
        "permissions-policy", "access-control-allow-origin", "x-vercel-id",
    ]
    for h in interesting:
        if h in headers:
            lines.append(f"{h}: {headers[h]}")
        else:
            if h in ("content-security-policy", "x-frame-options", "strict-transport-security", "x-content-type-options"):
                lines.append(f"MISSING: {h}  [CRITICAL]")
    return "\n".join(lines)


def tool_ash(url: str) -> str:
    parsed = urlparse(url)
    lines = [f"Target: {url}", f"Host: {parsed.hostname}", f"Scheme: {parsed.scheme}"]
    status, body, headers = _fetch(url)
    lines.append(f"HTTP status: {status}")
    for h in ("server", "x-powered-by", "x-vercel-cache", "x-vercel-id"):
        if h in headers:
            lines.append(f"{h}: {headers[h]}")
    # lightweight path probe
    base = url.rstrip("/")
    for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
        st, content, _ = _fetch(f"{base}/{path}")
        if st == 200 and content and "<!doctype html" not in content[:80].lower():
            lines.append(f"FOUND {path} ({len(content)} bytes)")
        elif st in (401, 403):
            lines.append(f"{path}: {st}")
    return "\n".join(lines)


def tool_ghost(url: str) -> str:
    base = url.rstrip("/")
    root_st, root_body, _ = _fetch(base + "/")
    ctrl_st, ctrl_body, _ = _fetch(base + "/__vibe_baseline_control_9f3a2c1e__")
    lines = [f"Root status: {root_st}", f"Control status: {ctrl_st}"]
    spa = False
    if root_body and ctrl_body:
        r = " ".join(root_body.split())[:500]
        c = " ".join(ctrl_body.split())[:500]
        if r == c or ("<!doctype html" in root_body[:200].lower() and root_body[:200] == ctrl_body[:200]):
            spa = True
            lines.append("SPA catch-all baseline active — ignoring shell clones")
    paths = [".env", ".git/HEAD", "config.json", "wp-config.php", "backup.sql"]
    hits = 0
    for p in paths:
        st, body, _ = _fetch(f"{base}/{p}")
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


def tool_api_finder(url: str) -> str:
    base = url.rstrip("/")
    root_st, root_body, _ = _fetch(base + "/")
    lines = [f"Base: {base}"]
    candidates = ["/api", "/api/v1", "/api/health", "/health", "/graphql", "/_next/data"]
    for path in candidates:
        st, body, headers = _fetch(urljoin(base + "/", path.lstrip("/")))
        ct = headers.get("content-type", "")
        if st == 0:
            continue
        # skip SPA clone
        if root_body and body and body[:150] == root_body[:150] and "text/html" in ct:
            continue
        if "json" in ct or st in (401, 403) or (st == 200 and body and not body.lstrip().startswith("<!")):
            lines.append(f"{path} → {st} content-type={ct[:40]}")
    if len(lines) == 1:
        lines.append("No obvious API endpoints confirmed")
    return "\n".join(lines)


def tool_senoria(url: str) -> str:
    status, body, _ = _fetch(url)
    lines = [f"Status: {status}", f"Body bytes: {len(body)}"]
    patterns = [
        ("sk-", "possible OpenAI-like key prefix"),
        ("api_key", "api_key string"),
        ("AWS_SECRET", "AWS secret marker"),
        ("BEGIN PRIVATE KEY", "private key block"),
    ]
    found = []
    low = body
    for needle, label in patterns:
        if needle in low:
            found.append(label)
    if found:
        lines.append("Markers (review manually): " + ", ".join(found))
    else:
        lines.append("No high-confidence secret markers in first body chunk")
    return "\n".join(lines)


BUILTIN: Dict[str, Any] = {
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
        out = fn(url)
        return {"returncode": 0, "stdout": out, "stderr": ""}
    except Exception as e:
        return {"returncode": 1, "stdout": "", "stderr": str(e)}
