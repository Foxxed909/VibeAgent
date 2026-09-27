"""Detect Cloudflare / bot-challenge pages — do NOT bypass.

Authorized testing of sites you own should use Cloudflare allowlists or a
browser-exported clearance cookie you control — not challenge evasion.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

CHALLENGE_MARKERS = (
    "just a moment",
    "attention required",
    "checking your browser",
    "cf-browser-verification",
    "cf-challenge",
    "challenge-platform",
    "_cf_chl",
    "turnstile",
    "enable javascript and cookies",
    "sorry, you have been blocked",
)


def is_challenge_page(status: int, body: str, headers: Optional[Dict[str, str]] = None) -> bool:
    headers = headers or {}
    server = (headers.get("server") or "").lower()
    cf = any(k.startswith("cf-") for k in headers) or "cloudflare" in server
    low = (body or "")[:8000].lower()
    if status in (403, 503) and any(m in low for m in CHALLENGE_MARKERS):
        return True
    if cf and status in (403, 503) and ("challenge" in low or "just a moment" in low):
        return True
    if "cf-mitigated" in headers or headers.get("cf-mitigated") == "challenge":
        return True
    return False


def challenge_advice(url: str) -> str:
    return (
        f"Bot / Cloudflare challenge detected for {url}. "
        "VibeAgent will not bypass robot checks. For assets you own: "
        "(1) Cloudflare Dashboard → Security → WAF → tools: allowlist the scanner IP, "
        "(2) temporarily lower Bot Fight Mode for a test window, or "
        "(3) paste a short-lived cf_clearance cookie you exported from YOUR browser session "
        "into the scan form (authorized use only). Continuing other in-scope paths."
    )


def classify_response(status: int, body: str, headers: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
    """Return (kind, note) where kind is ok|challenge|error."""
    if is_challenge_page(status, body, headers):
        return "challenge", "cloudflare_or_bot_challenge"
    if status == 0:
        return "error", "network_or_timeout"
    if status >= 500:
        return "error", f"http_{status}"
    return "ok", f"http_{status}"
