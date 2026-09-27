"""Exact-target scope enforcement.

Hobby: exact URLs/hosts + *.vercel.app only.
Enterprise: exact hosts, URLs, IP/CIDR ranges.

Trial access code unlocks Hobby scans without payment (friends + owner).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

CONFIRM_PHRASE = "I OWN OR AM AUTHORIZED TO TEST THESE TARGETS"

# Trial / friend access code — grants Hobby tier without payment.
# Keep in sync with scan.html
TRIAL_ACCESS_CODE = "9954FA-67£54CD-GROKJAILEDBROKE£D"


@dataclass
class Authorization:
    tier: str  # "hobby" | "enterprise"
    targets: List[str]
    confirmation: str
    app_name: Optional[str] = None
    company_name: Optional[str] = None
    contact_email: Optional[str] = None
    emergency_contact: Optional[str] = None
    note: Optional[str] = None
    time_window: Optional[str] = None
    access_code: Optional[str] = None  # trial code

    def validated(self) -> "Authorization":
        if self.confirmation.strip() != CONFIRM_PHRASE:
            raise ScopeError("Confirmation phrase mismatch. Scan refused.")
        if not self.targets:
            raise ScopeError("At least one exact target is required.")

        trial = is_valid_trial_code(self.access_code)
        if trial:
            # Trial always runs as Hobby scope rules
            self.tier = "hobby"

        normalized = []
        for raw in self.targets:
            t = normalize_target(raw)
            if not t:
                raise ScopeError(f"Invalid or empty target: {raw!r}")
            if self.tier == "hobby":
                if not is_hobby_allowed(t):
                    raise ScopeError(
                        f"Hobby tier only allows exact URLs/hosts and *.vercel.app. Rejected: {raw}"
                    )
            normalized.append(t)
        self.targets = normalized

        if self.tier == "hobby" and not self.app_name:
            raise ScopeError("Hobby tier requires app_name.")
        if self.tier == "enterprise" and not trial and not self.company_name:
            raise ScopeError("Enterprise tier requires company_name.")
        return self


class ScopeError(ValueError):
    pass


def is_valid_trial_code(code: Optional[str]) -> bool:
    if not code:
        return False
    return code.strip() == TRIAL_ACCESS_CODE


def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw or raw.startswith("#"):
        return ""
    if "*" in raw and not raw.endswith(".vercel.app") and raw != "*.vercel.app":
        return ""
    if raw.startswith("*.") and not raw.endswith(".vercel.app"):
        return ""
    return raw.rstrip("/")


def is_hobby_allowed(target: str) -> bool:
    """Exact host/URL or *.vercel.app / something.vercel.app."""
    t = target.lower()
    if t == "*.vercel.app":
        return True
    if t.endswith(".vercel.app") and "*" not in t:
        return True
    if "*" in t or "?" in t:
        return False
    if "://" in t:
        try:
            p = urlparse(t)
            return bool(p.hostname)
        except Exception:
            return False
    if re.match(r"^[a-z0-9.-]+$", t) and "." in t:
        return True
    if t in ("localhost", "127.0.0.1", "::1") or t.startswith("127.0.0.1:"):
        return True
    return False


def host_in_scope(host: str, auth: Authorization) -> bool:
    host = (host or "").lower().strip()
    if not host:
        return False
    for target in auth.targets:
        t = target.lower()
        if t == "*.vercel.app":
            if host.endswith(".vercel.app") or host == "vercel.app":
                return True
            continue
        if "://" in t:
            try:
                th = urlparse(t).hostname or ""
            except Exception:
                th = ""
        else:
            th = t.split("/")[0].split(":")[0]
        if host == th or host.endswith("." + th):
            return True
        if auth.tier == "enterprise" and "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
                ip = ipaddress.ip_address(host)
                if ip in net:
                    return True
            except ValueError:
                pass
    return False


def assert_url_in_scope(url: str, auth: Authorization) -> None:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    if not host_in_scope(host, auth):
        raise ScopeError(f"URL out of scope: {url}")
