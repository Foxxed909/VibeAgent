"""Canonical structured findings for VibeAgent and BreakAgent."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Optional
from urllib.parse import urlsplit


TOOL_META = {
    "vibe_headers": {
        "title": "Security response policy weakness",
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "remediation": "Set the missing security header with an application-appropriate policy and verify it on the affected route.",
    },
    "corscan": {
        "title": "CORS policy weakness",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "remediation": "Allow only trusted origins, avoid origin reflection, and never combine credentialed requests with an overly broad origin policy.",
    },
    "phantom": {
        "title": "Session or cookie policy weakness",
        "cwe": "CWE-614",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "remediation": "Harden session cookies with Secure, HttpOnly and an appropriate SameSite policy; avoid exposing bearer tokens in response bodies.",
    },
    "leep": {
        "title": "Potential authorization boundary weakness",
        "cwe": "CWE-862",
        "owasp": "A01:2021 - Broken Access Control",
        "remediation": "Enforce server-side authorization on every protected route and verify the result with an unauthenticated request.",
    },
    "env_probe": {
        "title": "Potential configuration exposure",
        "cwe": "CWE-200",
        "owasp": "A05:2021 - Security Misconfiguration",
        "remediation": "Remove public debug/config endpoints and prevent secrets or internal configuration from being returned to unauthenticated clients.",
    },
    "ghost": {
        "title": "Potential sensitive asset exposure",
        "cwe": "CWE-538",
        "owasp": "A05:2021 - Security Misconfiguration",
        "remediation": "Remove sensitive deployment artifacts from the public web root and deny access at both application and edge layers.",
    },
    "senoria": {
        "title": "Potential secret marker in public response",
        "cwe": "CWE-200",
        "owasp": "A02:2021 - Cryptographic Failures",
        "remediation": "Remove credentials from client-visible content, rotate any exposed secret, and use server-side secret storage.",
    },
    "openapi_scout": {
        "title": "Schema exposure requiring review",
        "cwe": "CWE-200",
        "owasp": "API9:2023 - Improper Inventory Management",
        "remediation": "Publish only intended API documentation and restrict internal schemas or developer consoles where appropriate.",
    },
    "api_finder": {
        "title": "API surface observation",
        "cwe": "CWE-200",
        "owasp": "API9:2023 - Improper Inventory Management",
        "remediation": "Review discovered endpoints for intended exposure and ensure authentication and authorization are enforced where required.",
    },
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _normalize_severity(tool: str, line: str) -> str:
    text = line.lower()
    if tool == "corscan" and "credentials=true" in text and ("reflected" in text or "wildcard" in text):
        return "high"
    if tool == "vibe_headers" and "missing:" in text:
        if "strict-transport-security" in text or "content-security-policy" in text:
            return "medium"
        return "low"
    if "critical" in text:
        return "high"
    if "possible exposure" in text:
        return "high" if tool in {"leep", "env_probe", "ghost", "senoria"} else "medium"
    return "info"


def _validation_status(tool: str, line: str) -> str:
    text = line.lower()
    if tool == "corscan" and "credentials=true" in text and ("reflected" in text or "wildcard" in text):
        return "confirmed"
    if tool == "vibe_headers" and "missing:" in text:
        return "observed"
    if "possible exposure" in text:
        return "unconfirmed"
    if "critical" in text:
        return "observed"
    return "informational"


def _title(tool: str, line: str) -> str:
    meta = TOOL_META.get(tool, {})
    base = meta.get("title") or f"{tool} finding"
    if tool == "vibe_headers":
        match = re.search(r"MISSING:\s*([^\s]+)", line, re.IGNORECASE)
        if match:
            return f"Missing security header: {match.group(1)}"
    if tool == "corscan" and "credentials=true" in line.lower():
        return "Credentialed CORS policy accepts an untrusted origin"
    return base


def finding_from_line(tool: str, line: str, *, url: Optional[str] = None) -> Dict[str, Any]:
    detail = (line or "").strip()
    meta = TOOL_META.get(tool, {})
    title = _title(tool, detail)
    severity = _normalize_severity(tool, detail)
    validation = _validation_status(tool, detail)
    fingerprint = f"{tool}|{url or ''}|{title}|{detail}"
    finding_id = "VA-" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:12].upper()
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "validation_status": validation,
        "tool": tool,
        "location": url or "",
        "evidence": detail,
        "recommendation": meta.get("remediation") or "Review the evidence and remediate the underlying security control.",
        "cwe": meta.get("cwe"),
        "owasp": meta.get("owasp"),
    }


def finding_from_worker(
    raw: Dict[str, Any],
    *,
    default_url: str = "",
    confirmed: bool = False,
    default_tool: str = "",
) -> Dict[str, Any]:
    tool = str(default_tool or raw.get("tool") or "native_worker").strip() or "native_worker"
    title = str(raw.get("title") or raw.get("summary") or f"{tool} finding").strip()
    evidence = str(raw.get("evidence") or raw.get("detail") or raw.get("summary") or title).strip()
    location = str(raw.get("location") or raw.get("url") or default_url).strip()
    if "://<host>" in location and default_url:
        try:
            base = default_url if "://" in default_url else "https://" + default_url
            parsed = urlsplit(base)
            suffix = location.split("://<host>", 1)[1]
            location = f"{parsed.scheme}://{parsed.netloc}{suffix}"
        except Exception:
            location = default_url
    severity = str(raw.get("severity") or ("high" if confirmed else "info")).lower()
    if severity not in SEVERITY_RANK:
        severity = "info"
    validation = str(raw.get("validation_status") or ("confirmed" if confirmed else "observed")).lower()
    recommendation = str(
        raw.get("recommendation")
        or TOOL_META.get(tool, {}).get("remediation")
        or "Review the evidence and remediate the underlying security control."
    )
    fingerprint = f"worker|{tool}|{location}|{title}|{evidence}"
    finding_id = "VA-" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:12].upper()
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "validation_status": validation,
        "tool": tool,
        "location": location,
        "evidence": evidence,
        "recommendation": recommendation,
        "cwe": raw.get("cwe"),
        "owasp": raw.get("owasp"),
        "source": "native-worker",
    }


def add_finding(report: Dict[str, Any], finding: Dict[str, Any]) -> bool:
    existing = {f.get("id") for f in report.setdefault("findings", [])}
    if finding.get("id") in existing:
        return False
    report["findings"].append(finding)
    return True


def severity_counts(report: Dict[str, Any]) -> Dict[str, int]:
    counts = {k: 0 for k in SEVERITY_RANK}
    for finding in report.get("findings") or []:
        sev = str(finding.get("severity") or "info").lower()
        counts[sev if sev in counts else "info"] += 1
    return counts
