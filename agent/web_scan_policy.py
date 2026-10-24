"""Private, non-persistent web scan policy.

Browser-only reporting allows a real, low-impact assessment without Redis only
when an operator has preapproved one exact HTTPS hostname and presented a
short-lived, host-bound signed proof. Never applies to the generic scan API.
"""
from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

from .scope import normalize_target
from .target_verification import is_operator_approved_proof


def browser_only_enabled() -> bool:
    return os.environ.get("VIBE_AGENT_BROWSER_ONLY_ENABLED", "").strip().lower() in {
        "1", "true", "yes"
    }


def check_browser_only_request(
    data: dict[str, Any],
    targets: list[str],
    proofs: dict[str, str],
    *,
    depth: str,
    stress_multiplier: Any,
) -> str | None:
    """Return the refusal reason, or None if this exact request is permitted."""
    if not browser_only_enabled():
        return "browser-only scanning is not enabled on this deployment"
    if len(targets) != 1:
        return "browser-only scanning requires one approved HTTPS hostname"
    target = normalize_target(targets[0])
    if not target:
        return "invalid target"
    try:
        parsed = urlsplit(target if "://" in target else "https://" + target)
        port = parsed.port
    except ValueError:
        return "invalid target URL"
    if (parsed.scheme.lower() != "https" or not parsed.hostname
            or port not in (None, 443) or parsed.username or parsed.password):
        return "browser-only scanning requires a standard HTTPS hostname"
    if not is_operator_approved_proof(target, proofs.get(target)):
        return "browser-only scanning requires a current operator approval for this exact hostname"
    if depth != "quick":
        return "browser-only scans are limited to Quick depth"
    if stress_multiplier:
        return "stress testing is disabled in browser-only mode"
    if data.get("cookie"):
        return "browser-only scans do not accept browser session cookies"
    if data.get("execution_backend", "portable") != "portable":
        return "browser-only scanning uses the bounded portable tools"
    if data.get("dry_run"):
        return "browser-only reporting is intended for real checks, not dry-runs"
    return None
