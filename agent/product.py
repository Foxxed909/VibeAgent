"""Product surface rules: what each tier may run."""
from __future__ import annotations

from typing import Optional, Tuple

from .scope import is_valid_trial_code

HOBBY_DEPTHS = {"quick", "standard"}
ALL_DEPTHS = {"quick", "standard", "deep"}


def resolve_depth(tier: str, depth: Optional[str], access_code: Optional[str]) -> str:
    d = (depth or "standard").strip().lower()
    trial = is_valid_trial_code(access_code)
    # Trial code may use deep; plain hobby cannot
    if tier == "hobby" and not trial:
        if d not in HOBBY_DEPTHS:
            return "standard"
        return d
    if d not in ALL_DEPTHS:
        return "standard"
    return d


def resolve_stress(
    tier: str,
    access_code: Optional[str],
    multiplier: Optional[int],
    stress_mode: Optional[str],
) -> Tuple[Optional[int], str]:
    """Returns (multiplier_or_None, mode capped|org)."""
    if not multiplier:
        return None, "capped"
    trial = is_valid_trial_code(access_code)
    enterprise = (tier or "").lower() == "enterprise"

    if not (trial or enterprise):
        # Hobby without code: no stress
        return None, "capped"

    mode = (stress_mode or "capped").strip().lower()
    if mode == "org" and not enterprise:
        # Only full enterprise may pick org-managed limits (not trial hobby)
        mode = "capped"

    if mode == "org":
        allowed = {5, 10, 20, 50}
    else:
        allowed = {5, 10, 20}

    m = int(multiplier)
    if m not in allowed:
        # clamp to nearest allowed or drop
        if mode == "org" and m > 20:
            m = 50 if m >= 50 else 20
        elif m > 20:
            m = 20
        elif m not in allowed:
            m = 5
    return m, mode
