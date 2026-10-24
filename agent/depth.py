"""Scan depth profiles — thoroughness without unbounded load."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class DepthProfile:
    name: str
    max_rounds: int
    tool_timeout_s: int
    tool_retries: int
    force_api_finder: bool
    follow_up_on_hits: bool
    require_final_report: bool
    max_paths_per_tool: int
    max_tool_calls: int
    max_retests: int
    stagnant_round_limit: int
    model_retries: int


DEPTHS: Dict[str, DepthProfile] = {
    "quick": DepthProfile(
        name="quick",
        max_rounds=4,
        tool_timeout_s=10,
        tool_retries=1,
        force_api_finder=True,
        follow_up_on_hits=False,
        require_final_report=True,
        max_paths_per_tool=12,
        max_tool_calls=18,
        max_retests=2,
        stagnant_round_limit=1,
        model_retries=1,
    ),
    "standard": DepthProfile(
        name="standard",
        max_rounds=12,
        tool_timeout_s=15,
        tool_retries=2,
        force_api_finder=True,
        follow_up_on_hits=True,
        require_final_report=True,
        max_paths_per_tool=30,
        max_tool_calls=42,
        max_retests=5,
        stagnant_round_limit=2,
        model_retries=2,
    ),
    "deep": DepthProfile(
        name="deep",
        max_rounds=15,
        tool_timeout_s=20,
        tool_retries=3,
        force_api_finder=True,
        follow_up_on_hits=True,
        require_final_report=True,
        max_paths_per_tool=50,
        max_tool_calls=70,
        max_retests=8,
        stagnant_round_limit=3,
        model_retries=3,
    ),
}

DEFAULT_DEPTH = "standard"


def get_depth(name: str | None) -> DepthProfile:
    key = (name or DEFAULT_DEPTH).strip().lower()
    return DEPTHS.get(key, DEPTHS[DEFAULT_DEPTH])
