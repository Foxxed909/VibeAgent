"""Tool catalog exposed to the VibeAgent reasoning loop.

The standalone app has two execution modes:
- portable/serverless tools implemented in agent.http_tools
- native VibeHacking tools when VIBEHACKING_ROOT points at a checkout

The catalog intentionally tracks the VibeAgent (recon/audit) toolset, not the
separate BreakAgent pipeline.
"""
from __future__ import annotations

from typing import Any, Dict, List


def _tool(name: str, description: str, properties: Dict[str, Any] | None = None) -> Dict[str, Any]:
    props: Dict[str, Any] = {"url": {"type": "string"}}
    if properties:
        props.update(properties)
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": props,
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    }


ALL_VIBEHACKING_TOOLS: List[Dict[str, Any]] = [
    _tool(
        "cloud_scout",
        "Fingerprint Cloudflare, Vercel, AWS and common cloud-edge behavior on an authorized target.",
    ),
    _tool(
        "ash",
        "Domain and perimeter recon: technology fingerprinting, server headers and public resources.",
    ),
    _tool(
        "spider",
        "Same-origin attack-surface crawler. Enumerates routes, assets and forms without leaving the authorized host.",
        {"depth": {"type": "integer", "minimum": 1, "maximum": 2}},
    ),
    _tool(
        "openapi_scout",
        "Discover exposed OpenAPI/Swagger schemas and likely GraphQL endpoints; map documented API routes.",
    ),
    _tool(
        "vibe_headers",
        "HTTP security-policy auditor for CSP, HSTS, framing, MIME-sniffing and related response headers.",
    ),
    _tool(
        "corscan",
        "CORS policy auditor using untrusted Origin values to detect reflection, wildcards and credentialed cross-origin access.",
    ),
    _tool(
        "phantom",
        "Cookie/session-token hygiene auditor: Secure, HttpOnly, SameSite and JWT-like token exposure indicators.",
    ),
    _tool(
        "leep",
        "Authorization-boundary auditor for common dashboard, admin, billing, settings, profile and account routes.",
    ),
    _tool(
        "env_probe",
        "Configuration and environment-exposure auditor for common debug/config paths. Evidence is redacted.",
    ),
    _tool(
        "ghost",
        "Sensitive asset finder. SPA catch-all HTML is calibrated and must not be treated as an exposure.",
    ),
    _tool(
        "api_finder",
        "Discover API/health/auth/schema endpoints from a bounded common-path list and follow up on confirmed hits.",
    ),
    _tool(
        "senoria",
        "Public asset secret scanner. Reports secret markers without returning raw credentials.",
    ),
    _tool(
        "bot_breaker",
        "Native VibeHacking perimeter challenge diagnostic for owner-authorized targets. Requires the full VibeHacking runtime.",
    ),
    _tool(
        "poc_gen",
        "Generate a benign local verification PoC for a confirmed finding. Requires the full VibeHacking runtime.",
        {"type": {"type": "string", "enum": ["xss", "csrf", "cors", "clickjacking"]}},
    ),
]

PORTABLE_TOOL_NAMES = {
    "cloud_scout",
    "ash",
    "spider",
    "openapi_scout",
    "vibe_headers",
    "corscan",
    "phantom",
    "leep",
    "env_probe",
    "ghost",
    "api_finder",
    "senoria",
}

NATIVE_ONLY_TOOL_NAMES = {"bot_breaker", "poc_gen"}


def get_tool_catalog(*, native: bool = False) -> List[Dict[str, Any]]:
    """Return only tools that the current runtime can actually execute."""
    if native:
        return list(ALL_VIBEHACKING_TOOLS)
    return [
        tool
        for tool in ALL_VIBEHACKING_TOOLS
        if tool["function"]["name"] in PORTABLE_TOOL_NAMES
    ]


# Backwards-compatible name for callers that want the complete VibeAgent surface.
VIBEHACKING_TOOLS = ALL_VIBEHACKING_TOOLS


SYSTEM_PROMPT = """You are VibeAgent — an autonomous agent for authorized defensive security testing.

AUTHORIZATION
- Jobs are pre-validated against the user's declared target scope.
- Only call tools that are present in the provided tool catalog.
- Never request or probe a URL outside the authorized target list.

METHOD
- Start with perimeter/cloud context and surface discovery.
- Prefer evidence-producing tools over speculation.
- Use spider/api_finder/openapi_scout to expand the known surface, then choose targeted follow-up tools.
- Continue after soft failures; do not repeat the same probe without a reason.

BOT / CDN CHALLENGES
- Treat challenge/interstitial responses as informational, not as proof the app is offline or vulnerable.
- On the portable runtime, do not invent challenge bypasses. Continue with other in-scope routes.
- Native VibeHacking-only tools may appear when the deployment explicitly has that runtime available.

EVIDENCE
- HTTP 200 alone is not a vulnerability.
- SPA catch-all HTML is not a secret leak.
- Redact credentials and tokens from output.
- Distinguish confirmed findings from possible exposures that require manual verification.

OUTPUT
- Narrate briefly like a senior application-security tester.
- Always end with a ## Findings section containing severity, evidence, affected URL and fix guidance.
"""
