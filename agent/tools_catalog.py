"""Agent-specific tool catalogs and prompts for standalone VibeAgent."""
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
    _tool("cloud_scout", "Fingerprint Cloudflare, Vercel, AWS and common cloud-edge behavior on an authorized target."),
    _tool("ash", "Domain and perimeter recon: technology fingerprinting, server headers and public resources."),
    _tool(
        "spider",
        "Same-origin attack-surface crawler. Enumerates routes, assets and forms without leaving the authorized host.",
        {"depth": {"type": "integer", "minimum": 1, "maximum": 2}},
    ),
    _tool("openapi_scout", "Discover exposed OpenAPI/Swagger schemas and likely GraphQL endpoints; map documented API routes."),
    _tool("vibe_headers", "HTTP security-policy auditor for CSP, HSTS, framing, MIME-sniffing and related response headers."),
    _tool("corscan", "CORS policy auditor using untrusted Origin values to detect reflection, wildcards and credentialed cross-origin access."),
    _tool("phantom", "Cookie/session-token hygiene auditor: Secure, HttpOnly, SameSite and JWT-like token exposure indicators."),
    _tool("leep", "Authorization-boundary auditor for common dashboard, admin, billing, settings, profile and account routes."),
    _tool("env_probe", "Configuration and environment-exposure auditor for common debug/config paths. Evidence is redacted."),
    _tool("ghost", "Sensitive asset finder. SPA catch-all HTML is calibrated and must not be treated as an exposure."),
    _tool("api_finder", "Discover API/health/auth/schema endpoints from a bounded common-path list and follow up on confirmed hits."),
    _tool("senoria", "Public asset secret scanner. Reports secret markers without returning raw credentials."),
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
    "cloud_scout", "ash", "spider", "openapi_scout", "vibe_headers", "corscan",
    "phantom", "leep", "env_probe", "ghost", "api_finder", "senoria",
}

VIBE_NATIVE_EXTRA = {"bot_breaker", "poc_gen"}

# BreakAgent is deliberately validation-focused. It can confirm control behavior,
# exposure signals, session policy and authorization boundaries, but it does not
# get challenge-bypass tooling by default.
BREAK_PORTABLE_TOOL_NAMES = {
    "cloud_scout", "openapi_scout", "vibe_headers", "corscan", "phantom",
    "leep", "env_probe", "ghost", "api_finder", "senoria",
}
BREAK_NATIVE_EXTRA = {"poc_gen"}


def normalize_agent_mode(value: str | None) -> str:
    mode = (value or "vibe").strip().lower().replace("_", "-")
    if mode in {"break", "breakagent", "break-agent"}:
        return "break"
    return "vibe"


def agent_name(agent_mode: str | None) -> str:
    return "BreakAgent" if normalize_agent_mode(agent_mode) == "break" else "VibeAgent"


def get_tool_catalog(*, native: bool = False, agent_mode: str = "vibe") -> List[Dict[str, Any]]:
    """Return only tools that this agent mode and runtime can actually execute."""
    mode = normalize_agent_mode(agent_mode)
    allowed = set(BREAK_PORTABLE_TOOL_NAMES if mode == "break" else PORTABLE_TOOL_NAMES)
    if native:
        allowed.update(BREAK_NATIVE_EXTRA if mode == "break" else VIBE_NATIVE_EXTRA)
    return [tool for tool in ALL_VIBEHACKING_TOOLS if tool["function"]["name"] in allowed]


def get_forced_tools(agent_mode: str, *, force_api_finder: bool) -> List[str]:
    mode = normalize_agent_mode(agent_mode)
    if mode == "break":
        tools = ["vibe_headers", "corscan", "phantom", "leep", "env_probe"]
        if force_api_finder:
            tools.insert(1, "api_finder")
        return tools

    tools = ["cloud_scout", "ash", "vibe_headers"]
    if force_api_finder:
        tools.append("api_finder")
    tools.extend(["openapi_scout", "ghost", "senoria"])
    return tools


VIBEAGENT_PROMPT = """You are VibeAgent — an autonomous agent for authorized defensive security testing.

AUTHORIZATION
- Jobs are pre-validated against the user's declared target scope.
- Only call tools present in the provided tool catalog.
- Never request or probe a URL outside the authorized target list.

METHOD
- Start with perimeter/cloud context and surface discovery.
- Prefer evidence-producing tools over speculation.
- Use spider/api_finder/openapi_scout to expand the known surface, then choose targeted follow-up tools.
- Continue after soft failures; do not repeat the same probe without a reason.

BOT / CDN CHALLENGES
- Treat challenge/interstitial responses as informational, not as proof the app is offline or vulnerable.
- On the portable runtime, do not invent challenge bypasses. Continue with other in-scope routes.

EVIDENCE
- HTTP 200 alone is not a vulnerability.
- SPA catch-all HTML is not a secret leak.
- Redact credentials and tokens from output.
- Distinguish confirmed findings from possible exposures that require manual verification.

OUTPUT
- Narrate briefly like a senior application-security tester.
- Always end with a ## Findings section containing severity, evidence, affected URL and fix guidance.
"""


BREAKAGENT_PROMPT = """You are BreakAgent — a validation-focused agent for authorized defensive security testing.

ROLE
- Work only inside the already-authorized target scope.
- Your job is to validate whether suspected weaknesses are real, reproducible and security-relevant.
- Do not expand scope, invent bypasses, or escalate beyond the tools exposed to you.

METHOD
- Prefer targeted confirmation over broad discovery.
- Re-check security headers, CORS, session/cookie policy, authorization boundaries, exposed config/schema surfaces and secret markers.
- Use API discovery only to locate in-scope endpoints worth validating.
- If a benign verification PoC tool is available, use it only when existing evidence supports that finding type.
- Never treat a status code alone as proof of a vulnerability.

SAFETY / EVIDENCE
- Do not attempt credential theft, destructive actions, persistence, denial of service or challenge bypass.
- Redact credentials and tokens.
- Label ambiguous results as unconfirmed and explain what manual verification remains.
- Preserve enough evidence for the owner to reproduce the result safely.

OUTPUT
- Be concise and evidence-led.
- Always end with ## Findings.
- For each finding include: validation status (confirmed/unconfirmed), severity, affected URL, evidence and fix guidance.
"""


def get_system_prompt(agent_mode: str) -> str:
    return BREAKAGENT_PROMPT if normalize_agent_mode(agent_mode) == "break" else VIBEAGENT_PROMPT


# Backwards compatibility for older callers.
SYSTEM_PROMPT = VIBEAGENT_PROMPT
VIBEHACKING_TOOLS = ALL_VIBEHACKING_TOOLS
