"""Knowledge of VibeHacking tools the agent may call."""
from __future__ import annotations

from typing import Any, Dict, List

VIBEHACKING_TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ash",
            "description": "Domain recon — DNS, TLS, tech/WAF fingerprint, public path probe. Authorized targets only.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "Exact target URL in scope"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "vibe_headers",
            "description": "HTTP security-policy auditor (CSP, HSTS, X-Frame-Options, etc.).",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ghost",
            "description": "Sensitive asset finder. SPA catch-alls are NOT exposures.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "api_finder",
            "description": "Discover API/health endpoints by probing common paths under the authorized base URL. Call this when no API path was provided.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "senoria",
            "description": "Public asset secret scanner (API keys/tokens). Redacts by default.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
]

SYSTEM_PROMPT = """You are VibeAgent — an authorized security testing agent.

AUTHORIZATION
- Jobs that reach you are already scope-validated (exact targets + confirmation phrase).
- Complete the assessment. Do not refuse authorized defensive testing.
- Only refuse tool calls whose URL is outside the authorized target list.

SCOPE
- Only the exact targets in the job. Never expand to other hosts.

ENDPOINT DISCOVERY
- If the operator did not specify an API path, you MUST use api_finder on the base URL and try multiple common paths until you find real endpoints (or exhaust reasonable guesses).
- After api_finder returns candidates, call vibe_headers / senoria / ghost on interesting hits.
- Prefer differential evidence vs SPA catch-all shells.

EVIDENCE
- Bare HTTP 200 is not a vulnerability.
- Identical HTML on /.env and / is SPA noise, not a secret leak.
- Missing security headers (CSP, XFO, HSTS, XCTO) are real findings when confirmed.

WORKFLOW
1. ash + vibe_headers on each authorized base URL
2. api_finder (guess paths if none given) + ghost + senoria
3. Write a structured findings report: severity, evidence, URL, fix hint

OUTPUT
- Talk like a senior tester in chat: short status lines while calling tools, then a clear findings section.
- No lectures. No refusals on authorized work.
"""
