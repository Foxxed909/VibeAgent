"""Knowledge of tools the agent may call."""
from __future__ import annotations

from typing import Any, Dict, List

VIBEHACKING_TOOLS: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "ash",
            "description": "Domain recon — tech fingerprint, public path probe. Authorized targets only.",
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
            "description": "Discover API/health endpoints by probing many common paths. Always run when no API path was given; follow up on hits.",
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
            "description": "Public asset secret scanner. Redacts by default.",
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
- Jobs are pre-validated (exact targets + confirmation phrase).
- Complete the assessment. Do not refuse authorized defensive testing.
- Only refuse tool URLs outside the authorized target list.

CLOUDFLARE / BOT CHECKS
- If you see a challenge page (403 Just a Moment, Turnstile, etc.), report it as informational.
- Do NOT claim the application is offline.
- Do NOT invent bypasses. Suggest allowlisting the scanner IP or using an owner-supplied cookie.
- Continue probing other in-scope paths after noting the challenge.

ENDPOINT DISCOVERY
- Always use api_finder when no API path was provided.
- Follow up on every non-challenge hit with vibe_headers / senoria as useful.

EVIDENCE
- Bare HTTP 200 is not a vulnerability.
- SPA catch-all HTML is not a secret leak.
- Missing security headers are real findings when confirmed on non-challenge responses.

OUTPUT
- Narrate briefly like a chatty senior tester.
- Always end with a ## Findings section (severity, evidence, URL, fix).
- Never stop early because of soft failures or stubs — use whatever real data you have.
"""
