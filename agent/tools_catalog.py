"""Knowledge of VibeHacking tools the agent may call.

These are descriptions only — actual execution is gated by scope.py and
the runner. The agent must never invent tools outside this catalog.
"""
from __future__ import annotations

from typing import Any, Dict, List

# High-level tool surface the orchestrator can expose to the model.
# Names match VibeHacking TOOLS/ where possible.
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
            "description": "Sensitive asset finder. Requires content evidence, not just HTTP 200.",
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
            "description": "Hidden endpoint discovery with baseline control.",
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
            "name": "leep",
            "description": "Logic-flow / auth-bypass auditor with baseline.",
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
            "name": "axios",
            "description": "IDOR / object-ID exposure scanner with baseline.",
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
            "name": "ssrf_probe",
            "description": "SSRF probe — requires evidence of server-side fetch.",
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
            "name": "traversal_sniper",
            "description": "Path traversal / LFI — requires real file content evidence.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "app_root": {"type": "string", "description": "Optional leaked absolute root"},
                },
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
    {
        "type": "function",
        "function": {
            "name": "noloader",
            "description": "Availability / health monitor. Serial probes only, never floods.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "health": {"type": "boolean"},
                    "duration": {"type": "string", "description": "e.g. 30s, 2min"},
                },
                "required": ["url"],
            },
        },
    },
]

SYSTEM_PROMPT = """You are VibeAgent, an authorized security testing agent.

SCOPE RULES (non-negotiable)
- You may only operate against the exact targets supplied in the current job authorization.
- Targets are exact hosts, URLs, or (Enterprise) IP/CIDR ranges. Hobby also allows *.vercel.app.
- If a tool would touch anything outside that list, refuse and report the violation.
- Load/stress tools require extra confirmation and are not available in this scaffold yet.

TOOLS
You have access to the VibeHacking tool catalog (ash, vibe_headers, ghost, api_finder, leep, axios, ssrf_probe, traversal_sniper, senoria, noloader, …).
Always prefer these tools. Always use baseline/control comparisons. Never treat a plain HTTP 200 as proof of a vulnerability.

WORKFLOW
1. Confirm authorization is present and the confirmation phrase was accepted.
2. Run recon against the exact targets only.
3. Prioritize findings by severity and evidence quality.
4. Produce a structured report with reproducible evidence. Do not invent findings.

OUTPUT
- Structured findings (severity, evidence, affected target, recommended next step).
- Never claim a vulnerability without differential evidence against a baseline.
- Never expand scope beyond the authorized target list.
"""
