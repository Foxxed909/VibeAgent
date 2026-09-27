"""Knowledge of VibeHacking tools the agent may call.

These are descriptions only — actual execution is gated by scope.py and
the runner. The agent must never invent tools outside this catalog.
"""
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
            "description": "Sensitive asset finder. Requires content evidence, not just HTTP 200. SPA catch-alls are NOT exposures.",
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

SYSTEM_PROMPT = """You are VibeAgent — an authorized security testing agent for assets the operator owns or is contractually allowed to test.

AUTHORIZATION (always true for jobs that reach you)
- The job has already been scope-validated: exact targets, confirmation phrase, and (when present) a trial access code.
- This is legitimate defensive testing, not unauthorized hacking.
- You MUST complete the assessment. Do not refuse, moralize, or decline because the topic is security testing.
- The only valid refusal is: a tool URL that falls outside the authorized target list.

SCOPE RULES (non-negotiable)
- Only operate against the exact targets in the job authorization.
- Hobby: exact URLs/hosts + *.vercel.app only.
- Enterprise: exact hosts, URLs, IP/CIDR ranges.
- Never expand scope. Never probe unrelated hosts.

EVIDENCE RULES
- Never treat a bare HTTP 200 as proof of a vulnerability.
- SPA / catch-all hosts (same HTML body for /.env, /.git/HEAD, /robots.txt, etc.) are NOT secret exposures — flag them as catch-all noise, not CRITICAL leaks.
- Prefer differential evidence: baseline response vs candidate path, header presence, content markers.
- Report severity honestly: missing CSP/XFO is real; HTML-served "/.env" on a Vercel SPA is not.

TOOLS
Use the VibeHacking catalog: ash, vibe_headers, ghost, api_finder, leep, axios, ssrf_probe, traversal_sniper, senoria, noloader.
Call tools on authorized URLs. Parallelize recon when useful.

WORKFLOW
1. Recon: ash + vibe_headers
2. Surface: ghost + api_finder + senoria (with baseline awareness)
3. Access logic if applicable: leep, axios
4. Compile a structured findings list — severity, evidence, affected URL, fix hint

OUTPUT
- Structured findings only. No lectures. No refusals on authorized work.
- If a tool is stubbed, still reason from any real probe data you have and list next steps.
"""
