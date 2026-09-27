"""Main orchestrator: validate auth → plan → call model → scope-check tools → report."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import chat, OpenRouterError, DEFAULT_MODEL
from .scope import Authorization, ScopeError, assert_url_in_scope, CONFIRM_PHRASE, is_valid_trial_code
from .tools_catalog import VIBEHACKING_TOOLS, SYSTEM_PROMPT

VIBEHACKING_ROOT = os.environ.get("VIBEHACKING_ROOT", "")


def run_job(auth: Authorization, *,
            dry_run: bool = False,
            model: Optional[str] = None) -> Dict[str, Any]:
    auth = auth.validated()
    trial = is_valid_trial_code(auth.access_code)
    report: Dict[str, Any] = {
        "tier": auth.tier,
        "trial": trial,
        "targets": auth.targets,
        "app_name": auth.app_name,
        "company_name": auth.company_name,
        "status": "planned" if dry_run else "running",
        "findings": [],
        "tool_calls": [],
        "errors": [],
    }

    if dry_run:
        report["plan"] = [
            f"Validate confirmation phrase ({CONFIRM_PHRASE!r})",
            f"Trial access: {trial}",
            f"Scope lock to: {auth.targets}",
            "Recon: ash, vibe_headers, ghost, api_finder",
            "Auth/access: leep, axios",
            "Injection surface: ssrf_probe, traversal_sniper",
            "Secrets: senoria",
            "Compile evidence-based report",
        ]
        report["status"] = "dry_run_ok"
        return report

    user_brief = (
        f"Authorization accepted.\n"
        f"Tier: {auth.tier}\n"
        f"Trial: {trial}\n"
        f"Targets (exact only): {json.dumps(auth.targets)}\n"
        f"App/Company: {auth.app_name or auth.company_name}\n"
        f"Run a scoped security assessment. Call tools only on the targets above."
    )
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_brief},
    ]

    try:
        completion = chat(
            messages,
            model=model or DEFAULT_MODEL,
            tools=VIBEHACKING_TOOLS,
        )
    except OpenRouterError as e:
        report["status"] = "model_error"
        report["errors"].append(str(e))
        return report

    choice = (completion.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    report["model_raw"] = message.get("content")

    tool_calls = message.get("tool_calls") or []
    for tc in tool_calls:
        fn = (tc.get("function") or {})
        name = fn.get("name") or ""
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {}
        url = args.get("url") or ""
        try:
            if url:
                assert_url_in_scope(url, auth)
            result = _dispatch_tool(name, args, auth)
            report["tool_calls"].append({"tool": name, "args": args, "result": result})
        except ScopeError as e:
            report["errors"].append(f"Scope violation blocked: {e}")
            report["tool_calls"].append({"tool": name, "args": args, "blocked": str(e)})
        except Exception as e:
            report["errors"].append(f"Tool {name} failed: {e}")

    report["status"] = "completed"
    return report


def _dispatch_tool(name: str, args: Dict[str, Any], auth: Authorization) -> Any:
    url = args.get("url") or ""
    if VIBEHACKING_ROOT:
        script = Path(VIBEHACKING_ROOT) / "TOOLS" / f"{name}.py"
        if script.exists():
            cmd = [sys.executable, str(script), "--url", url]
            if name == "traversal_sniper" and args.get("app_root"):
                cmd.extend(["--app-root", args["app_root"]])
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=VIBEHACKING_ROOT,
            )
            return {
                "returncode": proc.returncode,
                "stdout": proc.stdout[-4000:],
                "stderr": proc.stderr[-1000:],
            }
    return {
        "stub": True,
        "message": f"Tool {name} acknowledged for {url}. Set VIBEHACKING_ROOT to execute real tools.",
    }


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="VibeAgent orchestrator")
    p.add_argument("--tier", choices=["hobby", "enterprise"], default="hobby")
    p.add_argument("--target", action="append", default=[], help="Exact target (repeatable)")
    p.add_argument("--app-name", default="")
    p.add_argument("--company-name", default="")
    p.add_argument("--confirm", default="", help=f"Must be exactly: {CONFIRM_PHRASE}")
    p.add_argument("--access-code", default="", help="Trial / friends access code")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--model", default=None)
    args = p.parse_args(argv)

    auth = Authorization(
        tier=args.tier,
        targets=args.target or ["http://127.0.0.1:3456"],
        confirmation=args.confirm or CONFIRM_PHRASE,
        app_name=args.app_name or ("local-demo" if args.tier == "hobby" else None),
        company_name=args.company_name or ("Demo Corp" if args.tier == "enterprise" else None),
        access_code=args.access_code or None,
    )
    try:
        report = run_job(auth, dry_run=args.dry_run, model=args.model)
    except ScopeError as e:
        print(json.dumps({"status": "refused", "error": str(e)}, indent=2))
        return 2
    print(json.dumps(report, indent=2))
    return 0 if report.get("status") in ("completed", "dry_run_ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
