"""Main orchestrator: validate auth → multi-round tool loop → report + event stream."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .models import chat, OpenRouterError, DEFAULT_MODEL
from .scope import Authorization, ScopeError, assert_url_in_scope, CONFIRM_PHRASE, is_valid_trial_code
from .tools_catalog import VIBEHACKING_TOOLS, SYSTEM_PROMPT

try:
    from .openai_client import OpenAIError
except ImportError:
    OpenAIError = OpenRouterError  # type: ignore

try:
    from .http_tools import run_builtin
except ImportError:
    def run_builtin(name: str, args: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore
        return {"stub": True, "message": f"http_tools missing for {name}"}

VIBEHACKING_ROOT = os.environ.get("VIBEHACKING_ROOT", "")
MAX_ROUNDS = int(os.environ.get("VIBEAGENT_MAX_ROUNDS", "6"))
JOBS_DIR = Path(os.environ.get("VIBEAGENT_JOBS_DIR", "/tmp/vibeagent_jobs"))

EventCb = Optional[Callable[[Dict[str, Any]], None]]


def _emit(cb: EventCb, event: Dict[str, Any]) -> None:
    event.setdefault("ts", time.time())
    if cb:
        try:
            cb(event)
        except Exception:
            pass


def run_job(
    auth: Authorization,
    *,
    dry_run: bool = False,
    model: Optional[str] = None,
    on_event: EventCb = None,
    job_id: Optional[str] = None,
) -> Dict[str, Any]:
    auth = auth.validated()
    trial = is_valid_trial_code(auth.access_code)
    job_id = job_id or str(uuid.uuid4())[:12]

    report: Dict[str, Any] = {
        "job_id": job_id,
        "tier": auth.tier,
        "trial": trial,
        "targets": auth.targets,
        "app_name": auth.app_name,
        "company_name": auth.company_name,
        "status": "planned" if dry_run else "running",
        "findings": [],
        "tool_calls": [],
        "errors": [],
        "events": [],
        "report_text": None,
    }

    def emit(kind: str, **kwargs: Any) -> None:
        ev = {"type": kind, **kwargs}
        report["events"].append(ev)
        _emit(on_event, ev)

    emit("auth_ok", tier=auth.tier, trial=trial, targets=auth.targets)

    if dry_run:
        report["plan"] = [
            f"Validate confirmation phrase ({CONFIRM_PHRASE!r})",
            f"Trial access: {trial}",
            f"Scope lock to: {auth.targets}",
            "Recon: ash, vibe_headers, ghost, api_finder",
            "Secrets: senoria",
            "Compile evidence-based report",
        ]
        report["status"] = "dry_run_ok"
        emit("done", status="dry_run_ok")
        return report

    user_brief = (
        f"Authorization accepted.\n"
        f"Tier: {auth.tier}\n"
        f"Trial: {trial}\n"
        f"Targets (exact only): {json.dumps(auth.targets)}\n"
        f"App/Company: {auth.app_name or auth.company_name}\n"
        f"Run a scoped security assessment. Call tools only on the targets above.\n"
        f"After tools return, synthesize a structured findings list."
    )
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_brief},
    ]

    emit("agent_message", text="Starting scoped assessment.")

    for round_i in range(MAX_ROUNDS):
        emit("round", index=round_i + 1, max=MAX_ROUNDS)
        try:
            completion = chat(
                messages,
                model=model,
                tools=VIBEHACKING_TOOLS,
                max_tokens=4096,
            )
        except (OpenRouterError, OpenAIError) as e:
            report["status"] = "model_error"
            report["errors"].append(str(e))
            emit("error", text=str(e))
            emit("done", status="model_error")
            return report

        choice = (completion.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        content = message.get("content")
        tool_calls = message.get("tool_calls") or []

        assistant_msg: Dict[str, Any] = {"role": "assistant", "content": content}
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        messages.append(assistant_msg)

        if content:
            report["report_text"] = content
            emit("agent_message", text=content[:4000])

        if not tool_calls:
            break

        for tc in tool_calls:
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            tc_id = tc.get("id") or name
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            url = args.get("url") or ""
            emit("tool_start", tool=name, args=args)
            try:
                if url:
                    assert_url_in_scope(url, auth)
                result = _dispatch_tool(name, args, auth)
                report["tool_calls"].append({"tool": name, "args": args, "result": result})
                out = result.get("stdout") or result.get("message") or json.dumps(result)[:3000]
                emit("tool_result", tool=name, ok=True, preview=(out or "")[:2500])
                if name == "vibe_headers" and out:
                    for line in out.splitlines():
                        if "CRITICAL" in line or "MISSING:" in line:
                            report["findings"].append(
                                {"severity": "critical", "tool": name, "detail": line.strip()}
                            )
                            emit("finding", severity="critical", detail=line.strip())
                messages.append(
                    {"role": "tool", "tool_call_id": tc_id, "content": (out or "")[:6000]}
                )
            except ScopeError as e:
                report["errors"].append(f"Scope violation blocked: {e}")
                report["tool_calls"].append({"tool": name, "args": args, "blocked": str(e)})
                emit("tool_result", tool=name, ok=False, preview=str(e))
                messages.append({"role": "tool", "tool_call_id": tc_id, "content": f"BLOCKED: {e}"})
            except Exception as e:
                report["errors"].append(f"Tool {name} failed: {e}")
                emit("tool_result", tool=name, ok=False, preview=str(e))
                messages.append({"role": "tool", "tool_call_id": tc_id, "content": f"ERROR: {e}"})
    else:
        emit("agent_message", text="Max rounds reached; compiling from tool output.")

    if not report.get("report_text") and report["tool_calls"]:
        messages.append(
            {
                "role": "user",
                "content": (
                    "Based on the tool results above, write a concise findings report. "
                    "List severity, evidence, and fix hints. No false positives from SPA catch-alls."
                ),
            }
        )
        try:
            completion = chat(messages, model=model, tools=None, max_tokens=2048)
            choice = (completion.get("choices") or [{}])[0]
            message = choice.get("message") or {}
            content = message.get("content")
            if content:
                report["report_text"] = content
                emit("agent_message", text=content[:4000])
        except Exception as e:
            report["errors"].append(f"Synthesis failed: {e}")

    report["status"] = "completed"
    emit("done", status="completed", findings=len(report["findings"]))
    return report


def _dispatch_tool(name: str, args: Dict[str, Any], auth: Authorization) -> Any:
    url = args.get("url") or ""
    if VIBEHACKING_ROOT:
        script = Path(VIBEHACKING_ROOT) / "TOOLS" / f"{name}.py"
        if not script.exists() and name == "vibe_headers":
            for alt in ("vibe_headers.py",):
                cand = Path(VIBEHACKING_ROOT) / "TOOLS" / alt
                if cand.exists():
                    script = cand
                    break
        if script.exists():
            cmd = [sys.executable, str(script), "--url", url]
            if name == "traversal_sniper" and args.get("app_root"):
                cmd.extend(["--app-root", args["app_root"]])
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, cwd=VIBEHACKING_ROOT
            )
            return {
                "returncode": proc.returncode,
                "stdout": (proc.stdout or "")[-6000:],
                "stderr": (proc.stderr or "")[-1000:],
            }
    # Serverless / no VibeHacking install: real HTTP probes
    builtin = run_builtin(name, args)
    if not builtin.get("stub"):
        return builtin
    return {
        "stub": True,
        "message": f"Tool {name} acknowledged for {url}. Set VIBEHACKING_ROOT for full tool suite.",
    }


def save_job(report: Dict[str, Any]) -> Path:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    path = JOBS_DIR / f"{report['job_id']}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def load_job(job_id: str) -> Optional[Dict[str, Any]]:
    path = JOBS_DIR / f"{job_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


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
    p.add_argument("--save", action="store_true", help="Persist job JSON under VIBEAGENT_JOBS_DIR")
    args = p.parse_args(argv)

    auth = Authorization(
        tier=args.tier,
        targets=args.target or ["http://127.0.0.1:3456"],
        confirmation=args.confirm or CONFIRM_PHRASE,
        app_name=args.app_name or ("local-demo" if args.tier == "hobby" else None),
        company_name=args.company_name or ("Demo Corp" if args.tier == "enterprise" else None),
        access_code=args.access_code or None,
    )

    def print_event(ev: Dict[str, Any]) -> None:
        kind = ev.get("type")
        if kind == "tool_start":
            print(f"  → {ev.get('tool')} {ev.get('args')}", file=sys.stderr)
        elif kind == "tool_result":
            print(f"  ← {ev.get('tool')} ok={ev.get('ok')}", file=sys.stderr)
        elif kind == "agent_message":
            print(f"  ✎ {(ev.get('text') or '')[:120]}", file=sys.stderr)
        elif kind == "finding":
            print(f"  ! {ev.get('severity')}: {ev.get('detail')}", file=sys.stderr)

    try:
        report = run_job(auth, dry_run=args.dry_run, model=args.model, on_event=print_event)
    except ScopeError as e:
        print(json.dumps({"status": "refused", "error": str(e)}, indent=2))
        return 2
    if args.save or not args.dry_run:
        save_job(report)
    print(json.dumps(report, indent=2))
    return 0 if report.get("status") in ("completed", "dry_run_ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
