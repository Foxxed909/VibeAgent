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
from urllib.parse import urljoin

from .models import chat, OpenRouterError
from .scope import Authorization, ScopeError, assert_url_in_scope, CONFIRM_PHRASE, is_valid_trial_code
from .tools_catalog import VIBEHACKING_TOOLS, SYSTEM_PROMPT
from .depth import get_depth, DepthProfile
from . import job_store as _job_store

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
    depth: str = "standard",
    stress_multiplier: Optional[int] = None,
    stress_mode: str = "capped",
    cookie: Optional[str] = None,
) -> Dict[str, Any]:
    auth = auth.validated()
    trial = is_valid_trial_code(auth.access_code)
    job_id = job_id or str(uuid.uuid4())[:12]
    profile = get_depth(depth)
    if cookie:
        os.environ["VIBEAGENT_COOKIE"] = cookie

    report: Dict[str, Any] = {
        "job_id": job_id,
        "tier": auth.tier,
        "trial": trial,
        "targets": auth.targets,
        "app_name": auth.app_name,
        "company_name": auth.company_name,
        "status": "planned" if dry_run else "running",
        "depth": profile.name,
        "model": None,
        "provider": None,
        "reasoning_effort": "none",
        "findings": [],
        "tool_calls": [],
        "errors": [],
        "events": [],
        "report_text": None,
        "stress": None,
    }

    def emit(kind: str, **kwargs: Any) -> None:
        ev = {"type": kind, **kwargs}
        report["events"].append(ev)
        _emit(on_event, ev)

    emit("auth_ok", tier=auth.tier, trial=trial, targets=auth.targets, depth=profile.name)

    if dry_run:
        report["plan"] = [
            f"Depth: {profile.name} (max_rounds={profile.max_rounds})",
            f"Force api_finder={profile.force_api_finder}, follow_up={profile.follow_up_on_hits}",
            f"Retries={profile.tool_retries}, timeout={profile.tool_timeout_s}s",
        ]
        report["status"] = "dry_run_ok"
        emit("done", status="dry_run_ok")
        return report

    if stress_multiplier:
        if not (trial or auth.tier == "enterprise"):
            emit("error", text="Stress multipliers require Enterprise tier or trial access code.")
        else:
            try:
                from .stress import run_stress, format_stress
                m = int(stress_multiplier)
                for target in auth.targets:
                    url = target if "://" in target else f"https://{target}"
                    assert_url_in_scope(url, auth)
                    emit("tool_start", tool="stress", args={"url": url, "multiplier": m, "mode": stress_mode})
                    result = run_stress(url, multiplier=m, cookie=cookie, mode=stress_mode or "capped")
                    text = format_stress(result)
                    report["stress"] = result.__dict__
                    report["tool_calls"].append({"tool": "stress", "args": {"url": url, "multiplier": m}, "result": {"stdout": text}})
                    emit("tool_result", tool="stress", ok=True, preview=text)
            except Exception as e:
                report["errors"].append(f"Stress failed: {e}")
                emit("error", text=str(e))

    user_brief = (
        f"Authorization accepted.\nTier: {auth.tier}\nTrial: {trial}\n"
        f"Depth: {profile.name} (up to {profile.max_rounds} rounds)\n"
        f"Targets: {json.dumps(auth.targets)}\n"
        f"App/Company: {auth.app_name or auth.company_name}\n"
        f"MUST: recon, api_finder + follow-up, ghost/senoria, never quit on soft fail/challenge, "
        f"end with ## Findings. Challenges are informational, not downtime."
    )
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_brief},
    ]
    emit("agent_message", text=f"Starting {profile.name} assessment ({profile.max_rounds} max rounds).")

    forced_tools = ["ash", "vibe_headers"]
    if profile.force_api_finder:
        forced_tools.append("api_finder")
    forced_tools.extend(["ghost", "senoria"])

    for target in auth.targets:
        base = target if "://" in target else f"https://{target}"
        for tname in forced_tools:
            args: Dict[str, Any] = {"url": base}
            if tname == "api_finder":
                args["max_paths"] = profile.max_paths_per_tool
            _run_one_tool(tname, args, auth, report, emit, profile)
            if tname == "api_finder" and profile.follow_up_on_hits:
                last = report["tool_calls"][-1] if report["tool_calls"] else None
                out = ((last or {}).get("result") or {}).get("stdout") or ""
                for hit_url in _parse_api_hits(base, out):
                    try:
                        assert_url_in_scope(hit_url, auth)
                    except ScopeError:
                        continue
                    _run_one_tool("vibe_headers", {"url": hit_url}, auth, report, emit, profile)

    tool_digest = []
    for tc in report["tool_calls"]:
        preview = (tc.get("result") or {}).get("stdout") or tc.get("blocked") or ""
        tool_digest.append(f"### {tc['tool']} {tc.get('args')}\n{preview[:2500]}")
    messages.append({
        "role": "user",
        "content": (
            "Forced recon results follow. Continue with extra in-scope probes if useful, "
            "then write final ## Findings. Do not give up on challenges.\n\n"
            + "\n\n".join(tool_digest[:20])
        ),
    })

    for round_i in range(profile.max_rounds):
        emit("round", index=round_i + 1, max=profile.max_rounds)
        try:
            completion = chat(messages, model=model, tools=VIBEHACKING_TOOLS, max_tokens=4096)
        except (OpenRouterError, OpenAIError) as e:
            report["errors"].append(str(e))
            emit("error", text=str(e))
            break

        meta = completion.get("_vibeagent") or {}
        if meta.get("model") and not report.get("model"):
            report["model"] = meta.get("model")
            report["provider"] = meta.get("provider")
            report["reasoning_effort"] = meta.get("reasoning_effort") or "none"
            emit("model_info", model=report["model"], provider=report.get("provider"), reasoning_effort=report.get("reasoning_effort"))

        choice = (completion.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        content = message.get("content")
        tool_calls = message.get("tool_calls") or []
        reasoning = message.get("reasoning") or message.get("reasoning_content")
        if reasoning:
            emit("reasoning", text=str(reasoning)[:6000])

        assistant_msg: Dict[str, Any] = {"role": "assistant", "content": content}
        if tool_calls:
            assistant_msg["tool_calls"] = tool_calls
        messages.append(assistant_msg)
        if content:
            report["report_text"] = content
            emit("agent_message", text=content[:8000])
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
                result = _dispatch_tool(name, args, auth, profile)
                report["tool_calls"].append({"tool": name, "args": args, "result": result})
                out = result.get("stdout") or result.get("message") or json.dumps(result)[:3000]
                emit("tool_result", tool=name, ok=True, preview=(out or "")[:2500])
                _harvest_findings(name, out, report, emit)
                messages.append({"role": "tool", "tool_call_id": tc_id, "content": (out or "")[:6000]})
            except ScopeError as e:
                report["errors"].append(f"Scope violation blocked: {e}")
                emit("tool_result", tool=name, ok=False, preview=str(e))
                messages.append({"role": "tool", "tool_call_id": tc_id, "content": f"BLOCKED: {e}"})
            except Exception as e:
                report["errors"].append(f"Tool {name} failed: {e}")
                emit("tool_result", tool=name, ok=False, preview=str(e))
                messages.append({"role": "tool", "tool_call_id": tc_id, "content": f"ERROR: {e}"})

    if profile.require_final_report and (
        not report.get("report_text") or "## Findings" not in (report.get("report_text") or "")
    ):
        messages.append({
            "role": "user",
            "content": (
                "Write the final report with a ## Findings section. "
                "Severity, evidence, URL, fix hints. Challenges are informational."
            ),
        })
        try:
            completion = chat(messages, model=model, tools=None, max_tokens=3072)
            meta = completion.get("_vibeagent") or {}
            if meta.get("model"):
                report["model"] = report.get("model") or meta.get("model")
            choice = (completion.get("choices") or [{}])[0]
            content = (choice.get("message") or {}).get("content")
            if content:
                report["report_text"] = content
                emit("agent_message", text=content[:8000])
        except Exception as e:
            report["errors"].append(f"Synthesis failed: {e}")
            report["report_text"] = _local_findings_fallback(report)
            emit("agent_message", text=report["report_text"])

    report["status"] = "completed"
    emit("done", status="completed", findings=len(report["findings"]))
    return report


def _run_one_tool(name, args, auth, report, emit, profile: DepthProfile) -> None:
    emit("tool_start", tool=name, args=args)
    last_err = None
    for attempt in range(1, profile.tool_retries + 1):
        try:
            if args.get("url"):
                assert_url_in_scope(args["url"], auth)
            result = _dispatch_tool(name, args, auth, profile)
            report["tool_calls"].append({"tool": name, "args": args, "result": result})
            out = result.get("stdout") or result.get("message") or json.dumps(result)[:3000]
            emit("tool_result", tool=name, ok=True, preview=(out or "")[:2500])
            _harvest_findings(name, out, report, emit)
            if "[CHALLENGE]" in (out or ""):
                emit("finding", severity="info", detail=f"Bot/CDN challenge during {name}")
            return
        except ScopeError as e:
            report["errors"].append(str(e))
            emit("tool_result", tool=name, ok=False, preview=str(e))
            return
        except Exception as e:
            last_err = e
            time.sleep(0.4 * attempt)
    report["errors"].append(f"Tool {name} failed after retries: {last_err}")
    emit("tool_result", tool=name, ok=False, preview=str(last_err))


def _parse_api_hits(base: str, stdout: str) -> List[str]:
    """Extract in-scope follow-up URLs from api_finder output.

    api_finder prints one candidate per line as ``/path -> <status> ...`` using
    a unicode arrow (U+2192); ``->`` is accepted as a fallback. Challenge lines
    are skipped -- a challenge is not a discovered endpoint.
    """
    arrows = ("\u2192", "->")
    hits: List[str] = []
    base_prefix = base.rstrip("/") + "/"
    for line in (stdout or "").splitlines():
        if "CHALLENGE" in line:
            continue
        arrow = next((a for a in arrows if a in line), None)
        if arrow is None:
            continue
        head = line.split(arrow, 1)[0].strip().split()
        if not head:
            continue
        path = head[0]
        if not path.startswith("/"):
            continue
        hits.append(urljoin(base_prefix, path.lstrip("/")))
    return hits[:12]


def _harvest_findings(name: str, out: str, report: Dict[str, Any], emit) -> None:
    if not out:
        return
    for line in out.splitlines():
        if "MISSING:" in line or "CRITICAL" in line:
            detail = line.strip()
            report["findings"].append({"severity": "critical", "tool": name, "detail": detail})
            emit("finding", severity="critical", detail=detail)
        if "POSSIBLE exposure" in line:
            report["findings"].append({"severity": "high", "tool": name, "detail": line.strip()})
            emit("finding", severity="high", detail=line.strip())


def _local_findings_fallback(report: Dict[str, Any]) -> str:
    lines = ["## Findings", ""]
    if report.get("findings"):
        for f in report["findings"]:
            lines.append(f"- **{f.get('severity', 'info')}** ({f.get('tool')}): {f.get('detail')}")
    else:
        lines.append("- No automated critical findings harvested. Review tool transcripts above.")
    return "\n".join(lines)


def _dispatch_tool(name: str, args: Dict[str, Any], auth: Authorization, profile: Optional[DepthProfile] = None) -> Any:
    url = args.get("url") or ""
    if VIBEHACKING_ROOT:
        script = Path(VIBEHACKING_ROOT) / "TOOLS" / f"{name}.py"
        if script.exists():
            proc = subprocess.run(
                [sys.executable, str(script), "--url", url],
                capture_output=True, text=True,
                timeout=(profile.tool_timeout_s if profile else 20),
                cwd=VIBEHACKING_ROOT,
            )
            return {"returncode": proc.returncode, "stdout": (proc.stdout or "")[-6000:], "stderr": (proc.stderr or "")[-1000:]}
    if name == "api_finder" and profile:
        args = dict(args)
        args["max_paths"] = profile.max_paths_per_tool
    builtin = run_builtin(name, args)
    if not builtin.get("stub"):
        return builtin
    return {"stub": True, "message": f"Tool {name} acknowledged for {url}."}


def save_job(report: Dict[str, Any]) -> str:
    return _job_store.save_job(report)


def load_job(job_id: str) -> Optional[Dict[str, Any]]:
    return _job_store.load_job(job_id)
