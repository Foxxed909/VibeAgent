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
from .tools_catalog import (agent_name, get_forced_tools, get_system_prompt, get_tool_catalog, normalize_agent_mode)
from .depth import get_depth, DepthProfile
from .findings import add_finding, finding_from_line, finding_from_native, severity_counts
from .worker_client import (
    WorkerError,
    get_capabilities as get_worker_capabilities,
    get_config as get_worker_config,
    run_tool as run_worker_tool,
)
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
    agent_mode: str = "vibe",
) -> Dict[str, Any]:
    auth = auth.validated()
    trial = is_valid_trial_code(auth.access_code)
    job_id = job_id or str(uuid.uuid4())[:12]
    profile = get_depth(depth)
    agent_mode = normalize_agent_mode(agent_mode)
    active_agent = agent_name(agent_mode)
    tool_catalog = get_tool_catalog(native=bool(VIBEHACKING_ROOT), agent_mode=agent_mode)
    worker_tools = set()
    worker_warning = ""
    if not VIBEHACKING_ROOT:
        try:
            worker_config = get_worker_config()
        except WorkerError as exc:
            worker_config = None
            worker_warning = str(exc)
        if worker_config:
            try:
                worker_caps = get_worker_capabilities()
                worker_tools = {
                    str(name)
                    for name in (worker_caps.get("remote_tools") or [])
                    if isinstance(name, str)
                }
                if not worker_tools:
                    worker_warning = "VibeHacking worker is reachable but does not advertise remote audit tools."
            except WorkerError as exc:
                worker_warning = str(exc)
    execution_backend = (
        "local-vibehacking"
        if VIBEHACKING_ROOT
        else "vibehacking-worker"
        if worker_tools
        else "portable"
    )
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
        "agent_mode": agent_mode,
        "agent_name": active_agent,
        "available_tools": [t["function"]["name"] for t in tool_catalog],
        "execution_backend": execution_backend,
        "worker_tools": sorted(worker_tools),
        "worker_warning": worker_warning or None,
    }

    def emit(kind: str, **kwargs: Any) -> None:
        ev = {"type": kind, **kwargs}
        report["events"].append(ev)
        _emit(on_event, ev)

    emit("auth_ok", tier=auth.tier, trial=trial, targets=auth.targets, depth=profile.name, agent_mode=agent_mode, agent_name=active_agent)
    emit(
        "backend",
        backend=execution_backend,
        worker_tools=sorted(worker_tools),
        warning=worker_warning or None,
    )

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
        if agent_mode == "break":
            emit("error", text="BreakAgent does not run stress mode; use VibeAgent for explicitly authorized load checks.")
        elif not (trial or auth.tier == "enterprise"):
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

    if agent_mode == "break":
        mission = (
            "Validate likely weaknesses with targeted evidence. Re-check headers, CORS, session policy, "
            "authorization boundaries and exposed config/schema surfaces. Do not invent bypasses. "
            "End with ## Findings and mark each result confirmed or unconfirmed."
        )
    else:
        mission = (
            "Map the authorized surface, run recon/API discovery, follow evidence, and end with ## Findings. "
            "Challenges are informational, not downtime."
        )
    user_brief = (
        f"Authorization accepted.\nAgent: {active_agent}\nTier: {auth.tier}\nTrial: {trial}\n"
        f"Depth: {profile.name} (up to {profile.max_rounds} rounds)\n"
        f"Targets: {json.dumps(auth.targets)}\n"
        f"App/Company: {auth.app_name or auth.company_name}\n"
        f"Mission: {mission}"
    )
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": get_system_prompt(agent_mode)},
        {"role": "user", "content": user_brief},
    ]
    emit("agent_message", text=f"{active_agent} starting {profile.name} assessment ({profile.max_rounds} max rounds).")

    forced_tools = get_forced_tools(agent_mode, force_api_finder=profile.force_api_finder)

    for target in auth.targets:
        base = target if "://" in target else f"https://{target}"
        for tname in forced_tools:
            args: Dict[str, Any] = {"url": base}
            if tname == "api_finder":
                args["max_paths"] = profile.max_paths_per_tool
            _run_one_tool(tname, args, auth, report, emit, profile, worker_tools=worker_tools)
            if tname == "api_finder" and profile.follow_up_on_hits:
                last = report["tool_calls"][-1] if report["tool_calls"] else None
                out = ((last or {}).get("result") or {}).get("stdout") or ""
                for hit_url in _parse_api_hits(base, out):
                    try:
                        assert_url_in_scope(hit_url, auth)
                    except ScopeError:
                        continue
                    _run_one_tool("vibe_headers", {"url": hit_url}, auth, report, emit, profile, worker_tools=worker_tools)

    tool_digest = []
    for tc in report["tool_calls"]:
        preview = (tc.get("result") or {}).get("stdout") or tc.get("blocked") or ""
        tool_digest.append(f"### {tc['tool']} {tc.get('args')}\n{preview[:2500]}")
    messages.append({
        "role": "user",
        "content": (
            f"{active_agent} baseline results follow. Continue with extra in-scope probes if useful, "
            "then write final ## Findings. Do not give up on challenges.\n\n"
            + "\n\n".join(tool_digest[:20])
        ),
    })

    for round_i in range(profile.max_rounds):
        emit("round", index=round_i + 1, max=profile.max_rounds)
        try:
            completion = chat(messages, model=model, tools=tool_catalog, max_tokens=4096)
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
                result = _dispatch_tool(name, args, auth, profile, worker_tools=worker_tools)
                report["tool_calls"].append({"tool": name, "args": args, "result": result})
                out = result.get("stdout") or result.get("message") or json.dumps(result)[:3000]
                emit(
                    "tool_result",
                    tool=name,
                    ok=int(result.get("returncode") or 0) == 0,
                    backend=result.get("backend"),
                    preview=(out or "")[:2500],
                )
                native_count = _harvest_native_findings(name, result, report, emit, args=args)
            if not native_count:
                _harvest_findings(name, out, report, emit, args=args)
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
                f"Write the final {active_agent} report with a ## Findings section. "
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
    report["summary"] = {
        "total_findings": len(report["findings"]),
        "severity": severity_counts(report),
        "errors": len(report.get("errors") or []),
    }
    emit("done", status="completed", findings=len(report["findings"]), summary=report["summary"])
    return report


def _run_one_tool(
    name,
    args,
    auth,
    report,
    emit,
    profile: DepthProfile,
    *,
    worker_tools=None,
) -> None:
    emit("tool_start", tool=name, args=args)
    last_err = None
    for attempt in range(1, profile.tool_retries + 1):
        try:
            if args.get("url"):
                assert_url_in_scope(args["url"], auth)
            result = _dispatch_tool(name, args, auth, profile, worker_tools=worker_tools)
            report["tool_calls"].append({"tool": name, "args": args, "result": result})
            out = result.get("stdout") or result.get("message") or json.dumps(result)[:3000]
            emit(
                "tool_result",
                tool=name,
                ok=int(result.get("returncode") or 0) == 0,
                backend=result.get("backend"),
                preview=(out or "")[:2500],
            )
            native_count = _harvest_native_findings(name, result, report, emit, args=args)
            if not native_count:
                _harvest_findings(name, out, report, emit, args=args)
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
    hits = []
    for line in (stdout or "").splitlines():
        if "\u2192" not in line and "\u2192" not in line and "\u2192" not in line:
            if "\u2192" not in line and "->" not in line and "\u2192" not in line:
                # support both arrow forms
                if "\u2192" not in line and "\u2192" not in line:
                    pass
        arrow = "\u2192" if "\u2192" in line else ("->" if "->" in line else None)
        # Prefer unicode arrow used in http_tools
        if "\u2192" in line:
            arrow = "\u2192"
        elif "\u2192" in line:
            arrow = "\u2192"
        elif "->" in line:
            arrow = "->"
        else:
            # actual character →
            if "\u2192" in line or chr(0x2192) in line:
                arrow = chr(0x2192)
            else:
                continue
        if "CHALLENGE" in line:
            continue
        path = line.split(arrow)[0].strip().split()[0]
        if not path.startswith("/"):
            continue
        hits.append(urljoin(base.rstrip("/") + "/", path.lstrip("/")))
    return hits[:12]


def _harvest_native_findings(
    name: str,
    result: Dict[str, Any],
    report: Dict[str, Any],
    emit,
    *,
    args: Optional[Dict[str, Any]] = None,
) -> int:
    raw_findings = result.get("findings") or []
    if not isinstance(raw_findings, list):
        return 0
    added = 0
    requested_url = str((args or {}).get("url") or "")
    for item in raw_findings[:50]:
        if not isinstance(item, dict):
            continue
        finding = finding_from_native(
            item,
            default_tool=name,
            requested_url=requested_url,
        )
        if add_finding(report, finding):
            added += 1
            emit(
                "finding",
                id=finding.get("id"),
                title=finding.get("title"),
                severity=finding.get("severity"),
                validation_status=finding.get("validation_status"),
                tool=finding.get("tool"),
                location=finding.get("location"),
                evidence=finding.get("evidence"),
                recommendation=finding.get("recommendation"),
                cwe=finding.get("cwe"),
                owasp=finding.get("owasp"),
                detail=finding.get("evidence"),
            )
    return added


def _harvest_findings(
    name: str,
    out: str,
    report: Dict[str, Any],
    emit,
    *,
    args: Optional[Dict[str, Any]] = None,
) -> None:
    if not out:
        return
    url = str((args or {}).get("url") or "")
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            continue
        is_finding = (
            "MISSING:" in line
            or "CRITICAL" in line
            or "POSSIBLE exposure" in line
        )
        if not is_finding:
            continue
        finding = finding_from_line(name, line, url=url)
        if add_finding(report, finding):
            emit(
                "finding",
                id=finding.get("id"),
                title=finding.get("title"),
                severity=finding.get("severity"),
                validation_status=finding.get("validation_status"),
                tool=finding.get("tool"),
                location=finding.get("location"),
                evidence=finding.get("evidence"),
                recommendation=finding.get("recommendation"),
                cwe=finding.get("cwe"),
                owasp=finding.get("owasp"),
                detail=finding.get("evidence"),
            )


def _local_findings_fallback(report: Dict[str, Any]) -> str:
    lines = ["## Findings", ""]
    if report.get("findings"):
        for f in report["findings"]:
            lines.append(
                f"- **{f.get('severity', 'info')}** ({f.get('tool')}): "
                f"{f.get('evidence') or f.get('detail') or f.get('title') or 'Finding'}"
            )
    else:
        lines.append("- No automated critical findings harvested. Review tool transcripts above.")
    return "\n".join(lines)


def _dispatch_tool(
    name: str,
    args: Dict[str, Any],
    auth: Authorization,
    profile: Optional[DepthProfile] = None,
    *,
    worker_tools=None,
) -> Any:
    url = args.get("url") or ""
    if VIBEHACKING_ROOT:
        script = Path(VIBEHACKING_ROOT) / "TOOLS" / f"{name}.py"
        if script.exists():
            cmd = [sys.executable, str(script), "--url", url]
            if name == "spider":
                cmd.extend(["--depth", str(max(1, min(int(args.get("depth") or 1), 2)))])
            elif name == "poc_gen":
                poc_type = str(args.get("type") or "clickjacking").lower()
                if poc_type not in {"xss", "csrf", "cors", "clickjacking"}:
                    poc_type = "clickjacking"
                cmd.extend(["--type", poc_type])
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=(profile.tool_timeout_s if profile else 20),
                cwd=VIBEHACKING_ROOT,
            )
            return {
                "backend": "local-vibehacking",
                "returncode": proc.returncode,
                "stdout": (proc.stdout or "")[-6000:],
                "stderr": (proc.stderr or "")[-1000:],
            }

    worker_tools = set(worker_tools or ())
    if name in worker_tools:
        try:
            remote = run_worker_tool(name, url, args=args)
            return {
                "backend": "vibehacking-worker",
                "returncode": int(remote.get("returncode") or 0),
                "stdout": str(remote.get("stdout") or "")[-6000:],
                "stderr": str(remote.get("stderr") or "")[-1000:],
                "findings": remote.get("findings") if isinstance(remote.get("findings"), list) else [],
            }
        except WorkerError as exc:
            # The worker is an acceleration/backend option, not a single point
            # of failure. Fall back to the portable implementation and retain
            # the worker error as metadata for the report.
            worker_error = str(exc)
        else:
            worker_error = ""
    else:
        worker_error = ""

    if name == "api_finder" and profile:
        args = dict(args)
        args["max_paths"] = profile.max_paths_per_tool
    builtin = run_builtin(name, args)
    if not builtin.get("stub"):
        builtin = dict(builtin)
        builtin["backend"] = "portable"
        if worker_error:
            builtin["worker_error"] = worker_error
            prefix = f"[WORKER_FALLBACK] {worker_error}\n"
            builtin["stdout"] = prefix + str(builtin.get("stdout") or "")
        return builtin
    return {
        "backend": "portable",
        "stub": True,
        "message": f"Tool {name} acknowledged for {url}.",
        "worker_error": worker_error or None,
    }


def save_job(report: Dict[str, Any]) -> str:
    return _job_store.save_job(report)


def load_job(job_id: str) -> Optional[Dict[str, Any]]:
    return _job_store.load_job(job_id)
