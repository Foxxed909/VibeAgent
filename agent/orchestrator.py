"""Main orchestrator: validate auth → multi-round tool loop → report + event stream."""
from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

from .models import chat, OpenRouterError, validate_requested_model
from .scope import Authorization, ScopeError, assert_url_in_scope, CONFIRM_PHRASE, is_valid_trial_code
from .tools_catalog import (
    ALL_VIBEHACKING_TOOLS,
    agent_name,
    get_forced_tools,
    get_system_prompt,
    get_tool_catalog,
    normalize_agent_mode,
)
from .depth import get_depth, DepthProfile
from .findings import add_finding, finding_from_line, finding_from_worker, severity_counts
from .worker_client import (
    WorkerError,
    native_worker_capabilities,
    remote_audit_capabilities,
    run_native_target,
    run_remote_audit_tool,
    target_host,
)
from .target_verification import is_target_verified
from .request_context import (
    reset_cookie,
    reset_provider_keys,
    set_cookie,
    set_provider_keys,
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


class JobCancelled(Exception):
    """Raised at safe agent checkpoints when cancellation is requested."""

KNOWN_TOOL_NAMES = {tool["function"]["name"] for tool in ALL_VIBEHACKING_TOOLS}


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
    execution_backend: str = "portable",
    ownership_proofs: Optional[Dict[str, str]] = None,
    provider_keys: Optional[Dict[str, str]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    cookie_token = set_cookie(cookie)
    provider_keys_token = set_provider_keys(provider_keys)
    try:
        return _run_job_impl(
            auth,
            dry_run=dry_run,
            model=model,
            on_event=on_event,
            job_id=job_id,
            depth=depth,
            stress_multiplier=stress_multiplier,
            stress_mode=stress_mode,
            cookie=cookie,
            agent_mode=agent_mode,
            execution_backend=execution_backend,
            ownership_proofs=ownership_proofs,
            should_cancel=should_cancel,
        )
    finally:
        reset_provider_keys(provider_keys_token)
        reset_cookie(cookie_token)


def _run_job_impl(
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
    execution_backend: str = "portable",
    ownership_proofs: Optional[Dict[str, str]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    auth = auth.validated()
    trial = is_valid_trial_code(auth.access_code)
    job_id = job_id or secrets.token_urlsafe(18)
    profile = get_depth(depth)
    agent_mode = normalize_agent_mode(agent_mode)
    active_agent = agent_name(agent_mode)
    model = validate_requested_model(model)
    tool_catalog = get_tool_catalog(native=bool(VIBEHACKING_ROOT), agent_mode=agent_mode)
    catalog_names = {tool["function"]["name"] for tool in tool_catalog}
    execution_backend = (execution_backend or "portable").strip().lower()
    if execution_backend not in {"portable", "worker-tools", "native-worker"}:
        execution_backend = "portable"

    verified_targets = {
        target: is_target_verified(target, (ownership_proofs or {}).get(target))
        for target in auth.targets
    }

    worker_tools = set()
    worker_warning = None
    if execution_backend == "worker-tools":
        if not dry_run:
            unverified = [target for target, ok in verified_targets.items() if not ok]
            if unverified:
                raise WorkerError(
                    "worker-tools target ownership is not verified; complete the /.well-known/vibeagent-verification.txt challenge first"
                )
        caps = remote_audit_capabilities(auth.targets)
        if not caps.get("can_launch"):
            raise WorkerError(str(caps.get("message") or "VibeHacking audit-tool bridge is unavailable"))
        catalog_names = {t["function"]["name"] for t in tool_catalog}
        worker_tools = {
            name for name in (caps.get("remote_tools") or [])
            if name in catalog_names
        }
        if not worker_tools:
            raise WorkerError("VibeHacking worker has no compatible audit tools for this agent mode.")
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
        "available_tools": (
            [t["function"]["name"] for t in tool_catalog]
            if execution_backend in {"portable", "worker-tools"}
            else ["native-worker-managed"]
        ),
        "execution_backend": execution_backend,
        "worker_tools": sorted(worker_tools),
        "worker_warning": worker_warning,
        "ownership_verified": verified_targets,
        "native_worker": None,
        "loop": {
            "phase": "authorization",
            "rounds_completed": 0,
            "duplicate_calls_skipped": 0,
            "retests": 0,
            "stop_reason": None,
        },
        "review": None,
    }

    def check_cancel() -> None:
        if should_cancel and should_cancel():
            raise JobCancelled("assessment cancellation requested")

    def emit(kind: str, **kwargs: Any) -> None:
        ev = {"type": kind, **kwargs}
        report["events"].append(ev)
        _emit(on_event, ev)

    emit(
        "auth_ok",
        tier=auth.tier,
        trial=trial,
        targets=auth.targets,
        depth=profile.name,
        agent_mode=agent_mode,
        agent_name=active_agent,
        execution_backend=execution_backend,
    )

    if dry_run:
        report["plan"] = [
            f"Execution backend: {execution_backend}",
            f"Depth: {profile.name} (max_rounds={profile.max_rounds})",
            f"Force api_finder={profile.force_api_finder}, follow_up={profile.follow_up_on_hits}",
            f"Retries={profile.tool_retries}, timeout={profile.tool_timeout_s}s",
            f"Tool budget={profile.max_tool_calls}, retest budget={profile.max_retests}",
            "Loop: baseline → investigate → reproduce → independent review → synthesize",
        ]
        if execution_backend == "native-worker":
            report["native_worker_capabilities"] = native_worker_capabilities(auth.targets, agent_mode=agent_mode)
            all_verified = bool(auth.targets) and all(verified_targets.values())
            report["native_worker_capabilities"]["ownership_verified"] = all_verified
            report["native_worker_capabilities"]["can_launch"] = bool(
                report["native_worker_capabilities"].get("can_launch")
            ) and all_verified
        elif execution_backend == "worker-tools":
            all_verified = bool(auth.targets) and all(verified_targets.values())
            report["worker_tool_capabilities"] = {
                "can_launch": all_verified,
                "ownership_verified": all_verified,
                "remote_tools": sorted(worker_tools),
            }
        report["status"] = "dry_run_ok"
        emit("done", status="dry_run_ok")
        return report

    if execution_backend == "native-worker":
        return _run_native_worker_job(auth, report, emit, agent_mode, active_agent, ownership_proofs=ownership_proofs)

    model_investigation_ok = False
    investigation_interrupted = False
    model_synthesis_ok = not profile.require_final_report
    if stress_multiplier:
        if execution_backend == "worker-tools":
            emit("error", text="Stress mode is not available through the bounded worker-tools backend.")
        elif agent_mode == "break":
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
    report["loop"]["phase"] = "baseline"
    emit("phase", name="baseline")

    forced_tools = get_forced_tools(agent_mode, force_api_finder=profile.force_api_finder)

    for target in auth.targets:
        check_cancel()
        base = target if "://" in target else f"https://{target}"
        for tname in forced_tools:
            check_cancel()
            args: Dict[str, Any] = {"url": base}
            if tname == "api_finder":
                args["max_paths"] = profile.max_paths_per_tool
            if len(report["tool_calls"]) >= profile.max_tool_calls:
                break
            _run_one_tool(tname, args, auth, report, emit, profile, worker_tools=worker_tools)
            if tname == "api_finder" and profile.follow_up_on_hits:
                last = report["tool_calls"][-1] if report["tool_calls"] else None
                out = ((last or {}).get("result") or {}).get("stdout") or ""
                for hit_url in _parse_api_hits(base, out):
                    try:
                        assert_url_in_scope(hit_url, auth)
                    except ScopeError:
                        continue
                    if len(report["tool_calls"]) >= profile.max_tool_calls:
                        break
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

    report["loop"]["phase"] = "investigate"
    emit("phase", name="investigate")
    executed = {
        _tool_fingerprint(str(call.get("tool") or ""), call.get("args") or {})
        for call in report["tool_calls"]
    }
    stagnant_rounds = 0

    for round_i in range(profile.max_rounds):
        check_cancel()
        if len(report["tool_calls"]) >= profile.max_tool_calls:
            report["loop"]["stop_reason"] = "tool_budget_reached"
            break
        emit("round", index=round_i + 1, max=profile.max_rounds)
        try:
            completion = _chat_with_retry(
                messages,
                model=model,
                tools=tool_catalog,
                max_tokens=4096,
                retries=profile.model_retries,
                emit=emit,
                purpose="investigation",
            )
        except (OpenRouterError, OpenAIError) as e:
            investigation_interrupted = True
            report["errors"].append(str(e))
            emit("error", text=str(e))
            break

        meta = completion.get("_vibeagent") or {}
        if meta.get("model") and not report.get("model"):
            report["model"] = meta.get("model")
            report["provider"] = meta.get("provider")
            report["reasoning_effort"] = meta.get("reasoning_effort") or "none"
            emit("model_info", model=report["model"], provider=report.get("provider"), reasoning_effort=report.get("reasoning_effort"))

        choices = completion.get("choices") or []
        choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
        if not choice:
            investigation_interrupted = True
            report["errors"].append("No usable investigation response from model")
            emit("error", text="No usable investigation response from model")
            break
        model_investigation_ok = True
        message = choice.get("message") or {}
        if not isinstance(message, dict):
            message = {}
        content = message.get("content")
        tool_calls = message.get("tool_calls") or []
        if not isinstance(tool_calls, list):
            tool_calls = []
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
            report["loop"]["stop_reason"] = "model_finished"
            break

        calls_executed_this_round = 0
        for tc in tool_calls:
            check_cancel()
            if not isinstance(tc, dict):
                report["errors"].append("Model returned an invalid tool call object.")
                continue
            fn = tc.get("function") or {}
            if not isinstance(fn, dict):
                report["errors"].append("Model returned an invalid tool function object.")
                continue
            name = fn.get("name") or ""
            if not isinstance(name, str):
                name = ""
            tc_id = tc.get("id") or name
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except (TypeError, json.JSONDecodeError):
                args = {}
            if not isinstance(args, dict):
                args = {}
            url = args.get("url") or ""
            emit("tool_start", tool=name, args=args)
            try:
                if name not in catalog_names:
                    raise ScopeError(f"Tool is not available to {active_agent}: {name!r}")
                if url:
                    assert_url_in_scope(url, auth)
                fingerprint = _tool_fingerprint(name, args)
                if fingerprint in executed:
                    report["loop"]["duplicate_calls_skipped"] += 1
                    emit("tool_result", tool=name, ok=True, skipped=True, preview="Skipped exact duplicate probe.")
                    messages.append({"role": "tool", "tool_call_id": tc_id, "content": "SKIPPED: exact duplicate probe; choose a new evidence-producing action."})
                    continue
                if len(report["tool_calls"]) >= profile.max_tool_calls:
                    messages.append({"role": "tool", "tool_call_id": tc_id, "content": "SKIPPED: tool-call budget reached; synthesize from existing evidence."})
                    report["loop"]["stop_reason"] = "tool_budget_reached"
                    continue
                result = _dispatch_tool(name, args, auth, profile, worker_tools=worker_tools)
                executed.add(fingerprint)
                calls_executed_this_round += 1
                report["tool_calls"].append({"tool": name, "args": args, "result": result})
                out = result.get("stdout") or result.get("message") or json.dumps(result)[:3000]
                if result.get("stub") or int(result.get("returncode") or 0) != 0:
                    report["errors"].append(f"Tool {name} failed: {str(result.get('stderr') or out)[:350]}")
                emit(
                    "tool_result",
                    tool=name,
                    ok=int(result.get("returncode") or 0) == 0,
                    backend=result.get("backend"),
                    preview=(out or "")[:2500],
                )
                if not result.get("stub") and int(result.get("returncode") or 0) == 0:
                    native_count = _harvest_worker_findings(name, result, report, emit, args=args)
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

        report["loop"]["rounds_completed"] = round_i + 1
        if calls_executed_this_round:
            stagnant_rounds = 0
        else:
            stagnant_rounds += 1
            if stagnant_rounds >= profile.stagnant_round_limit:
                report["loop"]["stop_reason"] = "no_new_evidence"
                break

    report["loop"]["phase"] = "reproduce"
    emit("phase", name="reproduce")
    _retest_findings(auth, report, emit, profile, worker_tools=worker_tools)

    analysis_effort = (os.environ.get("VIBE_AGENT_ANALYSIS_EFFORT") or "high").strip().lower()
    if analysis_effort not in {"none", "low", "medium", "high"}:
        analysis_effort = "high"
    review_model = (os.environ.get("VIBE_AGENT_REVIEW_MODEL") or "").strip()
    if review_model:
        report["loop"]["phase"] = "independent_review"
        emit("phase", name="independent_review", model=review_model)
        try:
            validate_requested_model(review_model)
            review_messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an independent defensive-security evidence reviewer. "
                        "Do not propose bypasses or new attack actions. Identify false positives, "
                        "missing evidence, severity mistakes, and the three highest-value safe follow-ups."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps({
                        "targets": auth.targets,
                        "findings": report.get("findings") or [],
                        "errors": report.get("errors") or [],
                        "tool_count": len(report.get("tool_calls") or []),
                    })[:24000],
                },
            ]
            review_completion = _chat_with_retry(
                review_messages,
                model=review_model,
                tools=None,
                max_tokens=1800,
                retries=profile.model_retries,
                emit=emit,
                purpose="independent review",
                reasoning_effort=analysis_effort,
            )
            review_choice = (review_completion.get("choices") or [{}])[0]
            review_text = str((review_choice.get("message") or {}).get("content") or "").strip()
            review_meta = review_completion.get("_vibeagent") or {}
            if review_text:
                report["review"] = {
                    "model": review_meta.get("model") or review_model,
                    "provider": review_meta.get("provider"),
                    "text": review_text,
                }
                messages.append({
                    "role": "user",
                    "content": "Independent reviewer notes (advisory; preserve only claims supported by tool evidence):\n\n" + review_text[:8000],
                })
                emit("review", model=report["review"]["model"], text=review_text[:4000])
        except Exception as exc:
            report["errors"].append(f"Independent review unavailable: {exc}")
            emit("error", text="Independent review unavailable; continuing with collected evidence.")

    check_cancel()
    if profile.require_final_report:
        messages.append({
            "role": "user",
            "content": (
                f"Write the final {active_agent} report with a ## Findings section. "
                "Use only collected tool evidence, incorporate reproduced/unconfirmed status and reviewer corrections, "
                "deduplicate claims, and include severity, evidence, URL and fix guidance. "
                "Use attacker-style threat reasoning but clearly distinguish what was actually tested. "
                "For every material finding include the preconditions, attack surface, observed behavior, "
                "confidence, contradictory evidence, impact rationale, and remediation. "
                "Challenges are informational and authorization is context, not evidence."
            ),
        })
        try:
            report["loop"]["phase"] = "synthesize"
            emit("phase", name="synthesize")
            completion = _chat_with_retry(
                messages,
                model=model,
                tools=None,
                max_tokens=3072,
                retries=profile.model_retries,
                emit=emit,
                purpose="synthesis",
                reasoning_effort=analysis_effort,
            )
            meta = completion.get("_vibeagent") or {}
            if meta.get("model"):
                report["model"] = report.get("model") or meta.get("model")
            choice = (completion.get("choices") or [{}])[0]
            content = (choice.get("message") or {}).get("content")
            if content:
                model_synthesis_ok = True
                report["report_text"] = content
                emit("agent_message", text=content[:8000])
        except Exception as e:
            report["errors"].append(f"Synthesis failed: {e}")
            report["report_text"] = _local_findings_fallback(report)
            emit("agent_message", text=report["report_text"])

    if not model_investigation_ok:
        report["status"] = "failed"
    elif investigation_interrupted or not model_synthesis_ok:
        report["status"] = "partial"
    else:
        report["status"] = "completed"
    report["loop"]["phase"] = report["status"]
    report["loop"]["stop_reason"] = report["loop"].get("stop_reason") or report["status"]
    report["summary"] = {
        "total_findings": len(report["findings"]),
        "severity": severity_counts(report),
        "errors": len(report.get("errors") or []),
    }
    emit("done", status=report["status"], findings=len(report["findings"]), summary=report["summary"])
    return report


def _tool_fingerprint(name: str, args: Dict[str, Any]) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{name}|{canonical}".encode("utf-8")).hexdigest()


def _chat_with_retry(
    messages: List[Dict[str, Any]],
    *,
    model: Optional[str],
    tools: Optional[List[Dict[str, Any]]],
    max_tokens: int,
    retries: int,
    emit,
    purpose: str,
    reasoning_effort: Optional[str] = None,
) -> Dict[str, Any]:
    last_error: Optional[Exception] = None
    for attempt in range(1, max(1, retries) + 1):
        try:
            return chat(messages, model=model, tools=tools, max_tokens=max_tokens, reasoning_effort=reasoning_effort)
        except (OpenRouterError, OpenAIError) as exc:
            last_error = exc
            if attempt >= max(1, retries):
                raise
            delay = min(2.0, 0.35 * (2 ** (attempt - 1)))
            emit("model_retry", purpose=purpose, attempt=attempt, delay_s=delay)
            time.sleep(delay)
    assert last_error is not None
    raise last_error


def _retest_findings(
    auth: Authorization,
    report: Dict[str, Any],
    emit,
    profile: DepthProfile,
    *,
    worker_tools=None,
) -> None:
    candidates = []
    for finding in report.get("findings") or []:
        severity = str(finding.get("severity") or "info").lower()
        status = str(finding.get("validation_status") or "").lower()
        tool = str(finding.get("tool") or "")
        url = str(finding.get("location") or "")
        if severity not in {"critical", "high", "medium"}:
            continue
        if status not in {"observed", "unconfirmed"}:
            continue
        if tool not in KNOWN_TOOL_NAMES or not url:
            continue
        candidates.append(finding)

    for finding in candidates[:profile.max_retests]:
        if len(report.get("tool_calls") or []) >= profile.max_tool_calls:
            report["loop"]["stop_reason"] = "tool_budget_reached"
            return
        try:
            assert_url_in_scope(str(finding["location"]), auth)
        except ScopeError:
            continue
        before = len(report["tool_calls"])
        _run_one_tool(
            str(finding["tool"]),
            {"url": str(finding["location"])},
            auth,
            report,
            emit,
            profile,
            worker_tools=worker_tools,
        )
        report["loop"]["retests"] += 1
        if len(report["tool_calls"]) <= before:
            continue
        result = report["tool_calls"][-1].get("result") or {}
        output = str(result.get("stdout") or result.get("message") or "")
        evidence = str(finding.get("evidence") or "").strip()
        if evidence and evidence in output:
            finding["retested"] = True
            # Repeatability is not evidence of exploitability for heuristic checks.
            deterministic = finding.get("tool") == "vibe_headers" and evidence.startswith("MISSING:")
            if not deterministic:
                continue
            finding["validation_status"] = "reproduced"
            emit(
                "finding_validated",
                id=finding.get("id"),
                validation_status="reproduced",
                tool=finding.get("tool"),
                location=finding.get("location"),
            )


def _emit_structured_finding(report: Dict[str, Any], emit, finding: Dict[str, Any]) -> None:
    if not add_finding(report, finding):
        return
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


def _run_native_worker_job(
    auth: Authorization,
    report: Dict[str, Any],
    emit,
    agent_mode: str,
    active_agent: str,
    *,
    ownership_proofs: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    if len(auth.targets) != 1:
        raise WorkerError("native-worker backend currently requires exactly one target per job")

    target = auth.targets[0]
    if not is_target_verified(target, (ownership_proofs or {}).get(target)):
        raise WorkerError(
            "native-worker target ownership is not verified; complete the /.well-known/vibeagent-verification.txt challenge first"
        )
    caps = native_worker_capabilities(auth.targets, agent_mode=agent_mode)
    if not caps.get("can_launch"):
        rejected = caps.get("rejected_targets") or []
        if rejected:
            raise WorkerError("target is not approved in VIBE_AGENT_WORKER_ALLOWED_HOSTS")
        raise WorkerError(str(caps.get("message") or "native worker is unavailable"))

    emit("agent_message", text=f"{active_agent} delegating approved target to protected native VibeHacking worker.")

    def on_worker_event(event: Dict[str, Any]) -> None:
        kind = str(event.get("kind") or "info").lower()
        title = str(event.get("title") or "")
        detail = str(event.get("detail") or "")
        tool = str(event.get("tool") or "")
        if kind == "tool_start":
            emit("tool_start", tool=tool or title or "native-worker", args={"url": target, "native_worker": True})
        elif kind == "tool_result":
            emit("tool_result", tool=tool or "native-worker", ok=True, preview=(detail or title)[:2500])
        elif kind == "break":
            emit("agent_message", text=(title + ("\n" + detail if detail else ""))[:4000])
        else:
            emit("agent_message", text=(title + ("\n" + detail if detail else ""))[:4000])

    state = run_native_target(target, agent_mode, on_worker_event=on_worker_event)
    worker_model = state.get("model") or {}
    if isinstance(worker_model, dict):
        report["model"] = worker_model.get("id") or worker_model.get("name")
    else:
        report["model"] = str(worker_model or "") or None
    report["provider"] = "vibehacking-worker"
    report["reasoning_effort"] = "worker-managed"
    report["native_worker"] = {
        "thread_id": state.get("thread_id"),
        "status": state.get("status"),
        "verdict": state.get("verdict"),
        "resilience_score": state.get("resilience_score"),
        "confirmed_breaks": len(state.get("confirmed_breaks") or []),
    }

    expected_host = target_host(target)

    # The upstream worker currently reads a shared structured-finding log.
    # Accept only findings with an explicit full URL that resolves back to this exact target host.
    for raw in state.get("findings") or []:
        if not isinstance(raw, dict):
            continue
        location = str(raw.get("location") or raw.get("url") or "")
        if not location or target_host(location) != expected_host:
            continue
        _emit_structured_finding(
            report,
            emit,
            finding_from_worker(raw, default_url=target, confirmed=False),
        )

    # confirmed_breaks are stored inside the thread state itself, so they are thread-local.
    for raw_break in state.get("confirmed_breaks") or []:
        if not isinstance(raw_break, dict):
            continue
        worker_finding = {
            "tool": raw_break.get("tool") or "native_worker",
            "title": raw_break.get("summary") or "Native worker confirmed weakness",
            "summary": raw_break.get("summary"),
            "evidence": raw_break.get("evidence"),
            "location": target,
            "severity": "high",
            "validation_status": "confirmed",
        }
        _emit_structured_finding(
            report,
            emit,
            finding_from_worker(worker_finding, default_url=target, confirmed=True),
        )

    verdict = str(state.get("verdict") or "Native worker assessment completed.")
    report["report_text"] = verdict + "\n\n" + _local_findings_fallback(report)
    report["status"] = "completed"
    report["summary"] = {
        "total_findings": len(report["findings"]),
        "severity": severity_counts(report),
        "errors": len(report.get("errors") or []),
    }
    emit("agent_message", text=report["report_text"][:8000])
    emit("done", status="completed", findings=len(report["findings"]), summary=report["summary"])
    return report


def _run_one_tool(name, args, auth, report, emit, profile: DepthProfile, *, worker_tools=None) -> None:
    emit("tool_start", tool=name, args=args)
    last_err = None
    for attempt in range(1, profile.tool_retries + 1):
        try:
            if args.get("url"):
                assert_url_in_scope(args["url"], auth)
            result = _dispatch_tool(name, args, auth, profile, worker_tools=worker_tools)
            report["tool_calls"].append({"tool": name, "args": args, "result": result})
            out = result.get("stdout") or result.get("message") or json.dumps(result)[:3000]
            if result.get("stub") or int(result.get("returncode") or 0) != 0:
                report["errors"].append(f"Tool {name} failed: {str(result.get('stderr') or out)[:350]}")
            emit(
                "tool_result",
                tool=name,
                ok=int(result.get("returncode") or 0) == 0,
                backend=result.get("backend"),
                preview=(out or "")[:2500],
            )
            if not result.get("stub") and int(result.get("returncode") or 0) == 0:
                native_count = _harvest_worker_findings(name, result, report, emit, args=args)
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
        if "FOUND" in line and "—" in line:
            candidate = line.split("—", 1)[1].strip().split()[0].strip(".,;()")
            if "://<host>" in candidate:
                suffix = candidate.split("://<host>", 1)[1]
                if suffix.startswith("/"):
                    hits.append(base.rstrip("/") + suffix)
                    continue
            if candidate.startswith(("http://", "https://")):
                hits.append(candidate)
                continue
        arrow = "→" if "→" in line else ("->" if "->" in line else None)
        if arrow is None:
            continue
        if "CHALLENGE" in line:
            continue
        path = line.split(arrow)[0].strip().split()[0]
        if not path.startswith("/"):
            continue
        hits.append(urljoin(base.rstrip("/") + "/", path.lstrip("/")))
    return hits[:12]


def _harvest_worker_findings(
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
    default_url = str((args or {}).get("url") or "")
    for raw in raw_findings[:50]:
        if not isinstance(raw, dict):
            continue
        finding = finding_from_worker(raw, default_url=default_url, confirmed=False, default_tool=name)
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
        _emit_structured_finding(report, emit, finding)


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
    if name not in KNOWN_TOOL_NAMES:
        raise ScopeError(f"unknown tool: {name!r}")
    url = args.get("url") or ""
    worker_tools = set(worker_tools or ())
    worker_error = ""

    if name in worker_tools:
        try:
            remote = run_remote_audit_tool(url, name, args=args)
            return {
                "backend": "vibehacking-worker",
                "returncode": int(remote.get("returncode") or 0),
                "stdout": str(remote.get("stdout") or "")[-6000:],
                "stderr": str(remote.get("stderr") or "")[-1000:],
                "findings": remote.get("findings") if isinstance(remote.get("findings"), list) else [],
            }
        except WorkerError as exc:
            worker_error = str(exc)

    if VIBEHACKING_ROOT:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name or ""):
            raise ScopeError("invalid native tool name")
        script = Path(VIBEHACKING_ROOT) / "TOOLS" / f"{name}.py"
        tools_root = (Path(VIBEHACKING_ROOT) / "TOOLS").resolve()
        try:
            script.resolve().relative_to(tools_root)
        except ValueError as exc:
            raise ScopeError("native tool path escaped the tools directory") from exc
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
                capture_output=True, text=True,
                timeout=(profile.tool_timeout_s if profile else 20),
                cwd=VIBEHACKING_ROOT,
                env=_native_tool_environment(),
            )
            return {
                "backend": "local-vibehacking",
                "returncode": proc.returncode,
                "stdout": (proc.stdout or "")[-6000:],
                "stderr": (proc.stderr or "")[-1000:],
            }

    if name == "api_finder" and profile:
        args = dict(args)
        args["max_paths"] = profile.max_paths_per_tool
    builtin = run_builtin(name, args)
    if not builtin.get("stub"):
        builtin = dict(builtin)
        builtin["backend"] = "portable"
        if worker_error:
            builtin["worker_error"] = worker_error
            builtin["stdout"] = f"[WORKER_FALLBACK] {worker_error}\n" + str(builtin.get("stdout") or "")
        return builtin
    return {
        "backend": "portable",
        "returncode": 1,
        "stub": True,
        "message": f"Tool {name} is not implemented by the selected execution backend for {url}.",
        "worker_error": worker_error or None,
    }


def _native_tool_environment() -> Dict[str, str]:
    """Pass runtime basics to local tools without provider/storage credentials."""
    allowed = {
        "PATH", "PYTHONPATH", "LANG", "LC_ALL", "TZ",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    }
    child = {key: value for key, value in os.environ.items() if key in allowed}
    child["PYTHONUNBUFFERED"] = "1"
    return child


def save_job(report: Dict[str, Any]) -> str:
    return _job_store.save_job(report)


def load_job(job_id: str) -> Optional[Dict[str, Any]]:
    return _job_store.load_job(job_id)
