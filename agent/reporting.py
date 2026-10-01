"""JSON and SARIF exporters for canonical VibeAgent reports."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .findings import severity_counts


def normalized_report(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = list(report.get("findings") or [])
    return {
        "schema_version": "1.0",
        "job_id": report.get("job_id"),
        "status": report.get("status"),
        "agent": {
            "mode": report.get("agent_mode") or "vibe",
            "name": report.get("agent_name") or "VibeAgent",
        },
        "assessment": {
            "tier": report.get("tier"),
            "depth": report.get("depth"),
            "targets": report.get("targets") or [],
            "app_name": report.get("app_name"),
            "company_name": report.get("company_name"),
        },
        "model": {
            "provider": report.get("provider"),
            "name": report.get("model"),
            "reasoning_effort": report.get("reasoning_effort") or "none",
        },
        "summary": {
            "total_findings": len(findings),
            "severity": severity_counts(report),
            "errors": len(report.get("errors") or []),
        },
        "findings": findings,
        "report_text": report.get("report_text"),
    }


def json_bytes(report: Dict[str, Any]) -> bytes:
    return json.dumps(normalized_report(report), indent=2, ensure_ascii=False).encode("utf-8")


def _rule_id(finding: Dict[str, Any]) -> str:
    raw = str(finding.get("cwe") or finding.get("tool") or "VIBEAGENT")
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-") or "VIBEAGENT"


def _sarif_level(severity: str) -> str:
    sev = (severity or "info").lower()
    if sev in {"critical", "high"}:
        return "error"
    if sev in {"medium", "low"}:
        return "warning"
    return "note"


def sarif_dict(report: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = list(report.get("findings") or [])
    rule_map: Dict[str, Dict[str, Any]] = {}
    results = []

    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id not in rule_map:
            rule_map[rule_id] = {
                "id": rule_id,
                "name": str(finding.get("title") or finding.get("tool") or rule_id)[:120],
                "shortDescription": {"text": str(finding.get("title") or "VibeAgent finding")[:500]},
                "help": {
                    "text": str(finding.get("recommendation") or "Review and remediate the finding.")[:2000]
                },
                "properties": {
                    "security-severity": str(finding.get("severity") or "info"),
                    "tags": [x for x in [finding.get("owasp"), finding.get("tool")] if x],
                },
            }

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(str(finding.get("severity") or "info")),
            "message": {
                "text": (
                    f"{finding.get('title')}: {finding.get('evidence')} "
                    f"[validation={finding.get('validation_status')}]"
                )[:4000]
            },
            "properties": {
                "findingId": finding.get("id"),
                "severity": finding.get("severity"),
                "validationStatus": finding.get("validation_status"),
                "tool": finding.get("tool"),
                "owasp": finding.get("owasp"),
            },
        }
        location = str(finding.get("location") or "")
        if location:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": location}
                }
            }]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.get("agent_name") or "VibeAgent",
                    "informationUri": "https://github.com/Foxxed909/VibeAgent",
                    "rules": list(rule_map.values()),
                }
            },
            "results": results,
            "properties": {
                "jobId": report.get("job_id"),
                "agentMode": report.get("agent_mode") or "vibe",
            },
        }],
    }


def sarif_bytes(report: Dict[str, Any]) -> bytes:
    return json.dumps(sarif_dict(report), indent=2, ensure_ascii=False).encode("utf-8")
