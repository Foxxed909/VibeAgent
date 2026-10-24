"""POST /api/scan — create job, run orchestrator, return job_id + report."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.scope import Authorization, ScopeError, normalize_target
from agent.models import OpenRouterError, validate_requested_model
from agent.orchestrator import run_job
from agent.job_store import save_job, backend_name
from agent.product import resolve_depth, resolve_stress
from agent.target_verification import is_target_verified
from api._security import apply_cors, read_json_body, require_allowed_origin, require_scan_access


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not require_allowed_origin(self):
            return
        raw, error, code = read_json_body(self)
        if error:
            return self._json(code, {"ok": False, "error": error})
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._json(400, {"ok": False, "error": "invalid JSON"})
        if not isinstance(data, dict):
            return self._json(400, {"ok": False, "error": "JSON body must be an object"})
        text_fields = (
            "tier", "confirmation", "app_name", "company_name", "contact_email",
            "emergency_contact", "note", "access_code", "model", "depth",
            "stress_mode", "cookie", "agent_mode", "execution_backend",
        )
        if any(data.get(key) is not None and not isinstance(data.get(key), str) for key in text_fields):
            return self._json(400, {"ok": False, "error": "text fields must contain strings"})

        targets = data.get("targets") or []
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.splitlines() if t.strip()]
        if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
            return self._json(400, {"ok": False, "error": "targets must be a string or list of strings"})
        ownership_proofs = data.get("ownership_proofs") or {}
        if not isinstance(ownership_proofs, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in ownership_proofs.items()
        ):
            return self._json(400, {"ok": False, "error": "ownership_proofs must be a string map"})
        ownership_proofs = {
            normalize_target(key): value
            for key, value in ownership_proofs.items()
            if normalize_target(key)
        }

        auth = Authorization(
            tier=(data.get("tier") or "hobby").lower(),
            targets=targets,
            confirmation=(data.get("confirmation") or "").strip(),
            app_name=data.get("app_name") or None,
            company_name=data.get("company_name") or None,
            contact_email=data.get("contact_email") or None,
            emergency_contact=data.get("emergency_contact") or None,
            note=data.get("note") or None,
            access_code=data.get("access_code") or None,
        )
        dry = bool(data.get("dry_run"))
        if not dry and not require_scan_access(self, data.get("access_code")):
            return
        try:
            model = validate_requested_model(data.get("model") or None)
        except OpenRouterError as exc:
            return self._json(400, {"ok": False, "error": str(exc)})
        depth = resolve_depth(auth.tier, data.get("depth"), auth.access_code)
        stress_m, stress_mode = resolve_stress(
            auth.tier, auth.access_code, data.get("stress_multiplier"), data.get("stress_mode")
        )
        cookie = (data.get("cookie") or "").strip() or None
        agent_mode = data.get("agent_mode") or "vibe"
        execution_backend = data.get("execution_backend") or "portable"

        try:
            if not dry and (os.environ.get("VIBE_AGENT_REQUIRE_OWNERSHIP", "1").strip().lower() not in {"0", "false", "no"}):
                unverified = [
                    target for target in targets
                    if not is_target_verified(target, ownership_proofs.get(normalize_target(target)))
                ]
                if unverified:
                    raise ScopeError("Target ownership verification is required before a live scan.")
            report = run_job(
                auth,
                dry_run=dry,
                model=model,
                depth=depth,
                stress_multiplier=stress_m,
                stress_mode=stress_mode,
                cookie=cookie,
                agent_mode=agent_mode,
                execution_backend=execution_backend,
                ownership_proofs=ownership_proofs,
            )
            try:
                save_job(report)
            except Exception:
                pass
            return self._json(200, {
                "ok": True,
                "job_id": report.get("job_id"),
                "report": report,
                "store": backend_name(),
            })
        except ScopeError as e:
            return self._json(403, {"ok": False, "error": str(e)})
        except Exception:
            return self._json(500, {"ok": False, "error": "scan failed"})

    def do_OPTIONS(self):
        if not require_allowed_origin(self):
            return
        self.send_response(204)
        apply_cors(self)
        self.end_headers()

    def _json(self, code, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        apply_cors(self)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return
