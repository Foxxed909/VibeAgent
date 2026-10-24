"""POST /api/queue — enqueue an authorized scan or cancel it with a one-use capability."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.models import OpenRouterError, validate_requested_model
from agent.product import resolve_depth
from agent.queue_store import cancel, enqueue, require_queue, worker_online
from agent.scope import Authorization, ScopeError, normalize_target
from agent.target_verification import is_target_verified
from api._security import (
    apply_cors, parse_provider_keys, read_json_body,
    require_allowed_origin, require_scan_access,
)


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        if not require_allowed_origin(self):
            return
        self.send_response(204)
        apply_cors(self)
        self.end_headers()

    def do_POST(self):
        if not require_allowed_origin(self):
            return
        raw, error, status = read_json_body(self)
        if error:
            return self._json(status, {"ok": False, "error": error})
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._json(400, {"ok": False, "error": "invalid JSON"})
        if not isinstance(data, dict):
            return self._json(400, {"ok": False, "error": "JSON body must be an object"})

        try:
            require_queue()
        except RuntimeError as exc:
            return self._json(503, {"ok": False, "error": str(exc)})

        if data.get("action") == "cancel":
            job_id, token = data.get("job_id"), data.get("cancel_token")
            if not isinstance(job_id, str) or not isinstance(token, str):
                return self._json(400, {"ok": False, "error": "job_id and cancel_token required"})
            try:
                cancelled = cancel(job_id, token)
            except ValueError:
                cancelled = False
            return self._json(202 if cancelled else 403, {"ok": cancelled, "status": "cancellation_requested" if cancelled else "denied"})

        fields = ("tier", "confirmation", "app_name", "company_name", "model",
                  "depth", "agent_mode", "execution_backend", "access_code", "cookie")
        if any(data.get(k) is not None and not isinstance(data[k], str) for k in fields):
            return self._json(400, {"ok": False, "error": "text fields must be strings"})
        keys, key_error = parse_provider_keys(data)
        if key_error:
            return self._json(400, {"ok": False, "error": key_error})
        # Never escrow BYOK secrets or browser cookies in Redis / a queued task.
        if keys or data.get("cookie"):
            return self._json(400, {"ok": False, "error": "queued scans use worker environment credentials; provider_keys and cookies are not accepted"})
        if data.get("stress_multiplier") or data.get("dry_run"):
            return self._json(400, {"ok": False, "error": "queued stress mode and dry-run are not supported"})
        if not require_scan_access(self, data.get("access_code")):
            return
        try:
            if not worker_online():
                return self._json(503, {"ok": False, "error": "No durable scan worker is online. Start the worker before submitting queued scans."})
        except Exception:
            return self._json(503, {"ok": False, "error": "Worker availability could not be checked"})
        targets = data.get("targets") or []
        if isinstance(targets, str):
            targets = [x.strip() for x in targets.splitlines() if x.strip()]
        if not isinstance(targets, list) or not all(isinstance(x, str) for x in targets):
            return self._json(400, {"ok": False, "error": "targets must be a list of strings"})
        proofs = data.get("ownership_proofs") or {}
        if not isinstance(proofs, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in proofs.items()):
            return self._json(400, {"ok": False, "error": "ownership_proofs must be a string map"})
        proofs = {normalize_target(k): v for k, v in proofs.items() if normalize_target(k)}
        try:
            auth = Authorization(
                tier=(data.get("tier") or "hobby").lower(), targets=targets,
                confirmation=(data.get("confirmation") or "").strip(),
                app_name=data.get("app_name") or None, company_name=data.get("company_name") or None,
                access_code=data.get("access_code") or None,
            ).validated()
            if os.environ.get("VIBE_AGENT_REQUIRE_OWNERSHIP", "1").lower() not in {"0", "false", "no"}:
                if not all(is_target_verified(t, proofs.get(normalize_target(t))) for t in auth.targets):
                    raise ScopeError("Target ownership verification is required before a live scan")
            model = validate_requested_model(data.get("model") or None)
            depth = resolve_depth(auth.tier, data.get("depth"), auth.access_code)
            mode = data.get("agent_mode") or "vibe"
            if mode not in {"vibe", "break"}:
                raise ScopeError("agent_mode must be vibe or break")
            job_id, cancel_token = enqueue(
                auth, model=model, depth=depth, mode=mode,
                execution_backend=data.get("execution_backend") or "portable",
                ownership_proofs=proofs,
            )
            return self._json(202, {"ok": True, "job_id": job_id, "status": "queued", "cancel_token": cancel_token})
        except (ScopeError, OpenRouterError, ValueError) as exc:
            return self._json(400, {"ok": False, "error": str(exc)})
        except Exception:
            return self._json(503, {"ok": False, "error": "queue persistence failed; scan was not accepted"})

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
