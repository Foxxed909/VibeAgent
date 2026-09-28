# VibeAgent — In-depth codebase review

_Scope: `Foxxed909/VibeAgent` (full), with `Foxxed909/VibeHacking` read as reference.
Severity uses the same scale the product reports: **critical / high / medium / low / info**._

Both repositories are clearly framed for **authorized** testing of apps you own, and the
guardrails (confirmation phrase, exact-target scope, "don't bypass challenges", evidence-based
findings, redaction-by-default in VibeHacking) are real and thoughtful. This review is about
tightening the product before it takes money and real traffic — nothing here questions the
legitimacy of the use case.

---

## 1. Contradictions, detangled

The task asked me to surface and explain contradictions. Here are the ones that matter.

### C1 — "Exact targets you own" vs. Hobby scope allows *any* `*.vercel.app` — **high**
The landing copy says "Point it at apps **you own**" and "exact targets only", but
`agent/scope.py:is_hobby_allowed` returns `True` for **any** `something.vercel.app` host, and
`host_in_scope` treats `*.vercel.app` as in-scope. Ownership is never verified — the only gate is
the self-typed confirmation phrase (honour system). So a Hobby user can point the agent (and the
stress tool) at *anyone's* Vercel app.
**Detangle:** the confirmation phrase is a legal/consent gate, not a technical one. Either (a) drop
the blanket `*.vercel.app` allowance and require exact hosts, or (b) add a lightweight ownership
proof for vercel.app subdomains (a DNS TXT record, a `/.well-known/vibeagent-<token>` file, or a
Vercel OAuth check) before any request leaves. Until then the marketing overstates the control.

### C2 — Models `gpt-6-luna` / `gpt-5.6-luna` don't exist at the real OpenAI endpoint — **high**
`agent/openai_client.py` hardcodes `gpt-6-luna` and posts to `https://api.openai.com/v1/chat/completions`.
Those model IDs are fictional; a real key will get an HTTP 404 `model_not_found`. The README and UI
present them as the default engine.
**Detangle:** this is a demo/placeholder engine. Make it explicit: default to a real model
(or the OpenRouter free models, which *are* real) and treat the "Luna" IDs as an opt-in via
`VIBEAGENT_MODEL`. Also, `reasoning_effort` is sent on Chat Completions for every request; real
reasoning models expect it via the Responses API and standard chat models reject unknown params —
gate it by model.

### C3 — "$50 / scan", "$200 / scan" but nothing charges — **medium**
There is no billing anywhere (`README` lists "Billing" as unchecked, correctly). The price is copy
only. That's fine for an MVP, but combined with C1 it means *anyone* can run paid-tier work for free
against a broad target set. Flagging so the pricing page isn't mistaken for an enforced gate.

### C4 — Trial code marked "keep in sync with scan.html" — a secret shipped in the client — **critical**
See S1. A shared secret cannot be both "in the client" and a secret. Resolved in this PR.

### C5 — `requirements.txt` says "no deps" and that's true — **info, not a contradiction**
Stdlib-only is real and consistent across both repos. Good. Keep it.

---

## 2. Security findings

### S1 — Trial access code exposed in the client (and hardcoded in source) — **critical** ✅ fixed
`scan.html` *displayed* the working code in a `.trial-box`, embedded it as a JS constant, and
`agent/scope.py` hardcoded the same literal. Anyone viewing source got free Hobby scans. The string
also contained `GROKJAILEDBROKE`, which reads as jailbreak branding on a product whose whole pitch is
"authorized only".
**Fix (done):** `scope.py` now reads `VIBEAGENT_TRIAL_CODE` from the environment, compares with
`hmac.compare_digest` (constant-time), and treats an unset value as "trials disabled". The client no
longer displays or knows the code — it sends whatever the user types and the server decides.
**Operator action:** set `VIBEAGENT_TRIAL_CODE` in Vercel → Settings → Environment Variables, and
rotate the old code (it is burned).

### S2 — No auth or rate limiting on `/api/scan` and `/api/stream` — **high**
Both endpoints run the full agent (outbound traffic + LLM spend) for any anonymous caller, with
`Access-Control-Allow-Origin: *`. Combined with C1, this is an open relay for scanning/stressing any
`*.vercel.app`. **Fix:** require a per-request token (even a signed nonce minted server-side after a
lightweight check), lock CORS to your own origin, and add a per-IP + per-target rate limit (Upstash
Redis is already a dependency-free option via the KV code you have).

### S3 — Cross-request cookie leak via `os.environ` — **high**
`orchestrator.run_job` does `os.environ["VIBEAGENT_COOKIE"] = cookie` and `http_tools._extra_headers`
reads it back. On a warm serverless instance, two overlapping invocations share the process, so user
A's Cloudflare `cf_clearance` cookie can be attached to user B's requests.
**Fix (recommended, not yet applied — needs a small signature change):** thread `cookie` through
`_dispatch_tool → run_builtin → tool_*` explicitly and delete the `os.environ` path. As a stop-gap,
wrap `run_job` in `try/finally` and `os.environ.pop("VIBEAGENT_COOKIE", None)` — but that still races
under concurrency, so the explicit thread-through is the real fix.

### S4 — Client-controlled `model` string forwarded to the provider — **medium**
`api/scan.py` / `api/stream.py` pass `data.get("model")` straight to OpenAI/OpenRouter. A caller can
select arbitrary (expensive) models. **Fix:** allowlist model IDs server-side; reject anything else.

### S5 — Unbounded request body read into memory — **low**
Every handler does `self.rfile.read(int(Content-Length))` with no cap. A large `Content-Length` is a
cheap memory-pressure vector. **Fix:** cap at, say, 64 KB and reject larger.

### S6 — SSRF-shaped surface is inherent to the product — **info (by design, keep watching)**
The whole app makes server-side requests to user-supplied URLs. Scope enforcement is the mitigation
and it's reasonable, but note that `host_in_scope` resolves by hostname string, not by resolved IP —
a hostname in scope that resolves to `169.254.169.254` or an internal address would still be fetched.
**Fix:** after DNS resolution, block link-local / RFC-1918 / metadata IPs unless the tier explicitly
allows private ranges (Enterprise CIDR mode).

---

## 3. Correctness & code-quality findings

### Q1 — `_parse_api_hits` was structurally broken — **medium** ✅ fixed
The function had a block of redundant `"→" not in line` self-comparisons and dead `if/elif` branches
that did nothing; it "worked" only by luck of later reassignment. Rewritten to a clear
arrow-detection loop (`agent/orchestrator.py`).

### Q2 — Duplicated `save_job` / `load_job` — **low**
`orchestrator.py` re-exports thin wrappers around `job_store.*` that nothing uses (the API imports
from `job_store` directly). Remove the wrappers to avoid drift.

### Q3 — `resolve_stress` has an unreachable branch — **low**
In `agent/product.py`, the final `elif m not in allowed:` is inside `if m not in allowed:`, so it's
always true and never distinct from the `else`. Simplify to a clear clamp table.

### Q4 — Ephemeral job store on serverless — **medium (known)**
`job_store` falls back to `/tmp`, which doesn't survive cold starts on Vercel, so `/api/job?id=` 404s
across instances. The client leans on `sessionStorage`, which is per-tab. **Fix:** make Vercel KV /
Upstash the default in production and document it as required for shareable job links.

### Q5 — SSE via `BaseHTTPRequestHandler` may not truly stream on Vercel — **medium**
Vercel's Python runtime often buffers the response, so `/api/stream` can deliver everything at once
after `run_job` finishes. The thread's fallback to `/api/scan` is good defensive design, but the
"live" promise may silently degrade. **Fix:** verify streaming on the target runtime; if buffered,
consider chunked polling of a KV-backed event log instead.

### Q6 — `temperature` sent alongside reasoning params — **low**
Some reasoning models reject `temperature`. Gate per model (see C2).

### Q7 — Tests exist in VibeHacking, none in VibeAgent — **medium**
VibeHacking ships a real stdlib smoke test (compile-check + CLI sweep + version single-source). VibeAgent
has none. **Fix:** add a parallel `tests/smoke_test.py` that compile-checks `agent/` + `api/`, unit-tests
`scope.normalize_target` / `is_hobby_allowed` / `host_in_scope`, `product.resolve_depth/resolve_stress`,
and `_parse_api_hits`. These are pure functions — cheap, high-value coverage, and they lock in the
scope rules that everything else trusts.

---

## 4. UX & product findings (addressed by the redesign)

- **U1 (fixed):** the old UI is the exact AI-default look the design guidance warns against
  (near-black + acid-green pop). Redesigned into a distinctive "evidence dossier" system with full
  light **and** dark themes and a shared token stylesheet.
- **U2 (fixed):** trial code was printed on the page. Removed.
- **U3 (fixed):** the scan form gave no feedback on whether a target was in scope until submit. The
  new console shows a live per-target **scope check** and a **This run** summary.
- **U4 (fixed):** duplicated inline CSS across three pages → one `assets/theme.css`.
- **U5 (fixed):** the landing had no example of *output*. The hero now shows a real sample finding so
  visitors see what they get.
- **U6 (open):** the waitlist "saved locally" fallback message was misleading (nothing was saved).
  Reworded to an honest error.

---

## 5. What changed in this PR

**Redesign (UI/UX):**
- `assets/theme.css` — new shared design system: tokens, light + dark themes, buttons, nav, chips,
  severity scale, cards, footer.
- `index.html` — rebuilt landing: dossier hero with a live sample finding, golden-rule contract strip,
  4-step process ledger, coverage grid, two-tier pricing, scope rules, honest waitlist, theme toggle.
- `scan.html` — rebuilt scan console: tier toggle, sectioned form, live scope check + run summary,
  no exposed secret, server-authoritative depth/stress.
- `thread.html` — restyled live transcript with severity-aware finding cards; SSE logic unchanged.

**Security / correctness:**
- `agent/scope.py` — trial code moved to `VIBEAGENT_TRIAL_CODE` env with constant-time compare (S1/C4).
- `agent/orchestrator.py` — `_parse_api_hits` rewritten (Q1).

Everything else above is documented here rather than changed, to keep this diff reviewable.

---

## 6. New tool ideas (agent tool surface)

VibeAgent currently exposes 5 built-ins (`ash, vibe_headers, ghost, api_finder, senoria`) but
VibeHacking has ~40. High-value additions to wire in next, in rough priority:

1. **`corscan`** — CORS misconfig (reflected origins, credentialed wildcards). Common on APIs, easy win.
2. **`phantom`** — cookie/session flag auditor (HttpOnly / Secure / SameSite). Cheap, high signal.
3. **`redirect`** — open-redirect scanner. Fast, low-noise, real finding.
4. **`exploit_final`** — reflected/stored XSS confirmer (canary in, read it back unescaped). Evidence-first, fits the "must beat a baseline" ethos.
5. **`traversal_sniper`** — path traversal / LFI for `.env` and config.
6. **`prompt_injector`** — LLM prompt-injection suite for `/api/chat`-style endpoints (very on-brand for the "vibe-coded app" audience).
7. **`ssrf_probe`** — SSRF via instruct/computer-use endpoints (pair with S6 IP guardrails).

Guardrail note: VibeHacking's own CATALOG flags that `aukdoc`/`cloud_scout`/`vibe_headers` over-report
(e.g. any 200 as a "breach", HSTS-on-loopback as critical). Port the evidence-gating the built-ins
already do (baseline control, non-challenge only) to each new tool before exposing it.

---

## 7. New product ideas

- **Ownership verification** for `*.vercel.app` (TXT record or `/.well-known` token) — turns the honour
  system into a real gate and unlocks safe self-serve.
- **Re-scan diff** — store findings per target, show "3 new, 1 fixed, 2 regressed" between runs. This is
  the feature that makes it a recurring purchase instead of a one-off.
- **Continuous mode** — scheduled scans + alert on new critical (the README already hints at this).
- **Shareable report links** — needs KV (Q4); a signed, read-only `/r/<job>` page is a natural upsell.
- **PR / CI integration** — a GitHub Action that runs a Hobby scan against a preview deploy and comments
  findings. The audience already lives on Vercel preview URLs.
- **"Fix-it" hints** — each finding already has a fix hint; render copy-paste remediation (a CSP header,
  a cookie flag) so the loop closes inside the product.

---

## 8. Ten next steps (prioritized)

1. **Rotate + set `VIBEAGENT_TRIAL_CODE`** in the environment (the old code is burned). — done in code, needs deploy config.
2. **Gate `/api/scan` + `/api/stream`** with a server-minted token and per-IP/target rate limits; lock CORS to your origin. (S2)
3. **Decide the default model.** Point the default at a real model (or the OpenRouter free set) and treat "Luna" as opt-in; gate `reasoning_effort`/`temperature` by model. (C2)
4. **Thread the cookie through call args** and delete the `os.environ` path. (S3)
5. **Add ownership verification** for vercel.app subdomains, or drop the blanket `*.vercel.app` allowance. (C1)
6. **Add SSRF IP guardrails** — block link-local/RFC-1918/metadata IPs post-resolution unless the tier allows it. (S6)
7. **Make KV the production default** for the job store and document it; ship signed shareable report links. (Q4)
8. **Add `tests/smoke_test.py`** covering scope + product + parser pure functions, and run it in CI. (Q7)
9. **Verify SSE actually streams** on Vercel; if not, back the thread with a KV event log + polling. (Q5)
10. **Wire in the next tools** (`corscan`, `phantom`, `redirect`, `exploit_final`) with the same evidence-gating, and build the **re-scan diff** to make it a recurring product. (§6, §7)

---

_Reviewed against the repositories as checked out on the review branch. Items marked ✅ are applied in
this change; everything else is documented for follow-up rather than changed, to keep the diff focused._
