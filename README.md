# VibeAgent

Affordable autonomous **authorized** security testing with two agent modes:

- **VibeAgent** — discovery/recon mode. Maps the authorized surface, follows evidence and chooses audit tools dynamically.
- **BreakAgent** — validation mode. Re-checks suspected weaknesses with a narrower evidence-focused tool policy.

Both modes share the same model layer, scope enforcement, SSE live thread, job persistence and reports.

## Product tiers

- **Hobby** — $50 / scan · exact URLs + `*.vercel.app` only · optional private invite support
- **Enterprise** — $200 / scan · hosts, URLs, IP ranges

Powered by [VibeHacking](https://github.com/Foxxed909/VibeHacking) tools. Agents only operate against targets the user declares and confirms.

## Agent policies

### VibeAgent

Portable/serverless tools include cloud scouting, perimeter recon, same-origin spidering, OpenAPI discovery, security-header checks, CORS, session/cookie checks, authorization-boundary checks, environment/config exposure checks, sensitive-asset discovery, API discovery and redacted secret-marker scanning.

When `VIBEHACKING_ROOT` points to a native VibeHacking checkout, additional native capabilities may be exposed.

### BreakAgent

BreakAgent is intentionally validation-focused. Its default tool policy emphasizes headers, CORS, session policy, authorization boundaries, config/schema exposure, API discovery and secret-marker confirmation.

It does **not** receive the native challenge-bypass tool. On a native VibeHacking runtime it may receive the benign `poc_gen` verifier. Stress/load mode is disabled for BreakAgent.

## Live thread

Start from `/scan`, choose VibeAgent or BreakAgent, and the app opens `/thread?live=1`. Tool calls, findings, model information and the final report stream into the same thread UI.

## CLI

The confirmation phrase is required explicitly:

```text
I OWN OR AM AUTHORIZED TO TEST THESE TARGETS
```

Dry-run VibeAgent:

```bash
python -m agent.cli \
  --agent vibe \
  --tier hobby \
  --target https://my-app.vercel.app \
  --app-name MyApp \
  --confirm 'I OWN OR AM AUTHORIZED TO TEST THESE TARGETS' \
  --dry-run
```

Run BreakAgent:

```bash
export OPENAI_API_KEY=sk-...
python -m agent.cli \
  --agent break \
  --tier hobby \
  --target https://my-app.vercel.app \
  --app-name MyApp \
  --confirm 'I OWN OR AM AUTHORIZED TO TEST THESE TARGETS' \
  --save
```

To expose native VibeHacking capabilities:

```bash
export VIBEHACKING_ROOT=/path/to/VibeHacking
```

## Security hardening

### Private invite codes

No invite/access code is embedded in the frontend or repository. If private invite access is needed, configure only the SHA-256 digest server-side:

```bash
VIBE_AGENT_INVITE_CODE_SHA256=<64-character-sha256>
```

The raw code is entered by the user and compared server-side using a constant-time digest comparison. The older `VIBE_AGENT_TRIAL_CODE_SHA256` name remains accepted for deployment compatibility.

### API origin boundary

Sensitive browser endpoints use same-origin CORS rather than `Access-Control-Allow-Origin: *`. Optional additional trusted browser origins can be configured with:

```bash
VIBE_AGENT_ALLOWED_ORIGINS=https://admin.example.com
```

JSON request bodies are capped (16 KB by default) with `VIBE_AGENT_MAX_JSON_BODY_BYTES` available for controlled overrides.

### Per-job cookies

Optional Cloudflare/session cookies are carried in a per-request `ContextVar`, not process-global environment state, so a warm worker cannot leak one job's cookie into another job.

## Native VibeHacking worker

Portable mode is the default. To make the full persistent VibeHacking worker available to the standalone app, configure all of these server-side variables:

```bash
VIBE_AGENT_WORKER_URL=https://worker.example.com
VIBE_AGENT_WORKER_TOKEN=<at-least-32-random-characters>
VIBE_AGENT_WORKER_ALLOWED_HOSTS=app.example.com,api.example.com
VIBE_AGENT_WORKER_MODEL=laguna-s-2.1
```

The native bridge is fail-closed:

- the worker URL must be HTTPS with no embedded credentials, path, query or fragment;
- the token must be at least 32 characters;
- targets must match an **exact hostname** in `VIBE_AGENT_WORKER_ALLOWED_HOSTS`;
- wildcards and subdomain expansion are not accepted;
- native jobs currently run one target per job;
- every native target must pass a one-time HTTPS ownership challenge at `/.well-known/vibeagent-verification.txt`;
- ownership challenges are available only for already-allowlisted hosts;
- worker redirects are refused so the worker token is never forwarded to another origin;
- worker findings are filtered back to the exact target hostname before they enter the standalone report.

Native BreakAgent is disabled by default because the upstream BreakAgent pipeline is more invasive. An operator who has separately verified and allowlisted the target must explicitly opt in:

```bash
VIBE_AGENT_ENABLE_NATIVE_BREAKAGENT=1
```

The scan form queries `/api/capabilities` and only enables the native option when the exact target is allowlisted, ownership-verified, and permitted for the selected agent mode. The verification flow is exposed at `POST /api/verify_target`. For reliable verification state on serverless deployments, configure Vercel KV / Upstash.

## Deploy on Vercel

1. Import this repo into Vercel.
2. Framework: **Other**.
3. Set `OPENAI_API_KEY` and/or `OPENROUTER_API_KEY`.
4. For durable jobs and waitlist entries, configure Vercel KV / Upstash REST variables.
5. Optionally configure the protected native worker variables above.
6. Deploy.

## Status

- [x] Landing page
- [x] Authorization form
- [x] Dynamic multi-round VibeAgent orchestrator
- [x] BreakAgent validation mode
- [x] Expanded portable VibeAgent tool surface
- [x] Agent-specific tool policies
- [x] OpenAI + OpenRouter model paths
- [x] Live SSE thread UI with agent identity
- [x] Canonical structured findings with validation status, CWE/OWASP, evidence and remediation
- [x] JSON + SARIF 2.1.0 report exports
- [x] Protected native VibeHacking worker backend with exact-host allowlist
- [x] `/api/scan`, `/api/stream`, `/api/job`, `/api/report`, `/api/capabilities`, `/api/verify_target`
- [x] Persistent cloud job store via Vercel KV / Upstash when configured
- [x] Waitlist persistence via KV / Upstash when configured
- [x] Server-side hashed private invite validation
- [x] Per-job cookie isolation
- [x] Same-origin sensitive API boundary + request-size limits
- [x] Native target ownership verification
- [ ] Billing

## Golden rule

Only test apps you own or have explicit authorization to test.
