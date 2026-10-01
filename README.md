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

No invite/access code is embedded in the frontend or repository. Optional invite access uses only a server-side SHA-256 digest:

```bash
VIBE_AGENT_TRIAL_CODE_SHA256=<64-character-sha256>
```

The raw code is compared server-side using a constant-time digest comparison.

### API origin boundary

Sensitive browser endpoints use same-origin CORS instead of `Access-Control-Allow-Origin: *`. Extra trusted origins can be configured explicitly:

```bash
VIBE_AGENT_ALLOWED_ORIGINS=https://admin.example.com
```

JSON request bodies default to a 16 KB maximum; `VIBE_AGENT_MAX_JSON_BODY_BYTES` can override that ceiling deliberately.

### Per-job cookies

Optional Cloudflare/session cookies are stored in a per-request `ContextVar`, not process-global environment state, so warm/concurrent workers cannot leak one scan's cookie into another.

### Worker target ownership

Worker-backed execution requires an exact HTTPS ownership proof at:

```text
/.well-known/vibeagent-verification.txt
```

The verification API only operates on hosts already present in the standalone worker allowlist, and the scan UI will not enable worker-tools until both allowlisting and ownership verification succeed.

## Persistent VibeHacking worker

Portable mode is the default. The recommended native path is **worker-tools**:
the standalone VibeAgent/BreakAgent LLM loop stays in control, while compatible
bounded audit tools execute on the persistent VibeHacking runtime.

Configure the standalone app:

```bash
VIBE_AGENT_WORKER_URL=https://worker.example.com
VIBE_AGENT_WORKER_TOKEN=<at-least-32-random-characters>
VIBE_AGENT_WORKER_ALLOWED_HOSTS=app.example.com,api.example.com
```

Configure the VibeHacking worker with the same token and an independent exact-host
allowlist:

```bash
VIBE_WORKER_TOKEN=<same-token>
VIBE_WORKER_ALLOWED_HOSTS=app.example.com,api.example.com
python TOOLS/live_dashboard.py --host 0.0.0.0 --port 8080
```

The worker-tools bridge is fail-closed:

- the standalone worker URL must be HTTPS with no embedded credentials, path, query or fragment;
- the token must be at least 32 characters;
- both the standalone app **and** VibeHacking worker independently enforce exact hostnames;
- worker-backed targets also require the one-time `/.well-known/vibeagent-verification.txt` proof;
- wildcards and automatic subdomain expansion are not accepted;
- redirects are refused so the worker token is never forwarded to another origin;
- only the worker's defensive audit allowlist is exposed remotely;
- challenge-bypass, WAF-evasion, JWT-forging, exploit and load/stress tools are not exposed by worker-tools;
- each remote tool call uses isolated VibeHacking artifacts and returns redacted structured findings;
- if an individual remote tool call fails, the autonomous scan can fall back to its bounded portable implementation.

The older `native-worker` whole-agent delegation backend remains available to
operators through the CLI/API for compatibility, but it is not the normal scan
UI path. Native BreakAgent whole-agent delegation remains separately gated by
`VIBE_AGENT_ENABLE_NATIVE_BREAKAGENT=1`.

The scan form queries `/api/capabilities` and only enables worker-tools when the
exact target passes both allowlists, ownership verification succeeds, and the worker advertises its
protected remote audit bridge. Challenge creation/confirmation is exposed through
`POST /api/verify_target`. Configure Vercel KV / Upstash for reliable verification state on serverless deployments.

## Workspace

Open `/app` for the persisted security workspace:

- **Runs** — recent VibeAgent / BreakAgent jobs, backend, depth and finding counts
- **Findings** — aggregated structured findings across recent jobs
- **Reports** — direct JSON / SARIF downloads and thread links

The workspace is backed by `GET /api/jobs?include=findings`. KV / Upstash is recommended so history survives serverless instance rotation.

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
- [x] Autonomous VibeHacking worker-tools backend with dual exact-host allowlists
- [x] `/api/scan`, `/api/stream`, `/api/job`, `/api/report`, `/api/capabilities`
- [x] Persistent cloud job store via Vercel KV / Upstash when configured
- [x] Waitlist persistence via KV / Upstash when configured
- [x] Runs / Findings / Reports workspace
- [x] Server-side hashed private invite validation
- [x] Per-job cookie isolation
- [x] Same-origin sensitive API boundary + request-size limits
- [x] Worker target ownership verification
- [ ] Billing

## Golden rule

Only test apps you own or have explicit authorization to test.
