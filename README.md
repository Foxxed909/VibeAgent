# VibeAgent

Affordable autonomous **authorized** security testing with two agent modes:

- **VibeAgent** — discovery/recon mode. Maps the authorized surface, follows evidence and chooses audit tools dynamically.
- **BreakAgent** — validation mode. Re-checks suspected weaknesses with a narrower evidence-focused tool policy.

Both modes share the same model layer, scope enforcement, SSE live thread, job persistence and reports.

## Product tiers

- **Hobby** — $50 / scan · exact URLs/hosts only (exact Vercel app hostnames supported) · private invite or API access token required
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

### Scan access

No invite/access code is embedded in the frontend or repository. Optional invite access uses only a server-side SHA-256 digest:

```bash
VIBE_AGENT_INVITE_CODE_SHA256=<64-character-sha256>
```

The raw code is compared server-side using a constant-time digest comparison. `VIBE_AGENT_TRIAL_CODE_SHA256` remains accepted as a legacy deployment alias.

Live scans fail closed unless either a valid private invite is submitted or an operator API token is configured and sent as `X-VibeAgent-Token` (or `Authorization: Bearer ...`):

```bash
VIBE_AGENT_API_TOKEN=<long-random-operator-token>
```

For an intentionally unauthenticated local demo, set `VIBE_AGENT_ALLOW_UNAUTHENTICATED_SCANS=1`. Do not set it on a public deployment.

### Model allowlist

API callers cannot select arbitrary provider models. Configure the exact permitted identifiers when overriding the built-in defaults:

```bash
VIBE_AGENT_ALLOWED_MODELS=gpt-6-luna,gpt-5.6-luna
```

### API origin boundary

Sensitive browser endpoints use same-origin CORS instead of `Access-Control-Allow-Origin: *`. Extra trusted origins can be configured explicitly:

```bash
VIBE_AGENT_ALLOWED_ORIGINS=https://admin.example.com
```

JSON request bodies default to a 16 KB maximum; `VIBE_AGENT_MAX_JSON_BODY_BYTES` can override that ceiling deliberately.

### Per-job cookies

Optional Cloudflare/session cookies are stored in a per-request `ContextVar`, not process-global environment state, so warm/concurrent workers cannot leak one scan's cookie into another.

### Target ownership

Every hosted live scan requires an exact HTTPS ownership proof at:

```text
/.well-known/vibeagent-verification.txt
```

The verification fetch refuses redirects and blocks loopback, private, link-local, reserved and cloud-metadata address ranges. The scan UI will not launch until ownership verification succeeds. Set `VIBE_AGENT_REQUIRE_OWNERSHIP=0` only for a deliberately isolated local runtime.

### Outbound request boundary

Portable probes accept HTTP(S) URLs only, reject embedded credentials, resolve each destination immediately before use, block non-global address classes, and refuse redirects. This keeps an exact authorized hostname from turning into a redirect-based or DNS-based internal-network request. A local-only scanner can opt into private targets with `VIBE_AGENT_ALLOW_PRIVATE_TARGETS=1`.

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
- wildcards and automatic subdomain expansion are not accepted by any execution backend;
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

Job IDs are high-entropy capability identifiers. Listing all jobs requires a separate operator token:

```bash
VIBE_AGENT_WORKSPACE_TOKEN=<long-random-workspace-token>
```

Enter that token on `/app`; it is retained only in the current browser tab.

## Deploy on Vercel

1. Import this repo into Vercel.
2. Framework: **Other**.
3. Set `OPENAI_API_KEY` and/or `OPENROUTER_API_KEY`.
4. Configure `VIBE_AGENT_INVITE_CODE_SHA256` and/or `VIBE_AGENT_API_TOKEN` for live-scan access.
5. Configure `VIBE_AGENT_WORKSPACE_TOKEN` for `/app` history access.
6. For durable jobs and waitlist entries, configure Vercel KV / Upstash REST variables.
7. Optionally configure `VIBE_AGENT_ALLOWED_MODELS` and the protected native worker variables above.
8. Deploy.

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
- [x] All live-scan target ownership verification
- [x] SSRF-resistant outbound address policy + redirect refusal
- [x] Scan, workspace and model-selection access boundaries
- [ ] Billing

Exact host declarations never authorize sibling or child subdomains; list every authorized hostname explicitly.

## Golden rule

Only test apps you own or have explicit authorization to test.
