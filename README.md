# VibeAgent

Affordable autonomous **authorized** security testing with two agent modes:

- **VibeAgent** — discovery/recon mode. Maps the authorized surface, follows evidence and chooses audit tools dynamically.
- **BreakAgent** — validation mode. Re-checks suspected weaknesses with a narrower evidence-focused tool policy.

Both modes share the same model layer, scope enforcement, SSE live thread, job persistence and reports.

The quality loop is bounded and evidence-led: deterministic baseline, model-guided investigation, exact-duplicate suppression, reproducibility review of material findings, optional independent review, then final synthesis. Tool, round, retry and retest budgets are fixed by the selected depth profile. Repeating heuristic evidence alone cannot confirm exploitability. Interrupted model investigations return partial or failed statuses rather than unconditional completion.

## Product tiers

- **Hobby** — $50 / scan · exact URLs/hosts only (exact Vercel app hostnames supported) · private invite or API access token required
- **Enterprise** — $200 / scan · hosts, URLs, IP ranges

Powered by [VibeHacking](https://github.com/Foxxed909/VibeHacking) tools. Agents only operate against targets the user declares and confirms.

## Agent policies

### VibeAgent

Portable/serverless tools now include 16 bounded checks: cloud scouting, perimeter recon, same-origin spidering, OpenAPI discovery, security headers, CORS, session/cookie policy, authorization boundaries, configuration exposure, sensitive assets, API discovery, redacted secret markers, single-endpoint diagnostics, passive Next.js/RSC mapping, canary-based redirect checks and candidate private-route cache observations.

The passive Next.js/RSC and cache checks are deliberately observational. They do not claim middleware bypass, RSC data leakage, or exploitability without specific evidence. The native VibeHacking checkout remains the source of deeper platform-specific tools.

When `VIBEHACKING_ROOT` points to a native VibeHacking checkout, additional specialist auditors are available: `aukdoc`, `axios`, `smuggle_probe`, `header_inject`, and `biz_logic`. These tools require the local VibeHacking scripts and are not exposed through the default hosted worker bridge.

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
VIBE_AGENT_ALLOWED_MODELS=gpt-6-luna,openai/gpt-6-luna,google/gemini-3-flash
```

Exact `provider/model` IDs route through Vercel AI Gateway. Vercel deployments use the injected `VERCEL_OIDC_TOKEN`; local or non-Vercel runtimes can set `AI_GATEWAY_API_KEY`. Provider keys are never passed to browser code or scan tools.

Use GPT-6 Luna or GPT-5.6 Luna as the main VibeAgent planner and optionally configure an independent evidence reviewer. The agent instructions require hypothesis-driven, attacker-style threat reasoning and explicit disconfirmation of weak findings. Tool-calling compatibility retains the provider-required effort setting, while text-only synthesis/review requests a higher reasoning effort where supported; adjust with `VIBE_AGENT_ANALYSIS_EFFORT=none|low|medium|high` (default `high`).

To configure Google as the independent evidence reviewer:

```bash
VIBEAGENT_MODEL=gpt-6-luna
VIBE_AGENT_REVIEW_MODEL=google/gemini-3-flash
VIBE_AGENT_ALLOWED_MODELS=gpt-6-luna,google/gemini-3-flash
```

The local CLI also supports OpenAI's documented open-source Sign in with ChatGPT flow. It uses the public Responses API with the signed-in user's own consent and stores its rotating OAuth credentials only on that device. This local flow is not used by Vercel. The remotely hosted Vercel app still uses user-supplied API keys or Gateway credentials unless OpenAI approves the commercial partner integration. Google consumer subscriptions likewise are not stored or scraped; Google models are reached through AI Gateway or a supported provider API.

### NVIDIA Nemotron 3 Ultra 550B (OpenRouter Free or NVIDIA NIM)

Nemotron 3 Ultra is selectable in the scan form and is the **default
new-scan model**. It is supported in both discovery (VibeAgent) and validation
(BreakAgent) modes with the existing scope, ownership verification and tool
allowlists. The agent receives explicit instructions for red-team hypothesis
formation, attack-path prioritization, negative controls, evidence-only
validation and precise remediation. This is an *authorized* testing agent,
not a claim that every security weakness is exploitable.

**Option A — OpenRouter free endpoint**:

- Model: \`nvidia/nemotron-3-ultra-550b-a55b:free\`
- Key: \`OPENROUTER_API_KEY\` in a trusted environment, or fill the
  OpenRouter API key field on the scan form.
- HTTP API: \`https://openrouter.ai/api/v1/chat/completions\`.

**Option B — NVIDIA Build/NIM**:

- Model: \`nvidia/nemotron-3-ultra-550b-a55b\` (no \`:free\` suffix).
- Key: \`NVIDIA_API_KEY\` in a trusted environment, or fill the
  NVIDIA API key field on the scan form.
- HTTP API: \`https://integrate.api.nvidia.com/v1/chat/completions\`.

Selecting the \`:free\` model with **only a NVIDIA key** also routes to
NVIDIA NIM with the unsuffixed model ID. If an OpenRouter key is present,
the \`:free\` request goes to OpenRouter. Explicit unsuffixed NVIDIA
selection always uses NVIDIA and does not silently spend OpenRouter paid
credits. API keys are request-scoped and are never persisted in the scan
report; queued scans accept **no BYOK secrets** and instead use the worker
environment's key. Do not confuse a free API endpoint with unlimited
capacity: it can be rate-limited or unavailable.

To make Nemotron the CLI/server default **once a provider key is configured**:

\`\`\`bash
export VIBEAGENT_MODEL='nvidia/nemotron-3-ultra-550b-a55b:free'
export OPENROUTER_API_KEY='YOUR_OPENROUTER_KEY'
# or: export NVIDIA_API_KEY='YOUR_NVIDIA_KEY'
python -m agent.cli --model nvidia/nemotron-3-ultra-550b-a55b:free \
  --tier hobby --target https://your-owned-app.example \
  --app-name Demo --confirm 'I OWN OR AM AUTHORIZED TO TEST THESE TARGETS'
\`\`\`

If \`VIBE_AGENT_ALLOWED_MODELS\` is explicitly configured, include the exact
Nemotron ID(s) in that allowlist:

\`\`\`text
VIBE_AGENT_ALLOWED_MODELS=gpt-6-luna,google/gemini-3-flash,nvidia/nemotron-3-ultra-550b-a55b:free,nvidia/nemotron-3-ultra-550b-a55b
\`\`\`

For direct NVIDIA NIM, its model options enable the model's supported
reasoning mode. OpenRouter requests enable reasoning for the free Nemotron
model. Nemotron investigations and synthesis get a higher output-token
budget to allow deeper analysis; deterministic tool-call limits remain in
force.

**Important data-handling caveat:** OpenRouter's free Nemotron endpoint
warns against submitting confidential information or personal data, and
says requests may be logged. Do not use it to transmit secrets, private
vulnerability evidence, customer data, or sensitive targets. Consider
provider terms and organizational data-handling policies before scanning.
Free-model availability, tool-call behavior and provider quotas are not
guaranteed. Provider routing and unit tests do not prove a live model run.

### ChatGPT plan usage in the local CLI

Sign in on the device that will run VibeAgent:

```bash
python -m agent.cli auth login
python -m agent.cli auth models
```

Then choose an account-available model and run the local agent:

```bash
python -m agent.cli --chatgpt-plan \
  --model gpt-6-luna \
  --tier hobby \
  --target https://my-app.vercel.app \
  --app-name MyApp \
  --confirm 'I OWN OR AM AUTHORIZED TO TEST THESE TARGETS'
```

The sign-in callback binds to `127.0.0.1`. Credentials are kept in `~/.config/vibeagent/chatgpt_auth.json` with owner-only file permissions; `VIBEAGENT_CHATGPT_AUTH_FILE` can select another local path. Use `python -m agent.cli auth logout` to remove them. This feature is local CLI only; it does not enable subscription access on the hosted site.

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

On serverless deployments, set a strong signing key so challenges and short-lived host-bound proof receipts are stateless and survive instance rotation:

```bash
VIBE_AGENT_VERIFICATION_SECRET=<at-least-32-random-characters>
```

Proof receipts are scoped to one exact hostname, expire automatically, and are held in browser session storage. If the signing key is absent, the legacy KV/local state flow remains available.

### Outbound request boundary

Portable probes accept HTTP(S) URLs only, reject embedded credentials, resolve each destination immediately before use, block non-global address classes, and refuse redirects. This keeps an exact authorized hostname from turning into a redirect-based or DNS-based internal-network request. A local-only scanner can opt into private targets with `VIBE_AGENT_ALLOW_PRIVATE_TARGETS=1`.

## Durable background scan queue (opt-in)

The app now has two independent scan transports:

- **Durable queued mode**: asynchronous, resumable progress and safe cancellation
  checkpoints, backed by a separately hosted continuous worker and Redis/Upstash.
  No browser API keys, cookies, invite codes or raw cancellation tokens are
  persisted in queue task records.
- **Legacy live stream**: synchronous request-scoped assessments with BYOK;
  still subject to Vercel function timeouts and not resumable.

Queued API workflow:

1. POST /api/queue to submit (HTTP 202 returns job_id and a private cancel token).
2. GET /api/events?id=JOB_ID&after=0-0 to replay progress with cursor paging.
3. GET /api/job?id=JOB_ID for a completed report.
4. POST /api/queue with action=cancel, job_id and cancel_token to request a
   cooperative cancellation.

Access is checked before enqueueing; ownership is checked at submission and
again by the worker. Job IDs are high-entropy bearer URL capabilities, so treat
job links and cancellation tokens as private.

### Configure Vercel (control plane)

Configure VIBE_AGENT_QUEUE_ENABLED=1, KV_REST_API_URL, KV_REST_API_TOKEN,
VIBE_AGENT_VERIFICATION_SECRET, and the existing access configuration.
Do not place credentials in the repository. The signing secret must be the
same value on Vercel and on the independent worker. The queue is disabled by
default. Queue mode is exposed in the scan form only when a worker heartbeat
is visible; submissions are rejected if no worker is online.

### Deploy the continuous background worker

Use a VM/container host or the optional Render worker blueprint at render.yaml.
Vercel request handlers cannot host this long-lived process. Set the same
KV_REST_API_URL, KV_REST_API_TOKEN and VIBE_AGENT_VERIFICATION_SECRET there, plus
worker-owned model-provider credentials such as OPENAI_API_KEY.

    export VIBE_AGENT_QUEUE_ENABLED=1
    export KV_REST_API_URL='https://example.upstash.io'
    export KV_REST_API_TOKEN='your-private-token'
    export VIBE_AGENT_VERIFICATION_SECRET='shared-strong-secret'
    export OPENAI_API_KEY='worker-api-key'
    python -m agent.queue_worker

Or build the dedicated portable worker image:

    docker build -f Dockerfile.worker -t vibeagent-worker .
    docker run --env-file /secure/path/worker.env vibeagent-worker

The daemon renews its Redis lease and advertises liveness with a short TTL.
Worker crashes produce failed orphan jobs, not automatic replays of potentially
state-changing security tests. Events expire with the job TTL (24 hours by
default). For a controlled one-job worker invocation, use --once.

For the worker-tools backend, also configure VIBE_AGENT_WORKER_URL,
VIBE_AGENT_WORKER_TOKEN and VIBE_AGENT_WORKER_ALLOWED_HOSTS on the background
worker. The stock Docker image contains only portable agent code; native
VibeHacking scripts need their own installation.

### Queue limitations

- BYOK provider keys, cookies, load/stress mode and dry-runs are rejected in
  queue mode. Use provider keys configured on the long-lived worker.
- Cancellation is cooperative between agent operations; in-flight model calls
  or native worker tasks may not be immediately interruptible.
- Cursor-based event replay is durable, but full execution resumption from a
  fine-grained model checkpoint is not implemented. Orphans are failed safely.
- Organization RBAC, billing, automatic scan scheduling and browser Playwright
  end-to-end tests remain future enhancements.

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
`POST /api/verify_target`. Stateless signed verification is recommended; KV / Upstash remains supported for legacy verification state.

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
3. Set `OPENAI_API_KEY`, or use Vercel AI Gateway with deployment OIDC. OpenRouter remains an optional fallback.
4. Configure `VIBE_AGENT_INVITE_CODE_SHA256` and/or `VIBE_AGENT_API_TOKEN` for live-scan access.
5. Configure `VIBE_AGENT_WORKSPACE_TOKEN` for `/app` history access.
6. Set `VIBE_AGENT_VERIFICATION_SECRET` for stateless target verification.
7. Configure Vercel KV / Upstash REST variables **before** enabling hosted scans: live hosted scans now fail closed if durable storage is absent, or report persistence fails. This does not affect local filesystem-based CLI runs. Waitlist storage also requires KV.
8. Configure `VIBE_AGENT_REVIEW_MODEL=google/gemini-3-flash` and include it in `VIBE_AGENT_ALLOWED_MODELS` for dual-model review.
9. Optionally configure the protected native worker variables above.
10. Deploy.

## Status

- [x] Landing page
- [x] Authorization form
- [x] Dynamic multi-round VibeAgent orchestrator
- [x] BreakAgent validation mode
- [x] Expanded 16-tool portable VibeAgent surface, including passive Next.js/RSC, redirect, API endpoint, and cache observations
- [x] Agent-specific tool policies
- [x] OpenAI + Google through Vercel AI Gateway, plus direct OpenAI/OpenRouter paths
- [x] Bounded evidence/retest loop with independent reviewer model
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
- [x] Stateless, signed, exact-host verification receipts for serverless deployments
- [x] SSRF-resistant outbound address policy + redirect refusal
- [x] Scan, workspace and model-selection access boundaries
- [x] User-selectable GPT-6 Luna / GPT-5.6 Luna in the hosted scan form
- [x] Nemotron 3 Ultra 550B selectable/default with OpenRouter free and direct NVIDIA NIM provider routes
- [x] Explicit partial/failed scan statuses, strict hosted persistence, and interrupted-stream indication
- [x] Multi-target hostname verification controls
- [ ] Billing

Exact host declarations never authorize sibling or child subdomains; list every authorized hostname explicitly.

## Golden rule

Only test apps you own or have explicit authorization to test.
