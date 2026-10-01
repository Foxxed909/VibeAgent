# VibeAgent

Affordable autonomous **authorized** security testing with two agent modes:

- **VibeAgent** — discovery/recon mode. Maps the authorized surface, follows evidence and chooses audit tools dynamically.
- **BreakAgent** — validation mode. Re-checks suspected weaknesses with a narrower evidence-focused tool policy.

Both modes share the same model layer, scope enforcement, SSE live thread, job persistence and reports.

## Product tiers

- **Hobby** — $50 / scan · exact URLs + `*.vercel.app` only · trial code supported
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

## Deploy on Vercel

1. Import this repo into Vercel.
2. Framework: **Other**.
3. Set `OPENAI_API_KEY` and/or `OPENROUTER_API_KEY`.
4. For durable jobs and waitlist entries, configure Vercel KV / Upstash REST variables.
5. Deploy.

## Status

- [x] Landing page
- [x] Authorization form
- [x] Dynamic multi-round VibeAgent orchestrator
- [x] BreakAgent validation mode
- [x] Expanded portable VibeAgent tool surface
- [x] Agent-specific tool policies
- [x] OpenAI + OpenRouter model paths
- [x] Live SSE thread UI with agent identity
- [x] `/api/scan`, `/api/stream`, `/api/job`
- [x] Persistent cloud job store via Vercel KV / Upstash when configured
- [x] Waitlist persistence via KV / Upstash when configured
- [ ] Billing

## Golden rule

Only test apps you own or have explicit authorization to test.
