# VibeAgent

Affordable autonomous **authorized** security testing.

- **Hobby** — $50 / scan · exact URLs + `*.vercel.app` only
- **Enterprise** — $200 / scan · hosts, URLs, IP ranges

Powered by the [VibeHacking](https://github.com/Foxxed909/VibeHacking) tool surface. Agents only operate against the exact targets the user declares and confirms.

## Repo layout

```
index.html          # Landing page
scan.html           # Hobby / Enterprise authorization form (exact targets + phrase)
agent/              # Orchestrator scaffold
  scope.py          # Exact-target enforcement + Hobby vercel.app rule
  models.py         # OpenRouter free-model client
  tools_catalog.py  # VibeHacking tool descriptions + system prompt
  orchestrator.py   # validate → plan → model → scope-check tools → report
  cli.py
api/
  waitlist.py       # Vercel serverless waitlist stub
```

## Quick start (orchestrator)

```bash
# dry-run (no API key needed)
python -m agent.cli --tier hobby --target https://my-app.vercel.app --app-name MyApp --dry-run

# live model call (requires key)
export OPENROUTER_API_KEY=sk-or-...
export VIBEHACKING_ROOT=/path/to/VibeHacking   # optional: run real tools
python -m agent.cli --tier hobby --target https://my-app.vercel.app --app-name MyApp
```

Confirmation phrase (required):
```
I OWN OR AM AUTHORIZED TO TEST THESE TARGETS
```

## Deploy on Vercel

1. Import this repo at [vercel.com/new](https://vercel.com/new)
2. Framework: **Other** (static + optional Python serverless under `/api`)
3. Deploy → `*.vercel.app` URL

## Status

- [x] Landing page
- [x] Authorization form (`/scan.html`) — Hobby + Enterprise text schema
- [x] Agent orchestrator scaffold (scope lock, OpenRouter free models, VibeHacking tool catalog)
- [x] Waitlist API stub (`/api/waitlist`)
- [ ] Persistent job queue + report delivery
- [ ] Billing

## Golden rule

Only ever test apps you own or have explicit written authorization to test.
