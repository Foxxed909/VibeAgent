# VibeAgent

Affordable autonomous **authorized** security testing.

- **Hobby** — $50 / scan · exact URLs + `*.vercel.app` only · trial code supported
- **Enterprise** — $200 / scan · hosts, URLs, IP ranges

Powered by [VibeHacking](https://github.com/Foxxed909/VibeHacking) tools. Agents only operate against exact targets the user declares and confirms.

## Live thread

After you start a scan from `/scan.html`, you are redirected to `/thread.html?job=…` where agent steps stream (tool calls, findings, final report).

## Quick start

```bash
python -m agent.cli --tier hobby --target https://my-app.vercel.app --app-name MyApp --dry-run

export OPENAI_API_KEY=sk-...
export VIBEHACKING_ROOT=/path/to/VibeHacking
python -m agent.cli --tier hobby --target https://my-app.vercel.app --app-name MyApp \
  --access-code 'YOUR_TRIAL_CODE' --model gpt-6-luna --save
```

Confirmation phrase:

```
I OWN OR AM AUTHORIZED TO TEST THESE TARGETS
```

## Deploy on Vercel

1. Import this repo at [vercel.com/new](https://vercel.com/new)
2. Framework: **Other**
3. Set env: `OPENAI_API_KEY` and/or `OPENROUTER_API_KEY`
4. Deploy

## Status

- [x] Landing page
- [x] Authorization form + trial access code
- [x] Agent orchestrator (multi-round tool loop)\n- [x] Expanded VibeAgent tool surface: cloud scout, spider, OpenAPI scout, CORS, session/cookie audit, auth-boundary audit, env/config audit
- [x] OpenAI GPT-6 Luna / GPT-5.6 Luna + OpenRouter free models
- [x] Live scan thread UI
- [x] `/api/scan` + `/api/job`
- [x] Persistent cloud job store via Vercel KV / Upstash when configured (filesystem fallback)
- [ ] Billing

## Golden rule

Only ever test apps you own or have explicit authorization to test.
