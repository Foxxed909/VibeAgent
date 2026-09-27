# VibeAgent

Affordable autonomous **authorized** security testing.

- **Hobby** — $50 / scan · exact URLs + `*.vercel.app` only
- **Enterprise** — $200 / scan · hosts, URLs, IP ranges

Powered by the [VibeHacking](https://github.com/Foxxed909/VibeHacking) tool surface. Agents only operate against the exact targets the user declares and confirms.

## Landing page

Static landing page lives at the repo root (`index.html`).

### Deploy on Vercel

1. Import this repo in the [Vercel dashboard](https://vercel.com/new).
2. Framework preset: **Other** (static).
3. Deploy. You will get a `*.vercel.app` URL immediately.

Or with the Vercel CLI:

```bash
npx vercel
```

## Status

- [x] Landing page
- [ ] Authorization form (Hobby / Enterprise text schema)
- [ ] Agent orchestrator (OpenRouter free models + VibeHacking tools)
- [ ] Report delivery

## Golden rule

Only ever test apps you own or have explicit written authorization to test.
