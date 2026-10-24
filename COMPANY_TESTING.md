# Real company assessments: private operator workflow

The goal is a real, bounded assessment — **not a sample report**.
Do not publish company hostnames, internal screenshots, API keys or report
contents to the public repository. Only assess exact systems covered by your
organization's authorization and testing window.

## Option A: company-network CLI (recommended for private DNS/internal apps)

Run the CLI on a machine inside the approved company network or VPN. The
target hostname is typed on that machine, not sent to a public deployment.

1. Clone and install from the public repository.
2. Configure your own model API key as a local environment secret
   (`OPENROUTER_API_KEY` or `NVIDIA_API_KEY`), not an invite code.
3. Run a **real, Quick-depth** assessment of one authorized host:

```bash
python -m agent.cli --agent vibe --backend portable --tier hobby \
  --app-name 'Company approved assessment' \
  --target 'https://your-exact-approved-host.example' \
  --model 'nvidia/nemotron-3-ultra-550b-a55b:free' \
  --depth quick \
  --confirm 'I OWN OR AM AUTHORIZED TO TEST THESE TARGETS'
```

This performs real bounded HTTP checks and can call Nemotron for synthesis.
It does **not** automatically retrieve non-public Vercel projects or
company data. It does not require a challenge file in local CLI mode. It
does require an authorized target and working network/provider access.
The portable tool catalog makes GET/HEAD/OPTIONS observations; do not set
a stress multiplier for a first run.

Local scanners deny non-public/reserved addresses by default. For an
approved internal-only private IP address the existing
`VIBE_AGENT_ALLOW_PRIVATE_TARGETS=1` override exists, but it relaxes
outbound address safety and must **never** be enabled on a publicly
accessible deployment. Prefer an isolated company-network runner and
ensure access to only approved networks. Keep this variable off unless
the company's security owner explicitly requires and approves it.

## Option B: self-hosted Vercel, exact-host operator approval

This works only for an HTTPS hostname reachable from the Vercel runtime
under normal outbound network policy; it cannot reach a private VPN,
RFC1918 IP, or internal-only DNS host.

Configure the following **in your private Vercel project** and redeploy:

```text
VIBE_AGENT_OWNER_APPROVED_HOSTS=approved.company.example
VIBE_AGENT_API_TOKEN=<generate-strong-independent-operator-token>
VIBE_AGENT_VERIFICATION_SECRET=<generate-strong-signing-secret>
OPENROUTER_API_KEY=<your-own-provider-key>
KV_REST_API_URL=<your-own-Redis-REST-URL>
KV_REST_API_TOKEN=<your-own-Redis-REST-token>
```

Keep `VIBE_AGENT_REQUIRE_OWNERSHIP=1`. Do not configure the approved
hostname on the public shared VibeAgent service. Use your **own** project,
provider account and database. Never store secret values in source code.

On `/scan`, expand **Run a real scan**, enter your exact target and your
self-hosted operator scan token, and tap **Approve preconfigured company
host (operator only)**. The server only approves exact hosts listed
in `VIBE_AGENT_OWNER_APPROVED_HOSTS`; an invite code cannot authorize this
action. It returns a signed, host-bound proof valid for at most one hour,
and revocation takes effect when the allowlist entry is removed.

This route does **not** create or fetch a verification challenge file.
Operator-approved scans are **Quick-depth only** with stress disabled
and still require server-side scan access, model credentials, durable
report storage and the standard network/URL scope protections.
Normal challenge verification remains available for other real scans.

## Findings and access boundaries

Reports must distinguish confirmed observations from hypotheses; a
missing header or HTTP 200 alone is not an exploit. Ask the owner to
approve any expansion into authenticated testing, sensitive data,
invasive exploitation, increased request rates or extra hosts.

An operator-approved hostname is not permission to read arbitrary
company databases, browser sessions, or Vercel account resources.
Credentials entered for models go to those providers; assess your
organization's data handling terms before transmitting sensitive
results. In particular, do not submit confidential company data to
OpenRouter's free endpoint without approval.

No scan against an unnamed or undisclosed company host has been
performed by adding this feature; the target must be provided locally
to the CLI or in the operator's private scan form.
