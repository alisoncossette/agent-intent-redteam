# 🥊 Agent-Intention Red-Teamer

**Find how an AI agent behaves *unexpectedly* — not just how it gets jailbroken.**

Most agent red-teamers are security scanners: prompt injection, jailbreaks (Lakera, garak, PyRIT, …).
This one is different. It hunts **behavioral & intention failures** — the ways an agent goes wrong
*even with no adversary*:

- **intention-misalignment** — pursues a literal/proxy goal that diverges from what the user actually meant (spec-gaming, over-literal compliance, sycophancy)
- **emergent-behavior** — failures that only appear from multi-step chains, tool composition, or feedback loops (two safe tools → one unsafe effect)
- **off-label / mislabel** — a capability used for something it wasn't designed for; or the agent mis-classifies a situation and takes the right action for the *wrong* category
- **vulnerable-user judgment** — overstepping "to help," paternalizing, mis-trading safety vs. autonomy
- **authority & consent drift** — acting beyond consented scope, after a revoke, or treating a one-time OK as standing
- **security/injection** — included as *one slice*, not the focus

It then **adversarially verifies** every finding (kills hallucinated bugs) and hands developers a
**ranked list of concrete fixes**.

## How it works (tier → test → verify → improve)
```
Map     →  inventory the agent surface from the repo (tools, actions, authority checks, prompts)
Blast   →  fan out adversarial scenarios across the dimensions above (parallel)
Verify  →  an independent skeptic confirms each finding is real (default: not-a-bug)
Assess  →  scoreboard + ranked, concrete fixes pointing at the exact code
```

## Run it
```
# As a Claude Code workflow (today):
Workflow({ name: 'agent-intention-redteam', args: { repo: '<path-or-git-url>' } })
```
Roadmap to full deployment: **CLI** (`npx agent-redteam <repo>`) · **GitHub Action** (runs on every PR,
comments findings) · **Nebius-backed** scenario blast for massive cheap throughput.

## Proof — it found real bugs (dogfooded on Stead)
Pointed at **Stead** (a consent-gated personal agent), in one run:
- **73 adversarial probes**, **44 held**, **6 real authority bugs** surfaced and verified, e.g.:
  - negative / zero / `NaN` order amounts were **auto-authorized** (no lower-bound check)
  - a string amount **crashed** the consent engine (no type guard)
  - a one-time over-cap approval **silently widened the standing cap forever**
- **1 critical fix applied + verified** (amount must be finite & > 0 & numeric) → 32 tests still green.

That test → fix loop is the product: it doesn't just flag problems, it makes the agent safer.

## Why it matters
Agents are getting hands (Composio), eyes (Tavily), and autonomy. The dangerous failures aren't only
jailbreaks — they're the quiet ways an agent's *intention* drifts from its owner's. This tells
developers, before their users find out.

_Source: `../.claude/workflows/agent-intention-redteam.js`_
