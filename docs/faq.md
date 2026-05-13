---
title: FAQ for Evaluators
nav_order: 18
---

# FAQ for Evaluators

Answers to the questions buyers, security architects, and AppSec teams ask when evaluating Red-Team AI.

## How are you replicating the intuition and out-of-the-box thinking of an ethical hacker who can invent new vectors?

Three layers stacked together:

1. **Static analysis reads your actual code** — the analyzer extracts tools, roles, guardrails, hardcoded secrets, RBAC logic, and the tool call graph. Every attack is generated *from that context*, not from a fixed library.
2. **LLM attack planner** — for each category, a per-category generation prompt is handed to the LLM along with the discovered analysis. The LLM produces novel attacks tailored to your stack (e.g. a JWT forge using the actual secret it found, or a `read_file → send_email` chain using your real tool names).
3. **155 strategies × 141 categories composed orthogonally** — roughly 21,000 base combinations before adaptive rounds. The runner mutates and re-targets across rounds based on what almost worked.

It is not a fixed payload list. The same scan run twice produces different attacks.

## Is testing limited only to pre-programmed logic in the attack framework?

No. There are three escape valves:

- **LLM generation is on by default** — each category module ships seed attacks (3–5) plus a generation prompt that produces novel ones at runtime.
- **Adaptive multi-turn** generates each follow-up turn from the *previous response*, not a script — so the path is decided live by the model.
- **Custom extension points** — drop in your own attack categories (TypeScript, ~30 lines), custom strategies (JSON), custom policies, and custom compliance mappings without modifying core code.

## Does it have any context into how the AI infrastructure is structured?

Yes — this is the core differentiator. The codebase analyzer extracts:

- Tools (names, parameters, permissions, call graph)
- Roles and RBAC rules
- Input/output guardrails and regex patterns
- Hardcoded secrets (JWT, API keys, DB credentials)
- Framework, endpoints, middleware chain, data flow
- MCP servers and tool namespaces (for agent stacks)

Attacks are then generated against the actual surface. That is what produces findings like "forged JWT using the secret in `lib/auth.ts:47`" — impossible without reading the code.

## Can it run continuously in production and pause testing when target systems experience performance issues?

Today: partial.

- ✅ Throttling knobs: `concurrency`, `delayBetweenRequestsMs`, `MAX_CONCURRENT_RUNS`
- ✅ Respects upstream rate-limit responses (429 backoff)
- ✅ Scans can be scheduled via CI/CD or cron
- 🔜 Auto-pause based on target latency or error-rate thresholds — on the roadmap

{: .note }
The honest recommendation is to run against staging or a mirrored environment for continuous testing, and use scoped one-off scans against production with low concurrency.

## What means do users have to minimize risk of accidental crashes, overwhelming databases, or corrupting AI application state?

| Control | What it does |
|---------|--------------|
| **Throttling** | `concurrency: 1–3` + `delayBetweenRequestsMs: 200+` for respectful pacing |
| **Scoping** | Enable or disable categories and strategies per run; start with safe categories before destructive ones |
| **Auth isolation** | Credentials per role mean you can test with a sandbox user that has limited blast radius |
| **Isolated environments** | Every deployment guide recommends staging or synthetic data, never production with real PII |
| **Cancel in flight** | Every run has `DELETE /api/run/:id` to abort cleanly |
| **Audit log** (enterprise) | Every attack is recorded — provable trail of what was sent and when |
| **Dry-run mode** | `customAttacksOnly` + `enableLlmGeneration: false` replays a known set without LLM generation |

## How easy is setup and kickoff — steps, time, and on-prem vs cloud differences?

**Cloud / Docker quick path (~5 minutes):**

```bash
git clone https://github.com/sundi133/wb-red-team.git
cd wb-red-team
cp .env.example .env       # add one LLM API key
docker compose up -d        # dashboard at :4200
```

Or `npm run gen:interactive` for a guided config.

**On-prem is the same image plus Postgres** — `DATABASE_URL` + `MASTER_ENCRYPTION_KEY` enables encrypted storage, OIDC SSO, RBAC, and audit log. OpenShift deployment is documented step by step. AWS, GCP, Azure, Railway all run the same Compose stack.

{: .tip }
**No meaningful difference between on-prem and cloud** — single Docker image, swap the deployment target. First scan within 10–15 minutes.

## What is the depth of testing it performs?

- **141 attack categories** spanning prompt/input, auth, data, agentic, safety, RAG, model, infra, supply chain, compliance, multimodal
- **155 delivery strategies** (encoding, persona, social engineering, multi-turn, token smuggling, and more) composable with every category
- **Multi-round adaptive execution** — round N+1 re-targets near-misses from round N
- **Multi-turn conversations** up to 15 turns, with crescendo escalation and adaptive follow-ups
- **LLM judge** with per-category policy overrides plus 11 compliance framework mappings (OWASP LLM, OWASP Agentic, MITRE ATLAS, NIST AI RMF, NIST 800-53, EU AI Act, GDPR, HIPAA, ISO 27001, PCI DSS, Saudi PDPL)
- **Risk quantification** — business impact, financial exposure estimates, real-world incident mapping

A typical scan executes hundreds to thousands of attacks per run depending on intensity settings.

## Should we use this with other CART tools, alongside humans, or to fully automate and replace humans?

**Alongside humans, complementary to other CART tools.**

- **Replaces** the rote, repetitive parts of red-teaming (encoding variants, multi-turn escalation patterns, regression sweeps across 141 categories). A human should not be hand-typing 21,000 attack combinations.
- **Augments** human creativity through the custom attack and custom strategy extension points — a security engineer's one insight becomes hundreds of attacks via strategy composition.
- **Complements other tools** rather than competing: Promptfoo for black-box DAST and dataset benchmarks, Garak for pure model scanning, PyRIT for research. Red-Team AI is SAST+DAST for AI apps where you own the source. Customers often run two stacks.
- Does **not** replace a senior offensive engineer's judgment on what matters, novel attack-chain reasoning, or social-context-specific scenarios.

{: .note }
Treat it as the floor of coverage, not the ceiling.
