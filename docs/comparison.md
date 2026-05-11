---
title: Comparison & Status
nav_order: 17
---

# Comparison vs Other Tools

| Pick... | When |
|---------|------|
| **Red-Team AI** | You own the source. You're shipping an agentic AI app with tools and roles. You want findings tied to *your* code, not generic ones. |
| **[Promptfoo](https://github.com/promptfoo/promptfoo)** | You don't have source access. You need unified eval + red-team. Largest provider matrix. |
| **[Garak](https://github.com/leondz/garak)** | You're testing the model itself, not an application. Pure model-level scanning. |
| **[PyRIT](https://github.com/Azure/PyRIT)** | Python research framework with maximum extensibility. |
| **[DeepTeam](https://github.com/confident-ai/deepteam)** | Already on the DeepEval stack. |

## Red-Team AI vs Promptfoo

**Where Red-Team AI is stronger:**

| Area | Red-Team AI | Promptfoo |
|------|-------------|-----------|
| Source code analysis | Reads codebase — tools, roles, guardrails, secrets, call graphs | No source access |
| Agentic attacks | 13 categories | ~5 |
| Social engineering strategies | 20+ | ~3 |
| RAG attacks | 9 categories | ~3 |
| Adaptive rounds | Multi-round — defense profiling → strategy rotation → re-targeting | Single pass |
| Strategy × category composition | 155 × 141 orthogonal | Per-plugin |
| Self-hosted enterprise | Built-in Postgres, AES-256, SSO/OIDC, RBAC, audit log, multi-tenant | Enterprise SaaS plan |
| Risk quantification | LLM-powered business impact, financial exposure, incident mapping | Not built-in |
| Guardrail recommendations | Maps findings to Votal Shield configs | Not built-in |
| Compliance frameworks | 11 built-in | 6 |

**Where Promptfoo is stronger:**

| Area | Promptfoo | Red-Team AI |
|------|-----------|-------------|
| Maturity & community | 20k+ stars, OpenAI-backed | Beta |
| Provider support | 50+ | 4 |
| Compliance plugins | 56 granular plugins | 10 industry-specific categories |
| Dataset benchmarks | 11 curated (HarmBench, BeaverTails, ToxicChat, XSTest) | None |
| CI/CD | First-class GitHub Action, PR code scanning | API-based |
| Eval + red-team | Combined accuracy eval + security testing | Security testing only |
| Multi-turn agents | Hydra, GOAT, crescendo | Scripted, adaptive (LLM follow-ups), crescendo |
| GCG attacks | Gradient-based adversarial optimization | Not available |
| Multimodal encoding | Image, video, audio encoding bypass | Semantic multimodal attacks |

**They're complementary:** Promptfoo for black-box DAST, Red-Team AI for white-box SAST+DAST.

---

# Project Status & Community

**Beta.** Honest assessment:

- ✅ **Stable** — codebase analyzer, attack runner, judge, reports, dashboard, Docker, enterprise backend
- ✅ **Working well** — 141 categories × 155 strategies, multi-round adaptation, multi-turn crescendo, 11 compliance frameworks, risk quantification, Postgres + encryption
- 🚧 **In progress** — Hermes agent integration, cross-run memory, attack path visualization
- 🔜 **Roadmap** — GitHub Action, PDF reports, webhook notifications, llm-shield guardrail auto-deploy

## Community

- Issues / discussion: [GitHub Issues](https://github.com/sundi133/wb-red-team/issues)
- Enterprise / partnerships: [info@votal.ai](mailto:info@votal.ai)
- Demo target app: [`demo-agentic-app`](https://github.com/sundi133/demo-agentic-app)
- Guardrails: [Votal Shield (llm-shield)](https://github.com/sundi133/llm-shield)

**License:** [MIT](https://github.com/sundi133/wb-red-team/blob/main/LICENSE).
