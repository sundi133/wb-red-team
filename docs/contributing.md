---
title: Contributing
nav_order: 15
---

# Contributing

## Getting started

1. Fork and clone the repo
2. Install dependencies: `npm install`
3. Copy the example config: `cp config.example.json config.json` and fill in your target details
4. Run the type checker: `npm run typecheck`
5. Run tests: `npm test`

## Adding a new attack module

Attack modules live in `attacks/`. Each module must implement the `AttackModule` interface from `lib/types.ts`.

1. Create a new file in `attacks/`, e.g. `attacks/my-attack.ts`
2. Add your category to the `AttackCategory` union in `lib/types.ts`
3. Add a severity weight in `lib/report-generator.ts` (`SEVERITY_WEIGHTS` and `CATEGORIES`)
4. Import and register your module in `red-team.ts` (`ALL_MODULES` array)

**Module structure:**

```ts
import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "my_category" as const;

export const myCategoryModule: AttackModule = {
  category,

  getSeedAttacks(): Attack[] {
    return [
      {
        id: "mycat-1-descriptive-name",
        category,
        name: "Short attack name",
        description: "What this attack does",
        authMethod: "jwt",
        role: "admin",
        payload: { message: "The prompt sent to the agent" },
        expectation: "What success looks like",
        severity: "high",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker specializing in ...

AVAILABLE TOOLS:
${JSON.stringify(analysis.tools.map((t) => ({ name: t.name, description: t.description })), null, 2)}

Generate attacks that:
1. ...
2. ...`;
  },
};
```

**Multi-turn attacks:** add a `steps` array. The runner stops early if any step gets a `PASS` verdict.

```ts
{
  payload: { message: "Step 1: build rapport" },
  steps: [
    { payload: { message: "Step 2: escalate" } },
    { payload: { message: "Step 3: exfiltrate" } },
  ],
}
```

## Code style and PRs

- TypeScript strict mode
- No `any` types — use `unknown` and narrow
- Run `npm run lint` before submitting
- Create a feature branch from `main`
- Ensure `npm run typecheck` and `npm test` pass
- Open a PR with a clear description of what and why

{: .warning }
For security vulnerabilities in this framework itself, please email rather than opening a public issue.
