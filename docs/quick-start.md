---
title: Quick Start
nav_order: 2
---

# Quick Start

## Option A: Interactive Config Generator

Recommended for first-time users.

```bash
# 1. Clone and install
git clone https://github.com/sundi133/wb-red-team.git
cd wb-red-team && npm install

# 2. Set your LLM key (one of)
cp .env.example .env
# Edit .env — add at least one LLM key: ANTHROPIC_API_KEY, OPENAI_API_KEY,
# TOGETHER_API_KEY, AZURE_OPENAI_API_KEY, or CUSTOM_LLM_BASE_URL

# 3. Generate config interactively
npm run gen:interactive
```

The interactive generator walks you through app details, authentication, smart category selection with reasoning, strategy selection, intensity, and LLM provider. Iterate until satisfied, then save and run.

## Option B: CLI with config file

```bash
cp config.example.json config.json
# Edit config.json: set baseUrl, agentEndpoint, codebasePath
npm start
```

## Option C: AI Assistant (natural language)

```bash
npm run ai
# > test my chatbot at http://localhost:3000 for safety issues
# > run
# > results
# > guardrails
```

## Option D: Docker Dashboard

```bash
cp .env.example .env
# Edit .env with your LLM API key
docker compose up -d
# Open http://localhost:4200
```

Reports land in `report/` as both JSON and Markdown. Dashboard at `http://localhost:4200` with live progress, compliance analysis, and risk quantification.

## Trigger a run via API

After your config is created:

```bash
# Using a config file
curl -X POST http://localhost:4200/api/run \
  -H "Content-Type: application/json" \
  -d @configs/config.my-app.json

# If your target is on localhost (Docker needs host.docker.internal)
curl -X POST http://localhost:4200/api/run \
  -H "Content-Type: application/json" \
  -d "$(cat configs/config.my-app.json | sed 's/localhost:4000/host.docker.internal:4000/g')"

# Poll status
curl http://localhost:4200/api/run/<runId>

# List all runs
curl http://localhost:4200/api/runs

# Cancel a run
curl -X DELETE http://localhost:4200/api/run/<runId>

# With API key (enterprise mode)
curl -X POST http://localhost:4200/api/run \
  -H "X-API-Key: rtk_your_api_key" \
  -H "Content-Type: application/json" \
  -d @configs/config.insurance.json
```
