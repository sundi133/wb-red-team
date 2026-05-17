---
title: APIs & SDKs
nav_order: 6
---

# APIs & SDKs

Integrate red-team scanning into your AI applications using the REST API, Python SDK, or framework-specific libraries.

---

## REST API

The dashboard server exposes a full REST API on port 4200.

### Start a scan

```bash
curl -X POST http://localhost:4200/api/run \
  -H "Content-Type: application/json" \
  -d '{
    "target": {
      "baseUrl": "http://localhost:3000",
      "agentEndpoint": "/api/chat"
    },
    "categories": ["prompt_injection", "tool_misuse", "data_exfiltration"],
    "attackConfig": {
      "adaptiveRounds": 2,
      "maxAttacksPerCategory": 5
    }
  }'
```

Response:

```json
{ "id": "a1b2c3d4", "status": "queued" }
```

### Poll for status

```bash
curl http://localhost:4200/api/run/a1b2c3d4
```

### Get results

```bash
# JSON report
curl http://localhost:4200/api/report/report-2026-05-17-a1b2c3d4.json

# CSV export
curl http://localhost:4200/api/report-csv/report-2026-05-17-a1b2c3d4.json
```

### List all reports

```bash
curl http://localhost:4200/api/reports-meta?limit=10&search=prompt
```

### Run compliance analysis

```bash
curl -X POST http://localhost:4200/api/owasp-analyze \
  -H "Content-Type: application/json" \
  -d '{"reportFilename": "report-2026-05-17-a1b2c3d4.json"}'
```

---

## LangChain Integration

### Using LangChain Tools (Python)

Wrap the red-team REST API as LangChain tools so any LangChain agent can trigger scans, poll results, and analyze reports conversationally.

```python
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
import requests

RED_TEAM_URL = "http://localhost:4200"


@tool
def start_red_team_scan(
    target_url: str,
    endpoint: str = "/api/chat",
    categories: list[str] | None = None,
    rounds: int = 2,
) -> dict:
    """Start a red-team security scan against an AI agent endpoint."""
    config = {
        "target": {
            "baseUrl": target_url,
            "agentEndpoint": endpoint,
        },
        "attackConfig": {
            "adaptiveRounds": rounds,
            "maxAttacksPerCategory": 5,
        },
    }
    if categories:
        config["categories"] = categories
    resp = requests.post(f"{RED_TEAM_URL}/api/run", json=config)
    return resp.json()


@tool
def check_scan_status(run_id: str) -> dict:
    """Check the status and progress of a red-team scan."""
    resp = requests.get(f"{RED_TEAM_URL}/api/run/{run_id}")
    data = resp.json()
    return {
        "status": data.get("status"),
        "progress": len(data.get("progress", [])),
        "total": data.get("estimatedTotal"),
        "reportFile": data.get("reportFile"),
    }


@tool
def get_scan_results(run_id: str) -> dict:
    """Get the full results of a completed red-team scan."""
    # First get the report filename from the run
    run = requests.get(f"{RED_TEAM_URL}/api/run/{run_id}").json()
    report_file = run.get("reportFile")
    if not report_file:
        return {"error": "Scan not complete yet", "status": run.get("status")}
    resp = requests.get(f"{RED_TEAM_URL}/api/report/{report_file}")
    report = resp.json()
    return {
        "score": report["summary"]["score"],
        "total_attacks": report["summary"]["totalAttacks"],
        "passed": report["summary"]["passed"],
        "failed": report["summary"]["failed"],
        "by_category": {
            cat: {"total": v["total"], "passed": v["passed"]}
            for cat, v in report["summary"]["byCategory"].items()
        },
    }


@tool
def list_reports(search: str = "", limit: int = 5) -> list[dict]:
    """List recent red-team scan reports."""
    resp = requests.get(
        f"{RED_TEAM_URL}/api/reports-meta",
        params={"limit": limit, "search": search},
    )
    return resp.json().get("reports", [])


# Create the agent
llm = ChatOpenAI(model="gpt-4.1")
tools = [start_red_team_scan, check_scan_status, get_scan_results, list_reports]
agent = create_react_agent(llm, tools)

# Run it
result = agent.invoke({
    "messages": [
        {"role": "user", "content": "Scan my chatbot at http://localhost:3000 for prompt injection and tool misuse vulnerabilities"}
    ]
})
```

### Red-teaming a LangChain Agent

Test your own LangChain agent by pointing the scanner at its serving endpoint:

```python
# 1. Serve your LangChain agent
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langserve import add_routes
from fastapi import FastAPI

llm = ChatOpenAI(model="gpt-4.1")
agent = create_react_agent(llm, tools=[...])

app = FastAPI()
add_routes(app, agent, path="/chat")

# Run: uvicorn app:app --port 3000
```

```json
// 2. Red-team config targeting the LangChain agent
{
  "target": {
    "baseUrl": "http://localhost:3000",
    "agentEndpoint": "/chat/invoke",
    "customApiTemplate": {
      "bodyTemplate": "{\"input\": {\"messages\": [{\"role\": \"user\", \"content\": \"{{message}}\"}]}}",
      "responsePath": "output.content"
    }
  },
  "categories": [
    "prompt_injection",
    "tool_misuse",
    "tool_result_injection",
    "tool_chain_hijack",
    "data_exfiltration"
  ]
}
```

### LangChain + MCP Server

Connect the red-team MCP server directly to a LangChain agent using `langchain-mcp-adapters`:

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent
from langchain_anthropic import ChatAnthropic

llm = ChatAnthropic(model="claude-sonnet-4-20250514")

async with MultiServerMCPClient(
    {
        "red-team": {
            "command": "npx",
            "args": ["tsx", "/path/to/hermes-redteam/mcp-server.ts"],
            "transport_type": "stdio",
        }
    }
) as client:
    tools = client.get_tools()
    # Tools: read_repo, probe_target, write_config, run_scan,
    #        check_run_status, get_run_results, list_categories_and_strategies, etc.

    agent = create_react_agent(llm, tools)
    result = await agent.ainvoke({
        "messages": [{"role": "user", "content": "Scan my app at http://localhost:3000 for agentic security issues"}]
    })
```

---

## CrewAI Integration

### Red-team agent crew

```python
from crewai import Agent, Task, Crew
from crewai_tools import tool
import requests

RED_TEAM_URL = "http://localhost:4200"


@tool("Start Security Scan")
def start_scan(target_url: str, categories: str = "") -> str:
    """Start a red-team scan. Categories: comma-separated list like 'prompt_injection,tool_misuse'."""
    config = {
        "target": {"baseUrl": target_url, "agentEndpoint": "/api/chat"},
        "attackConfig": {"adaptiveRounds": 2, "maxAttacksPerCategory": 5},
    }
    if categories:
        config["categories"] = [c.strip() for c in categories.split(",")]
    resp = requests.post(f"{RED_TEAM_URL}/api/run", json=config)
    return str(resp.json())


@tool("Check Scan Status")
def check_status(run_id: str) -> str:
    """Check if a red-team scan is complete."""
    resp = requests.get(f"{RED_TEAM_URL}/api/run/{run_id}")
    return str(resp.json())


@tool("Get Scan Report")
def get_report(report_filename: str) -> str:
    """Get the summary of a completed scan report."""
    resp = requests.get(f"{RED_TEAM_URL}/api/report/{report_filename}")
    data = resp.json()
    summary = data.get("summary", {})
    return f"Score: {summary.get('score')}/100, Attacks: {summary.get('totalAttacks')}, Failed: {summary.get('failed')}"


scanner = Agent(
    role="AI Security Scanner",
    goal="Run comprehensive red-team scans against AI applications",
    backstory="You are an AI security expert who identifies vulnerabilities in LLM-powered applications.",
    tools=[start_scan, check_status, get_report],
)

analyst = Agent(
    role="Security Analyst",
    goal="Analyze red-team results and produce actionable remediation plans",
    backstory="You review security scan results and create prioritized fix recommendations.",
    tools=[get_report],
)

scan_task = Task(
    description="Scan the AI chatbot at {target_url} for prompt injection, tool misuse, and data exfiltration vulnerabilities.",
    expected_output="Scan run ID and status",
    agent=scanner,
)

analysis_task = Task(
    description="Analyze the scan results and create a remediation plan prioritized by severity.",
    expected_output="Prioritized list of vulnerabilities with specific fix recommendations",
    agent=analyst,
)

crew = Crew(agents=[scanner, analyst], tasks=[scan_task, analysis_task], verbose=True)
result = crew.kickoff(inputs={"target_url": "http://localhost:3000"})
```

---

## OpenAI Assistants / Responses API

### Function calling with the Responses API

```python
from openai import OpenAI
import requests, json

client = OpenAI()
RED_TEAM_URL = "http://localhost:4200"

tools = [
    {
        "type": "function",
        "name": "start_red_team_scan",
        "description": "Start a red-team security scan against an AI agent",
        "parameters": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Base URL of the target"},
                "endpoint": {"type": "string", "description": "Chat endpoint path"},
                "categories": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Attack categories to test",
                },
            },
            "required": ["target_url"],
        },
    },
    {
        "type": "function",
        "name": "get_scan_results",
        "description": "Get results of a completed scan by run ID",
        "parameters": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
            },
            "required": ["run_id"],
        },
    },
]


def handle_tool_call(name: str, args: dict) -> str:
    if name == "start_red_team_scan":
        config = {
            "target": {
                "baseUrl": args["target_url"],
                "agentEndpoint": args.get("endpoint", "/api/chat"),
            },
        }
        if args.get("categories"):
            config["categories"] = args["categories"]
        resp = requests.post(f"{RED_TEAM_URL}/api/run", json=config)
        return json.dumps(resp.json())
    elif name == "get_scan_results":
        resp = requests.get(f"{RED_TEAM_URL}/api/run/{args['run_id']}")
        return json.dumps(resp.json())
    return json.dumps({"error": "Unknown tool"})


response = client.responses.create(
    model="gpt-4.1",
    tools=tools,
    input="Scan my chatbot at http://localhost:3000 for security issues",
)

# Handle tool calls in a loop
while response.output:
    tool_calls = [o for o in response.output if o.type == "function_call"]
    if not tool_calls:
        break
    tool_results = []
    for tc in tool_calls:
        result = handle_tool_call(tc.name, json.loads(tc.arguments))
        tool_results.append({"type": "function_call_output", "call_id": tc.call_id, "output": result})
    response = client.responses.create(
        model="gpt-4.1",
        tools=tools,
        input=tool_results,
        previous_response_id=response.id,
    )

# Final text response
print([o.text for o in response.output if hasattr(o, "text")])
```

---

## Anthropic Claude API

### Tool use with Claude

```python
import anthropic
import requests, json

client = anthropic.Anthropic()
RED_TEAM_URL = "http://localhost:4200"

tools = [
    {
        "name": "start_red_team_scan",
        "description": "Start a red-team security scan against an AI agent endpoint",
        "input_schema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Base URL of the target"},
                "endpoint": {"type": "string", "description": "Chat endpoint path"},
                "categories": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Attack categories to test",
                },
            },
            "required": ["target_url"],
        },
    },
    {
        "name": "get_scan_results",
        "description": "Get results of a completed scan by run ID",
        "input_schema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
    },
]


def handle_tool(name, input_data):
    if name == "start_red_team_scan":
        config = {
            "target": {
                "baseUrl": input_data["target_url"],
                "agentEndpoint": input_data.get("endpoint", "/api/chat"),
            },
        }
        if input_data.get("categories"):
            config["categories"] = input_data["categories"]
        return requests.post(f"{RED_TEAM_URL}/api/run", json=config).json()
    elif name == "get_scan_results":
        return requests.get(f"{RED_TEAM_URL}/api/run/{input_data['run_id']}").json()


messages = [{"role": "user", "content": "Scan http://localhost:3000 for prompt injection and tool misuse"}]

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=4096,
    tools=tools,
    messages=messages,
)

# Agentic loop
while response.stop_reason == "tool_use":
    tool_block = next(b for b in response.content if b.type == "tool_use")
    result = handle_tool(tool_block.name, tool_block.input)

    messages.append({"role": "assistant", "content": response.content})
    messages.append({
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": tool_block.id, "content": json.dumps(result)}],
    })
    response = client.messages.create(
        model="claude-sonnet-4-20250514", max_tokens=4096, tools=tools, messages=messages,
    )

# Print final response
print(next(b.text for b in response.content if hasattr(b, "text")))
```

---

## Vercel AI SDK (TypeScript)

```typescript
import { openai } from "@ai-sdk/openai";
import { generateText, tool } from "ai";
import { z } from "zod";

const RED_TEAM_URL = "http://localhost:4200";

const result = await generateText({
  model: openai("gpt-4.1"),
  tools: {
    startScan: tool({
      description: "Start a red-team security scan",
      parameters: z.object({
        targetUrl: z.string().describe("Base URL of the AI agent"),
        endpoint: z.string().default("/api/chat"),
        categories: z.array(z.string()).optional(),
      }),
      execute: async ({ targetUrl, endpoint, categories }) => {
        const config: Record<string, unknown> = {
          target: { baseUrl: targetUrl, agentEndpoint: endpoint },
          attackConfig: { adaptiveRounds: 2, maxAttacksPerCategory: 5 },
        };
        if (categories) config.categories = categories;
        const resp = await fetch(`${RED_TEAM_URL}/api/run`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(config),
        });
        return resp.json();
      },
    }),
    getScanResults: tool({
      description: "Get results of a completed scan",
      parameters: z.object({ runId: z.string() }),
      execute: async ({ runId }) => {
        const resp = await fetch(`${RED_TEAM_URL}/api/run/${runId}`);
        return resp.json();
      },
    }),
  },
  maxSteps: 5,
  prompt: "Scan my chatbot at http://localhost:3000 for security issues",
});

console.log(result.text);
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: AI Security Scan
on:
  pull_request:
    branches: [main]

jobs:
  red-team:
    runs-on: ubuntu-latest
    services:
      red-team:
        image: ghcr.io/sundi133/wb-red-team:latest
        ports:
          - 4200:4200
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    steps:
      - name: Wait for server
        run: |
          for i in $(seq 1 30); do
            curl -sf http://localhost:4200/api/auth-config && break
            sleep 2
          done

      - name: Run scan
        run: |
          RUN_ID=$(curl -s -X POST http://localhost:4200/api/run \
            -H "Content-Type: application/json" \
            -d '{
              "target": {
                "baseUrl": "${{ env.TARGET_URL }}",
                "agentEndpoint": "/api/chat"
              },
              "categories": ["prompt_injection", "tool_misuse", "data_exfiltration"],
              "attackConfig": {"adaptiveRounds": 1, "maxAttacksPerCategory": 3}
            }' | jq -r '.id')
          echo "RUN_ID=$RUN_ID" >> $GITHUB_ENV

      - name: Wait for completion
        run: |
          for i in $(seq 1 60); do
            STATUS=$(curl -s http://localhost:4200/api/run/$RUN_ID | jq -r '.status')
            [ "$STATUS" = "done" ] && break
            [ "$STATUS" = "error" ] && exit 1
            sleep 10
          done

      - name: Check score
        run: |
          SCORE=$(curl -s http://localhost:4200/api/run/$RUN_ID | jq -r '.report.summary.score')
          echo "Security score: $SCORE/100"
          if [ "$SCORE" -lt 70 ]; then
            echo "::error::Security score $SCORE is below threshold (70)"
            exit 1
          fi
```

### Python script for CI pipelines

```python
"""Minimal CI script -- exits non-zero if score < threshold."""
import requests, time, sys

RED_TEAM_URL = "http://localhost:4200"
TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
THRESHOLD = int(sys.argv[2]) if len(sys.argv) > 2 else 70

# Start scan
run = requests.post(f"{RED_TEAM_URL}/api/run", json={
    "target": {"baseUrl": TARGET_URL, "agentEndpoint": "/api/chat"},
    "categories": ["prompt_injection", "tool_misuse", "data_exfiltration"],
    "attackConfig": {"adaptiveRounds": 1, "maxAttacksPerCategory": 3},
}).json()
run_id = run["id"]
print(f"Scan started: {run_id}")

# Poll until done
while True:
    status = requests.get(f"{RED_TEAM_URL}/api/run/{run_id}").json()
    if status["status"] in ("done", "error"):
        break
    print(f"  Progress: {len(status.get('progress', []))} attacks completed...")
    time.sleep(10)

if status["status"] == "error":
    print("Scan failed")
    sys.exit(1)

# Check score
report_file = status["reportFile"]
report = requests.get(f"{RED_TEAM_URL}/api/report/{report_file}").json()
score = report["summary"]["score"]
failed = report["summary"]["failed"]
print(f"Score: {score}/100 | Passed: {report['summary']['passed']} | Failed: {failed}")

if score < THRESHOLD:
    print(f"FAIL: Score {score} below threshold {THRESHOLD}")
    sys.exit(1)
print("PASS")
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/run` | POST | Start a new scan |
| `/api/run/:id` | GET | Get run status + progress |
| `/api/run/:id` | DELETE | Cancel a running scan |
| `/api/runs` | GET | List all runs |
| `/api/reports` | GET | List report filenames |
| `/api/reports-meta` | GET | Paginated reports with metadata |
| `/api/report/:filename` | GET | Full report JSON |
| `/api/report-csv/:filename` | GET | Export as CSV |
| `/api/owasp-analyze` | POST | OWASP compliance analysis (NDJSON stream) |
| `/api/risk-analyze` | POST | Business risk analysis (NDJSON stream) |
| `/api/compliance-frameworks` | GET | List compliance frameworks |
| `/api/audit-log` | GET | Query audit log (enterprise) |
