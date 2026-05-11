---
title: Operations & Security
nav_order: 16
---

# Troubleshooting & Security

## Troubleshooting

**`Cannot read properties of undefined (reading 'map')`**
Check for undefined arrays in attack processing. Add defensive checks to array operations.

**`LLM judge failed: 401 API key`**

```json
{
  "attackConfig": {
    "llmProvider": "openai",
    "judgeModel": "gpt-4o-mini"
  }
}
```
Verify the relevant API key in `.env`.

**`Rate limit exceeded`**

```json
{
  "attackConfig": {
    "concurrency": 1,
    "delayBetweenRequestsMs": 1000
  }
}
```

**`Connection timeout`**

```json
{ "target": { "baseUrl": "https://correct-api-url.com" } }
```

**Debug mode:**

```bash
DEBUG=red-team:* npm start config.json
```

---

## Security Considerations

**Safe testing practices:**
- Use dedicated test instances, not production
- Implement network isolation for testing
- Use synthetic test data, not real user data
- Monitor resource usage during tests

**Credential management:**

```bash
export OPENAI_API_KEY="sk-..."
export TEST_API_KEY="test-key-123"

echo "*.env"          >> .gitignore
echo "config-prod.json" >> .gitignore
```

**Audit trail:**

```json
{
  "logging": {
    "enableAuditLog": true,
    "logLevel": "info",
    "logFile": "/var/log/red-team-audit.log"
  }
}
```

**Responsible disclosure — finding template:**

```markdown
## Vulnerability Report
**Severity**: High/Medium/Low
**Category**: prompt_injection/data_exfiltration/etc
**Attack Vector**: Detailed reproduction steps
**Impact**: Potential business/security impact
**Evidence**: Screenshots/logs/responses
**Remediation**: Suggested fixes
**Timeline**: Discovery and disclosure dates
```

**Stakeholder communication cadence:**

1. **Immediate** — security team notification for critical findings
2. **24h** — development team briefing with technical details
3. **Weekly** — management summary with business impact
4. **Monthly** — trend analysis and security posture review

{: .note }
The goal of red-team testing is to improve security, not break systems. Test responsibly and work collaboratively with development teams to address findings.
