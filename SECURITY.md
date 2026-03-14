# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in wb-red-team, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email **security@votal.ai** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Scope

This project is a security testing tool designed to find vulnerabilities in AI agent applications. The attack payloads and techniques contained in this repository are intentional and for authorized testing purposes only.

**In scope:**
- Vulnerabilities in the framework itself (config parsing, report generation, dashboard, auth handling)
- Dependency vulnerabilities
- Information disclosure in generated reports

**Out of scope:**
- Attack payloads and seed attacks (these are intentionally adversarial by design)
- Vulnerabilities in the demo target app (it is intentionally vulnerable for testing)

## Responsible Use

This tool is intended for authorized security testing of AI applications you own or have permission to test. Unauthorized use against third-party systems is prohibited.
