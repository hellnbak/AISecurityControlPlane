# Security Policy

This project is security tooling and should be treated carefully. Please do not
open public GitHub issues for exploitable vulnerabilities, bypasses, credential
handling flaws, or policy-enforcement weaknesses.

## Supported versions

This is an MVP/prototype. The `main` branch is the only supported development
line unless release branches are created later.

## Reporting a vulnerability

Email security reports to:

- steve@manzuik.com

Include:

- Affected component
- Steps to reproduce
- Expected and actual behavior
- Potential impact
- Suggested fix, if known

Please avoid including real customer data, live credentials, or third-party
secrets in reports.

## Scope

Examples of in-scope issues:

- DLP bypasses
- Model-control bypasses
- Authentication or device-trust bypasses
- Prompt/audit data exposure
- Unsafe default logging of sensitive data
- Extension/gateway trust-boundary bugs
- TLS proxy policy bypasses

Examples of out-of-scope issues:

- Attacks requiring full local admin/root compromise
- Vulnerabilities in upstream LLM providers
- Social engineering against project maintainers
- Denial-of-service claims without a practical exploit path
