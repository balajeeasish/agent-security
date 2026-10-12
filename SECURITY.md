# Security Policy

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead, use [GitHub's private vulnerability reporting](https://github.com/balajeeasish/agent-security/security/advisories/new) on this repository. You can also reach the maintainer through the contact links on [the maintainer's GitHub profile](https://github.com/balajeeasish).

We aim to acknowledge reports within 3 business days and to ship a fix or mitigation within 30 days, depending on severity.

## Scope

This is a security *testing* library: its job is to find weaknesses in AI agents, not to be a hardened runtime itself. That said, we treat the integrity of the probe packs seriously:

- **Probe payloads are attack strings by design.** They are inert data used to test *your* agents. They never execute anything on their own.
- **In scope:** a probe that fails to detect a compromise it claims to cover, a sandbox bypass in `ToolSandbox`, a secret pattern missed by `scan()`.
- **Out of scope:** the behavior of agents you test with this library, and findings that require a live LLM API key to reproduce (include a redacted transcript instead).

## Safe Harbor

We consider security research conducted in good faith against this repository — following this policy and without accessing other users' data — to be authorized. We will not pursue legal action for such research.
