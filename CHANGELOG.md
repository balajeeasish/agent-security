# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and versioning follows
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-12

### Added
- OWASP Top 10 for Agentic Applications probe pack: 27 probes across
  `memory_poisoning`, `inter_agent`, `supply_chain`, `goal_hijack`,
  `privilege_abuse`, and `cascading_failure` (`build_owasp_probes()`).
- `ProbeRunner.json_report()`: machine-readable summary, per-category, and
  per-probe results.
- `ProbeRunner.sarif_report()`: SARIF 2.1.0 output for GitHub code scanning
  and enterprise security dashboards.
- `gate()` / `SecurityGateError`: fail-closed CI gate with a configurable
  compromise threshold; `examples/ci_gate.py` drop-in script.
- `SECURITY.md` vulnerability disclosure policy, `CONTRIBUTING.md`,
  issue and pull-request templates.
- CI now runs ruff, mypy (strict), and a coverage gate (>=90%) across
  Python 3.10–3.12.

### Changed
- Default pack is now 42 probes across 11 categories (was 15 across 5).
- README documents the OWASP Top 10 coverage map.

## [0.1.0] - 2026-09-30

### Added
- Initial release: 15 injection probes (`direct_override`,
  `indirect_tool_output`, `indirect_webpage`, `encoding_tricks`,
  `multi_turn`), `ProbeRunner` with Markdown reports, `ToolSandbox`
  (allowlists, arg validators, timeouts, blocked domains), and secret
  scanning/redaction (`scan`, `redact`).
