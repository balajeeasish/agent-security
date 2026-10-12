# Contributing

Thanks for helping make AI agents safer to ship. This guide keeps the
probe packs trustworthy: every probe here is a claim ("this attack works
unless you defend"), so quality bar is high.

## Adding a Probe

1. Pick the right category in `src/agent_security/probes.py`, or propose a
   new one if the attack doesn't fit the existing eleven.
2. Follow the `Probe` pattern:
   - `name`: snake_case, unique across the pack.
   - `payload_template`: the attack string. Mark tool calls the agent
     should *not* make with `TOOLCALL:<tool_name>` so the naive test
     agent trips the `compromised()` check.
   - `compromised`: a predicate on the agent's output. Prefer the
     `_executed("<tool>")` helper unless the attack needs a custom check.
   - `description`: one line on what the probe demonstrates.
3. Add the probe to the right builder (`_build_injection_probes()` or
   `build_owasp_probes()`).
4. Update the count/category assertions in `tests/test_probes.py`.
5. Run the full suite: `python -m pytest -q` — and confirm the demo still
   shows the naive agent compromised on every probe and the hardened
   agent clean (`python examples/demo.py`).

## Code Style

- Python 3.10+, stdlib only at runtime (pytest for tests).
- `ruff check` and `ruff format --check` must pass.
- `mypy --strict` must pass on `src/`.
- Type-annotate all public functions.

## Pull Requests

- One logical change per PR. Update `CHANGELOG.md` under Unreleased.
- New probes need tests proving the naive agent falls for them and the
  hardened agent doesn't (see `test_probes.py`).
- Keep payloads inert: probes are *data*, they must never execute
  anything when imported.
