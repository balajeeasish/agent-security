## What changed
<!-- One logical change per PR. -->

## Probe checklist (if adding probes)
- [ ] New probe(s) added to the right builder in `probes.py`
- [ ] `tests/test_probes.py` counts/categories updated
- [ ] Naive agent is compromised by the new probe(s); hardened agent is not
- [ ] `CHANGELOG.md` updated

## Verification
- [ ] `python -m pytest -q` passes
- [ ] `ruff check` and `ruff format --check` pass
- [ ] `mypy --strict src/` passes
- [ ] `python examples/demo.py` shows the expected naive/hardened split
