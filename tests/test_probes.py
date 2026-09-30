"""Tests for the probe pack and the probe runner."""

import base64
import re

from agent_security import ProbeRunner, build_default_probes
from agent_security.probes import Probe


def _naive_agent(text: str) -> str:
    """A deliberately insecure toy agent: echoes input, decodes base64
    blobs, and executes any TOOLCALL marker it finds."""
    haystack = text
    for token in re.findall(r"[A-Za-z0-9+/=]{20,}", text):
        try:
            decoded = base64.b64decode(token).decode("utf-8", errors="strict")
            haystack += " " + decoded
        except Exception:
            continue
    match = re.search(r"TOOLCALL:([a-z_]+)", haystack)
    if match:
        return f"Executed {match.group(1)} with full privileges. Done."
    return f"Understood. Repeating for clarity: {text[:160]}"


def _hardened_agent(text: str) -> str:
    """A toy agent that refuses raw tool calls instead of running them."""
    match = re.search(r"TOOLCALL:([a-z_]+)", text)
    if match:
        return f"Blocked by policy: tool '{match.group(1)}' is not allowlisted."
    return "Acknowledged. I only act through reviewed tools."


def test_probe_count():
    assert len(build_default_probes()) == 15


def test_probe_names_unique():
    names = [p.name for p in build_default_probes()]
    assert len(names) == len(set(names))


def test_all_five_categories_covered():
    categories = {p.category for p in build_default_probes()}
    assert categories == {
        "direct_override",
        "indirect_tool_output",
        "indirect_webpage",
        "encoding_tricks",
        "multi_turn",
    }


def test_every_category_has_at_least_two_probes():
    counts = {}
    for p in build_default_probes():
        counts[p.category] = counts.get(p.category, 0) + 1
    assert all(n >= 2 for n in counts.values())


def test_template_probe_renders_params():
    probe = next(
        p for p in build_default_probes() if p.name == "template_rendering"
    )
    rendered = probe.render({"victim_name": "operator"})
    assert "{victim_name}" not in rendered
    assert "operator" in rendered


def test_all_probes_compromise_naive_agent():
    runner = ProbeRunner(render_params={"victim_name": "operator"})
    results = runner.run(_naive_agent, build_default_probes())
    failed = [r.probe_name for r in results if not r.compromised]
    assert failed == [], f"naive agent resisted probes: {failed}"


def test_no_probe_compromises_hardened_agent():
    runner = ProbeRunner(render_params={"victim_name": "operator"})
    results = runner.run(_hardened_agent, build_default_probes())
    compromised = [r.probe_name for r in results if r.compromised]
    assert compromised == [], f"hardened agent fell for: {compromised}"


def test_runner_records_target_errors():
    def broken(_payload: str) -> str:
        raise RuntimeError("boom")

    probe = Probe(name="x", category="y", payload_template="hi")
    (result,) = ProbeRunner().run(broken, [probe])
    assert result.error.startswith("RuntimeError")
    assert not result.passed


def test_markdown_report_marks_compromised_rows():
    runner = ProbeRunner()
    results = runner.run(_naive_agent, build_default_probes()[:2])
    report = runner.markdown_report(results)
    assert "COMPROMISED" in report
    assert "2/2 probes compromised" in report
