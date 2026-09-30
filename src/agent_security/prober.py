"""Probe runner: execute probes against a target agent function."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Sequence

from agent_security.probes import Probe


@dataclass
class ProbeResult:
    """Outcome of running one probe against the target."""

    probe_name: str
    category: str
    compromised: bool
    output_preview: str = ""
    error: str = ""

    @property
    def passed(self) -> bool:
        """A probe passes when the agent was NOT compromised."""
        return not self.compromised and not self.error


class ProbeRunner:
    """Runs probes against a target agent callable and reports results.

    The target is any callable that takes a string (the probe payload) and
    returns a string (the agent's output). Keeping the interface this small
    means you can test anything: a raw LLM call, a LangChain agent, or a
    full multi-tool loop.
    """

    def __init__(self, render_params: Dict[str, str] | None = None) -> None:
        self.render_params = render_params or {}

    def run(
        self,
        target_fn: Callable[[str], str],
        probes: Sequence[Probe],
    ) -> List[ProbeResult]:
        results: List[ProbeResult] = []
        for probe in probes:
            payload = probe.render(self.render_params)
            try:
                output = target_fn(payload) or ""
                results.append(
                    ProbeResult(
                        probe_name=probe.name,
                        category=probe.category,
                        compromised=probe.compromised(output),
                        output_preview=output[:200],
                    )
                )
            except Exception as exc:  # noqa: BLE001 - report, don't crash
                results.append(
                    ProbeResult(
                        probe_name=probe.name,
                        category=probe.category,
                        compromised=False,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
        return results

    def markdown_report(self, results: Sequence[ProbeResult]) -> str:
        total = len(results)
        compromised = sum(1 for r in results if r.compromised)
        errored = sum(1 for r in results if r.error)
        passed = total - compromised - errored

        lines = [
            "# Probe Report",
            "",
            f"**{compromised}/{total} probes compromised the target** "
            f"({passed} passed, {errored} errored).",
            "",
            "| Probe | Category | Result |",
            "| --- | --- | --- |",
        ]
        for r in results:
            if r.error:
                status = f"ERROR ({r.error})"
            elif r.compromised:
                status = "COMPROMISED"
            else:
                status = "PASS"
            lines.append(f"| {r.probe_name} | {r.category} | {status} |")
        lines += [
            "",
            "A COMPROMISED row means the injected instruction was followed. "
            "Fix the agent (sandbox tools, validate inputs, redact outputs) "
            "and re-run until the report is clean.",
        ]
        return "\n".join(lines)
