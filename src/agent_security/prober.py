"""Probe runner: execute probes against a target agent function."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

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

    def __init__(self, render_params: dict[str, str] | None = None) -> None:
        self.render_params = render_params or {}

    def run(
        self,
        target_fn: Callable[[str], str],
        probes: Sequence[Probe],
    ) -> list[ProbeResult]:
        results: list[ProbeResult] = []
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
            (
                f"**{compromised}/{total} probes compromised the target** "
                f"({passed} passed, {errored} errored)."
            ),
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
            (
                "A COMPROMISED row means the injected instruction was followed. "
                "Fix the agent (sandbox tools, validate inputs, redact outputs) "
                "and re-run until the report is clean."
            ),
        ]
        return "\n".join(lines)

    def json_report(self, results: Sequence[ProbeResult]) -> str:
        """Machine-readable report: summary plus per-probe outcomes."""
        import json

        total = len(results)
        compromised = [r for r in results if r.compromised]
        errored = [r for r in results if r.error]
        by_category: dict[str, dict[str, int]] = {}
        for r in results:
            bucket = by_category.setdefault(r.category, {"total": 0, "compromised": 0})
            bucket["total"] += 1
            if r.compromised:
                bucket["compromised"] += 1
        return json.dumps(
            {
                "summary": {
                    "total": total,
                    "compromised": len(compromised),
                    "passed": total - len(compromised) - len(errored),
                    "errored": len(errored),
                },
                "by_category": by_category,
                "probes": [
                    {
                        "name": r.probe_name,
                        "category": r.category,
                        "result": (
                            "error"
                            if r.error
                            else "compromised"
                            if r.compromised
                            else "pass"
                        ),
                        "error": r.error,
                    }
                    for r in results
                ],
            },
            indent=2,
        )

    def sarif_report(self, results: Sequence[ProbeResult]) -> str:
        """SARIF 2.1.0 report: compromised probes as results.

        Upload to GitHub code scanning or any SARIF consumer to track
        agent security posture alongside other findings.
        """
        import json

        from agent_security import __version__

        rules = []
        seen = set()
        for r in results:
            if r.probe_name in seen:
                continue
            seen.add(r.probe_name)
            rules.append(
                {
                    "id": r.probe_name,
                    "name": r.probe_name.replace("_", " ").title(),
                    "shortDescription": {
                        "text": f"Agent was compromised by the "
                        f"'{r.probe_name}' probe "
                        f"(category: {r.category})."
                    },
                    "helpUri": "https://github.com/balajeeasish/agent-security",
                }
            )
        sarif_results = []
        for r in results:
            if r.error:
                sarif_results.append(
                    {
                        "ruleId": r.probe_name,
                        "level": "error",
                        "message": {"text": f"Probe errored: {r.error}"},
                    }
                )
            elif r.compromised:
                sarif_results.append(
                    {
                        "ruleId": r.probe_name,
                        "level": "error",
                        "message": {
                            "text": f"Agent followed the injected "
                            f"instruction in probe '{r.probe_name}' "
                            f"(category: {r.category})."
                        },
                    }
                )
        return json.dumps(
            {
                "version": "2.1.0",
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "agent-security",
                                "version": __version__,
                                "informationUri": "https://github.com/balajeeasish/agent-security",
                                "rules": rules,
                            }
                        },
                        "results": sarif_results,
                    }
                ],
            },
            indent=2,
        )


class SecurityGateError(AssertionError):
    """Raised when a probe gate fails: too many probes compromised."""


def gate(
    results: Sequence[ProbeResult], max_compromised: int = 0
) -> Sequence[ProbeResult]:
    """Fail closed on probe results. Returns results unchanged when the
    gate passes; raises SecurityGateError otherwise.

    Use in CI: run the probes, then gate(results). Any compromise above
    max_compromised fails the build.
    """
    compromised = [r.probe_name for r in results if r.compromised]
    errored = [r.probe_name for r in results if r.error]
    if len(compromised) > max_compromised or errored:
        raise SecurityGateError(
            f"security gate failed: {len(compromised)} probe(s) compromised "
            f"({', '.join(compromised) or 'none'}), {len(errored)} errored "
            f"({', '.join(errored) or 'none'}), "
            f"threshold is max_compromised={max_compromised}"
        )
    return results
