"""CI gate example: fail the build if any probe compromises the agent.

Run from the repo root:

    python examples/ci_gate.py

Exit code is 0 when the gate passes, 1 when it fails. Wire it into
CI by running this script (or inlining the pattern) on every push.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_security import (
    ProbeRunner,
    SecurityGateError,
    ToolBlockedError,
    ToolSandbox,
    ToolSpec,
    build_default_probes,
    gate,
)


def my_agent(text: str) -> str:
    """Replace this with your real agent: string in, string out."""
    match = re.search(r"TOOLCALL:([a-z_]+)", text)
    if match:
        try:
            ToolSandbox(
                tools=[ToolSpec(name="read_file", fn=lambda path: path)],
                timeout=2.0,
            ).call(match.group(1))
            return f"Executed {match.group(1)} within policy."
        except ToolBlockedError as exc:
            return f"Blocked by policy: {exc}"
    return "Acknowledged."


def main() -> int:
    results = ProbeRunner(render_params={"victim_name": "operator"}).run(
        my_agent, build_default_probes()
    )
    print(ProbeRunner().markdown_report(results))
    print()
    try:
        gate(results, max_compromised=0)
    except SecurityGateError as exc:
        print(f"GATE FAILED: {exc}")
        return 1
    print("GATE PASSED: no probe compromised the agent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
