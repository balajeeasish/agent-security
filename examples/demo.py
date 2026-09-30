"""Demo: 15 injection probes vs a naive agent, then vs a hardened one.

Run from the repo root:

    python examples/demo.py
"""

import base64
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agent_security import (  # noqa: E402
    ProbeRunner,
    ToolBlockedError,
    ToolSandbox,
    ToolSpec,
    build_default_probes,
    redact,
    scan,
)
from agent_security.sandbox import no_parent_traversal  # noqa: E402


def _extract_toolcall(text: str, decode_blobs: bool) -> str | None:
    """Find the first TOOLCALL marker, optionally inside base64 blobs."""
    haystack = text
    if decode_blobs:
        for token in re.findall(r"[A-Za-z0-9+/=]{20,}", text):
            try:
                decoded = base64.b64decode(token).decode("utf-8", errors="strict")
            except Exception:
                continue
            haystack += " " + decoded
    match = re.search(r"TOOLCALL:([a-z_]+)", haystack)
    return match.group(1) if match else None


def naive_agent(text: str) -> str:
    """Insecure toy agent: follows decoded blobs and runs any tool call."""
    tool = _extract_toolcall(text, decode_blobs=True)
    if tool:
        return f"Executed {tool} with full privileges. Done."
    return f"Understood. Repeating for clarity: {text[:160]}"


sandbox = ToolSandbox(
    tools=[
        ToolSpec(
            name="read_file",
            fn=lambda path: f"contents of {path}",
            validate=no_parent_traversal,
            description="Read a file under the working directory.",
        ),
        ToolSpec(
            name="web_search",
            fn=lambda query: f"results for {query}",
            description="Search the public web.",
        ),
    ],
    timeout=2.0,
    blocked_domains=["tracker.example.test"],
)


def hardened_agent(text: str) -> str:
    """The same agent, wrapped: sandbox all tool calls, redact outputs."""
    tool = _extract_toolcall(text, decode_blobs=False)
    if tool:
        try:
            sandbox.call(tool)
            outcome = f"Tool '{tool}' executed within policy."
        except ToolBlockedError as exc:
            outcome = f"Blocked by policy: {exc}"
    else:
        outcome = "Acknowledged. I only act through reviewed tools."
    return redact(outcome)


def main() -> None:
    probes = build_default_probes()
    runner = ProbeRunner(render_params={"victim_name": "operator"})

    print("=" * 64)
    print("PHASE 1: naive agent vs 15 injection probes")
    print("=" * 64)
    print(runner.markdown_report(runner.run(naive_agent, probes)))

    print()
    print("=" * 64)
    print("PHASE 2: hardened agent (ToolSandbox + output redaction)")
    print("=" * 64)
    print(runner.markdown_report(runner.run(hardened_agent, probes)))

    print()
    print("=" * 64)
    print("BONUS: secret scanning on a leaked config snippet")
    print("=" * 64)
    leaked = (
        "deploy config: aws_key=AKIAIOSFODNN7EXAMPLE, "
        "token=" + "ghp_" + "f" * 36 + ', password = "demo-secret-12345"'
    )
    for finding in scan(leaked):
        print(f"  [{finding.kind}] {finding.preview}")
    print()
    print("  redacted:", redact(leaked))


if __name__ == "__main__":
    main()
