"""Tests for the tool sandbox."""

import time

import pytest

from agent_security import ToolBlockedError, ToolSandbox, ToolSpec
from agent_security.sandbox import no_parent_traversal


def _read_file(path: str) -> str:
    return f"contents of {path}"


def _slow_tool() -> str:
    time.sleep(0.5)
    return "slow result"


def _search(query: str) -> str:
    return f"results for {query}"


@pytest.fixture()
def sandbox() -> ToolSandbox:
    return ToolSandbox(
        tools=[
            ToolSpec(
                name="read_file",
                fn=_read_file,
                validate=no_parent_traversal,
                description="Read a file under the working directory.",
            ),
            ToolSpec(name="web_search", fn=_search),
            ToolSpec(name="slow_tool", fn=_slow_tool),
        ],
        timeout=2.0,
        blocked_domains=["tracker.example.test"],
    )


def test_allowlisted_tool_executes(sandbox: ToolSandbox):
    assert sandbox.call("read_file", path="notes.txt") == "contents of notes.txt"


def test_unknown_tool_is_blocked(sandbox: ToolSandbox):
    with pytest.raises(ToolBlockedError, match="not allowlisted"):
        sandbox.call("send_email", to="x@example.com")


def test_arg_validator_rejects_unsafe_path(sandbox: ToolSandbox):
    with pytest.raises(ToolBlockedError, match="rejected arguments"):
        sandbox.call("read_file", path="../etc/passwd")


def test_arg_validator_rejects_absolute_path(sandbox: ToolSandbox):
    with pytest.raises(ToolBlockedError):
        sandbox.call("read_file", path="/etc/passwd")


def test_tool_timeout_raises(sandbox: ToolSandbox):
    sandbox.timeout = 0.05
    with pytest.raises(TimeoutError, match="exceeded"):
        sandbox.call("slow_tool")


def test_tool_within_timeout_succeeds(sandbox: ToolSandbox):
    sandbox.timeout = 5.0
    assert sandbox.call("slow_tool") == "slow result"


def test_blocked_domain_raises(sandbox: ToolSandbox):
    with pytest.raises(ToolBlockedError, match="blocked domain"):
        sandbox.assert_url_allowed("https://tracker.example.test/log?x=1")


def test_blocked_domain_matches_subdomains(sandbox: ToolSandbox):
    with pytest.raises(ToolBlockedError):
        sandbox.assert_url_allowed("https://api.tracker.example.test/x")


def test_allowed_domain_passes(sandbox: ToolSandbox):
    sandbox.assert_url_allowed("https://docs.example.com/guide")


def test_allowed_tools_listing(sandbox: ToolSandbox):
    assert sandbox.allowed_tools == ["read_file", "slow_tool", "web_search"]


def test_sandbox_accepts_dict_of_tools():
    sandbox = ToolSandbox(tools={"web_search": ToolSpec("web_search", _search)})
    assert sandbox.call("web_search", query="agents") == "results for agents"
