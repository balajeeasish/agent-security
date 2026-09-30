"""Tool sandbox: allowlist, argument validation, timeouts, domain blocks.

The core rule of agent security is simple: an agent should only be able to
do what you explicitly allow, with arguments you have validated, for as
long as you permit. ToolSandbox enforces all three.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List
from urllib.parse import urlparse


class ToolBlockedError(Exception):
    """Raised when a tool call is denied by sandbox policy."""


@dataclass
class ToolSpec:
    """A tool the agent is allowed to call, with its argument rules."""

    name: str
    fn: Callable[..., Any]
    validate: Callable[[Dict[str, Any]], None] | None = None
    description: str = ""


class ToolSandbox:
    """Gate every tool call behind an allowlist, validators, and timeouts."""

    def __init__(
        self,
        tools: Iterable[ToolSpec] | Dict[str, ToolSpec],
        timeout: float = 5.0,
        blocked_domains: Iterable[str] | None = None,
    ) -> None:
        if isinstance(tools, dict):
            self._tools = dict(tools)
        else:
            self._tools = {t.name: t for t in tools}
        self.timeout = timeout
        self.blocked_domains: List[str] = [d.lower() for d in (blocked_domains or [])]

    @property
    def allowed_tools(self) -> List[str]:
        return sorted(self._tools)

    def call(self, name: str, **kwargs: Any) -> Any:
        """Run a tool call through the policy checks, then execute it."""
        spec = self._tools.get(name)
        if spec is None:
            raise ToolBlockedError(
                f"tool '{name}' is not allowlisted "
                f"(allowed: {', '.join(self.allowed_tools) or 'none'})"
            )
        if spec.validate is not None:
            try:
                spec.validate(kwargs)
            except ValueError as exc:
                raise ToolBlockedError(
                    f"tool '{name}' rejected arguments: {exc}"
                ) from exc
        return self._run_with_timeout(spec, kwargs)

    def _run_with_timeout(self, spec: ToolSpec, kwargs: Dict[str, Any]) -> Any:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(spec.fn, **kwargs)
            try:
                return future.result(timeout=self.timeout)
            except concurrent.futures.TimeoutError as exc:
                raise TimeoutError(
                    f"tool '{spec.name}' exceeded {self.timeout}s timeout"
                ) from exc

    def assert_url_allowed(self, url: str) -> None:
        """Raise ToolBlockedError if the URL hits a blocked domain."""
        host = (urlparse(url).hostname or "").lower()
        for domain in self.blocked_domains:
            if host == domain or host.endswith("." + domain):
                raise ToolBlockedError(
                    f"url '{url}' hits blocked domain '{domain}'"
                )


def no_parent_traversal(args: Dict[str, Any]) -> None:
    """Example validator: file paths may not escape their directory."""
    path = str(args.get("path", ""))
    if ".." in path or path.startswith("/"):
        raise ValueError(f"unsafe path: {path!r}")
