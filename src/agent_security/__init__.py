"""agent-security: security testing primitives for AI agents.

Injection probes, tool sandboxing, and secret scanning for teams that
ship agents to production. Stdlib only.
"""

from agent_security.prober import ProbeRunner, SecurityGateError, gate
from agent_security.probes import Probe, build_default_probes, build_owasp_probes
from agent_security.sandbox import ToolBlockedError, ToolSandbox, ToolSpec
from agent_security.secrets import Finding, redact, scan

__all__ = [
    "Probe",
    "ProbeRunner",
    "SecurityGateError",
    "ToolBlockedError",
    "ToolSandbox",
    "ToolSpec",
    "Finding",
    "build_default_probes",
    "build_owasp_probes",
    "gate",
    "redact",
    "scan",
]

__version__ = "0.1.0"
