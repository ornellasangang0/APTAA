"""
utils/exec_event_log.py — Command execution intent logger for eBPF correlation.

PROBLEM:
attck_tagger / ATTCKReportBuilder currently produce ATT&CK mappings based on
what Blacksmith AI *says* it did (the command string + LLM-summarized output).
This is a self-declared mapping, not an observation. For someone instrumenting
the Kali container with eBPF (Tetragon/Falco), this has zero evidentiary value:
there's no way to verify "the agent claims it ran nmap" actually corresponds
to "the kernel saw an execve(nmap) in that container".

WHAT THIS FILE DOES:
Provides a lightweight, append-only JSONL event log of every command Blacksmith
sends to the pentest_shell /exec endpoint, with PRECISE timestamps bracketing
the call (before request, after response). This becomes the "intent" side of
a future correlation pipeline:

    Blacksmith intent event (this file)
              +
    Tetragon/Falco kernel event (execve, connect, openat...)
              =
    Correlated, evidence-based ATT&CK mapping

CORRELATION STRATEGY (since the /exec service is a third-party black box and
does not return a PID):
  - Match by TIME WINDOW: kernel events whose timestamp falls between
    `request_sent_at` and `response_received_at` (+ a small grace margin,
    e.g. 2-5s, to account for network/exec latency) are candidates.
  - Match by BINARY NAME: the first whitespace-separated token of `command`
    (e.g. "nmap" from "nmap -sS -p- 10.0.4.66") should match the `binary`
    field of the execve event Tetragon reports.
  - If multiple commands from the same agent overlap in time (rare, since
    pentest_shell calls are sequential per agent), the correlator should flag
    ambiguous matches rather than silently picking one — this is a job for
    the correlation script discussed separately with the kernel-tracing side.

This file does NOT do the correlation itself (that requires the Tetragon/Falco
event stream, which doesn't exist yet) — it only guarantees Blacksmith side
data is complete, precise, and ready to be joined later.

OUTPUT FORMAT (JSONL, one event per line, append-only):
{
    "event_id": "uuid4",
    "engagement_id": "BB-...",
    "agent": "recon_agent",
    "command": "nmap -sS -p- 10.0.4.66",
    "binary": "nmap",
    "container_target": "10.0.4.66",          # best-effort extraction, may be null
    "request_sent_at": "2026-06-30T14:32:10.123456+00:00",
    "response_received_at": "2026-06-30T14:32:41.789012+00:00",
    "duration_seconds": 31.665556,
    "status_code": 200,
    "correlation_status": "pending"             # pending | matched | unmatched
}
"""

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

# Default log location — mount this path as a shared volume between
# Blacksmith and whatever tooling will later run the correlator.
#
# Defaults to a project-local "logs/" directory rather than /var/log/blacksmith/
# to avoid requiring root permissions to create system directories — this was
# the cause of a startup crash (PermissionError on os.makedirs) when running
# as a non-root user. Override via the EXEC_EVENT_LOG_PATH env var if you want
# a system-wide location and have the permissions to create it (e.g. set up
# /var/log/blacksmith/ with appropriate ownership ahead of time, or run the
# container/service as a user with write access to it).
DEFAULT_LOG_PATH = os.getenv("EXEC_EVENT_LOG_PATH", "./logs/exec_events.jsonl")

_write_lock = threading.Lock()


def _extract_binary(command: str) -> str:
    """Best-effort extraction of the primary binary name from a shell command."""
    stripped = command.strip()
    if not stripped:
        return ""
    # Take the first whitespace-separated token, strip path components
    first_token = stripped.split()[0]
    return os.path.basename(first_token)


def _extract_target(command: str) -> str | None:
    """
    Best-effort extraction of a target IP/hostname from the command string.
    Not authoritative — just a convenience hint for manual review.
    """
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    match = re.search(ip_pattern, command)
    if match:
        return match.group(0)

    # Fallback: look for something that looks like a hostname/URL after http(s)://
    url_pattern = r"https?://([^\s/:]+)"
    match = re.search(url_pattern, command)
    if match:
        return match.group(1)

    return None


class ExecEventLogger:
    """
    Thread-safe append-only logger for pentest_shell execution intent events.

    Usage (typically called by ATTCKAutoTagMiddleware or directly inside
    pentest_shell, bracketing the actual /exec HTTP call):

        logger = ExecEventLogger(engagement_id="BB-20260630-...")

        request_sent_at = datetime.now(timezone.utc)
        response = requests.post(container_uri, json={"cmd": command})
        response_received_at = datetime.now(timezone.utc)

        logger.log_event(
            agent="recon_agent",
            command=command,
            request_sent_at=request_sent_at,
            response_received_at=response_received_at,
            status_code=response.status_code,
        )
    """

    def __init__(self, engagement_id: str, log_path: str = DEFAULT_LOG_PATH):
        self.engagement_id = engagement_id
        self.log_path = log_path
        self._enabled = True

        try:
            os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        except (PermissionError, OSError) as e:
            # Don't crash app startup over a logging path issue — disable
            # exec event logging for this session and let the rest of
            # Blacksmith run normally. The ATT&CK report will simply have
            # no kernel-correlation join keys (evidence_status stays
            # "declared" forever for this session), but everything else
            # (pentest_shell execution, ATT&CK tagging via KB/LLM) keeps
            # working.
            logging.getLogger("exec_event_log").warning(
                f"[EXEC-LOG] could not create log directory for '{self.log_path}' "
                f"({e}). Exec event logging disabled for this session — set "
                f"EXEC_EVENT_LOG_PATH to a writable path to enable it."
            )
            self._enabled = False

    def log_event(
        self,
        agent: str,
        command: str,
        request_sent_at: datetime,
        response_received_at: datetime,
        status_code: int | None = None,
    ) -> dict[str, Any] | None:
        """
        Record one command execution intent event. Returns the event dict
        that was written, or None if logging is disabled for this session
        (e.g. due to a filesystem permission issue at startup).
        """
        event = {
            "event_id": str(uuid.uuid4()),
            "engagement_id": self.engagement_id,
            "agent": agent,
            "command": command,
            "binary": _extract_binary(command),
            "container_target": _extract_target(command),
            "request_sent_at": request_sent_at.isoformat(),
            "response_received_at": response_received_at.isoformat(),
            "duration_seconds": (response_received_at - request_sent_at).total_seconds(),
            "status_code": status_code,
            "correlation_status": "pending",
        }

        if not self._enabled:
            return event  # still return it so callers can use event_id etc. in-memory

        try:
            with _write_lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except (PermissionError, OSError) as e:
            logging.getLogger("exec_event_log").warning(
                f"[EXEC-LOG] failed to write event (disabling further writes "
                f"this session): {e}"
            )
            self._enabled = False

        return event

    def read_all_events(self) -> list[dict[str, Any]]:
        """Read back all logged events for this log file (useful for the correlator)."""
        if not self._enabled or not os.path.exists(self.log_path):
            return []
        events = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        except (PermissionError, OSError) as e:
            logging.getLogger("exec_event_log").warning(
                f"[EXEC-LOG] failed to read event log: {e}"
            )
        return events
