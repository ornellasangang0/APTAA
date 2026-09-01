"""
utils/ebpf_correlator.py — eBPF/Tetragon correlation skeleton.

⚠️ PARTIALLY CONFIRMED — updated after inspecting the actual docker-compose.yml:

    services:
      mini-kali-slim:
        image: yohannesgk/mini-kali-slim:latest
        container_name: shell-executor
        ports:
          - "9756:9756"
        restart: unless-stopped

KEY FACTS THIS CONFIRMS:
  - The /exec HTTP service (port 9756) runs INSIDE the "shell-executor"
    container itself — it is NOT a host-side service doing `docker exec`.
    pentest_shell therefore talks directly to a small HTTP server embedded
    in the mini-kali-slim image, which presumably forks pentest commands
    (nmap, whois, hydra...) as its own child processes.
  - No PID is available from the /exec HTTP response (confirmed from trace
    JSON: response shape is {"stdout": ..., "stderr": ...}, no pid field).
    This is fine — container-level filtering is the standard, more robust
    approach anyway (PIDs are short-lived and easy to reuse/confuse; a
    stable container identity is not).
  - container_name "shell-executor" is FIXED in the compose file, but the
    underlying container_id (the hash Tetragon/Docker actually key on) can
    CHANGE if the container is recreated (`restart: unless-stopped` does
    NOT guarantee the same container_id survives, e.g. after `docker compose
    up` is rerun or the container crashes and compose recreates it).
    → resolve_container_id() below does name→ID resolution at correlation
      time rather than hardcoding an ID, so this stays correct across restarts.
  - No `pid: host` in the compose file → the container has its own PID
    namespace (good security default). Tetragon must observe within that
    container's namespace/cgroup, not look for a host-level PID.

STILL TO CONFIRM WITH THE KERNEL-TRACING SIDE BEFORE THIS IS FUNCTIONAL:

  - Can Tetragon's TracingPolicy filter by container_id directly? (Typical:
    yes, via the `containerID` field humans usually fetch once via
    `docker inspect shell-executor --format '{{.Id}}'` and feed into the
    policy, OR some Tetragon setups support filtering by pod/container name
    labels directly — confirm which applies to her setup.)
  - What format will Tetragon export events in, and where will this script
    read them from? (Recommend JSON Lines to a file as the simplest start,
    matching exec_events.jsonl's format.)
  - Since container_id can change across container recreation, does her
    pipeline re-resolve it automatically, or does it need a restart of the
    Tetragon policy too? Worth scripting both sides to refresh together.
  - Clock skew between wherever Blacksmith's Python runs and the host kernel
    clock Tetragon timestamps against — if same host (likely here, given
    `localhost:9756`), skew should be negligible, but worth a sanity check.

USAGE (once the kernel event source is confirmed):

    from utils.ebpf_correlator import correlate_engagement, resolve_container_id

    container_id = resolve_container_id("shell-executor")
    correlate_engagement(
        exec_event_log_path="/var/log/blacksmith/exec_events.jsonl",
        kernel_event_log_path="/var/log/tetragon/events.jsonl",  # TBD format
        report_builder=report_builder,
        expected_container_id=container_id,
    )
"""

import json
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger("ebpf_correlator")

DEFAULT_GRACE_SECONDS = 5.0

# Fixed in docker-compose.yml — the underlying container_id can still change
# across recreations, so always resolve fresh rather than hardcoding the ID.
SHELL_EXECUTOR_CONTAINER_NAME = "shell-executor"


def resolve_container_id(container_name: str = SHELL_EXECUTOR_CONTAINER_NAME) -> str | None:
    """
    Resolve a Docker container name to its current container_id via
    `docker inspect`. This is the value Tetragon's TracingPolicy will
    typically need to scope observation to just this container.

    Returns None if Docker isn't reachable or the container isn't running —
    callers should treat that as "cannot correlate yet, container may be down".
    """
    try:
        result = subprocess.run(
            ["docker", "inspect", container_name, "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            logger.warning(
                f"[CORRELATOR] could not resolve container '{container_name}': "
                f"{result.stderr.strip()}"
            )
            return None
        container_id = result.stdout.strip()
        return container_id or None
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning(f"[CORRELATOR] docker inspect failed: {e}")
        return None


def _load_jsonl(path: str) -> list[dict[str, Any]]:
    """Load a JSON Lines file into a list of dicts. Returns [] if missing."""
    import os
    if not os.path.exists(path):
        logger.warning(f"[CORRELATOR] file not found: {path}")
        return []
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning(f"[CORRELATOR] skipping malformed line in {path}")
    return events


def correlate_engagement(
    exec_event_log_path: str,
    kernel_event_log_path: str,
    report_builder,  # ATTCKReportBuilder — typed loosely to avoid circular import
    expected_container_id: str | None = None,
    grace_seconds: float = DEFAULT_GRACE_SECONDS,
) -> dict[str, int]:
    """
    Correlate Blacksmith's declared exec events against kernel-observed events
    and upgrade the report's evidence_status accordingly.

    Args:
        exec_event_log_path: path to utils/exec_event_log.py's JSONL output.
        kernel_event_log_path: path to the Tetragon/Falco JSONL event export.
        report_builder: the live ATTCKReportBuilder for this engagement.
        expected_container_id: result of resolve_container_id("shell-executor").
            If provided, kernel events from OTHER containers are ignored —
            critical on a host running multiple containers, otherwise a
            coincidental execve(nmap) elsewhere could be wrongly matched.
            If None, no container filtering is applied (only safe on a host
            running a single container, not recommended otherwise).
        grace_seconds: time window padding around request/response timestamps.

    ⚠️ PLACEHOLDER SCHEMA — the kernel_event shape assumed below
    (`binary`, `timestamp`, `pid`, `container_id`) is a best-guess based on
    typical Tetragon/Falco execve event exports. Confirm the real schema with
    the kernel-tracing side and adjust `_kernel_event_matches()` /
    `_find_kernel_match()` accordingly before relying on this.

    Returns a summary dict: {"confirmed": N, "disputed": N, "unmatched": N}
    """
    exec_events = _load_jsonl(exec_event_log_path)
    kernel_events = _load_jsonl(kernel_event_log_path)

    if expected_container_id:
        before = len(kernel_events)
        kernel_events = [
            ev for ev in kernel_events
            if ev.get("container_id") == expected_container_id
            # Tetragon sometimes truncates IDs to 12 chars (Docker short form) —
            # also accept a prefix match as a fallback.
            or (ev.get("container_id") and expected_container_id.startswith(ev["container_id"]))
        ]
        logger.info(
            f"[CORRELATOR] filtered kernel events to container "
            f"{expected_container_id[:12]}: {before} → {len(kernel_events)}"
        )
    else:
        logger.warning(
            "[CORRELATOR] no expected_container_id provided — matching against "
            "ALL kernel events on the host. Only safe if shell-executor is the "
            "only relevant container running."
        )

    logger.info(
        f"[CORRELATOR] loaded {len(exec_events)} declared events, "
        f"{len(kernel_events)} kernel events after filtering"
    )

    summary = {"confirmed": 0, "disputed": 0, "unmatched": 0}

    for declared in exec_events:
        match = _find_kernel_match(declared, kernel_events, grace_seconds)

        if match is None:
            summary["unmatched"] += 1
            continue

        if match["binary"] == declared.get("binary"):
            report_builder.upgrade_evidence_status(
                exec_event_id=declared["event_id"],
                new_status="kernel_confirmed",
                kernel_details=(
                    f"execve({match.get('binary')}) observed at "
                    f"{match.get('timestamp')} (PID {match.get('pid', '?')}, "
                    f"container {expected_container_id[:12] if expected_container_id else match.get('container_id', '?')})"
                ),
            )
            summary["confirmed"] += 1
        else:
            report_builder.upgrade_evidence_status(
                exec_event_id=declared["event_id"],
                new_status="disputed",
                kernel_details=(
                    f"Expected binary '{declared.get('binary')}' but kernel observed "
                    f"'{match.get('binary')}' in the matching time window"
                ),
            )
            summary["disputed"] += 1

    logger.info(f"[CORRELATOR] result: {summary}")
    return summary


def _find_kernel_match(
    declared: dict[str, Any],
    kernel_events: list[dict[str, Any]],
    grace_seconds: float,
) -> dict[str, Any] | None:
    """
    PLACEHOLDER matching logic. Assumes kernel_events entries look like:
        {"binary": "nmap", "timestamp": "2026-06-30T14:32:15+00:00", "pid": 1234, ...}
    Update this once the real Tetragon/Falco event schema is confirmed.
    """
    try:
        window_start = datetime.fromisoformat(declared["request_sent_at"]) - timedelta(seconds=grace_seconds)
        window_end = datetime.fromisoformat(declared["response_received_at"]) + timedelta(seconds=grace_seconds)
    except (KeyError, ValueError):
        return None

    for kev in kernel_events:
        try:
            kts = datetime.fromisoformat(kev["timestamp"])
        except (KeyError, ValueError):
            continue

        if window_start <= kts <= window_end:
            return kev

    return None


if __name__ == "__main__":
    container_id = resolve_container_id(SHELL_EXECUTOR_CONTAINER_NAME)
    if container_id:
        print(f"Resolved '{SHELL_EXECUTOR_CONTAINER_NAME}' → container_id: {container_id}")
        print(
            "This is the value to give the kernel-tracing side for their "
            "Tetragon TracingPolicy container filter.\n"
        )
    else:
        print(
            f"Could not resolve container '{SHELL_EXECUTOR_CONTAINER_NAME}' — "
            "is it running? (`docker ps` to check)\n"
        )

    print(
        "Full correlation is still a design skeleton beyond container "
        "resolution — see the module docstring for what needs to be "
        "confirmed with the kernel-tracing (Tetragon/Falco) side before "
        "this can produce real kernel_confirmed / disputed evidence statuses."
    )
