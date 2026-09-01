"""
utils/attck_report.py — ATT&CK engagement report builder for Blacksmith AI.

⚠️ EVIDENCE MODEL — READ BEFORE USING THIS REPORT FOR DETECTION ENGINEERING:

Every event in this report has an `evidence_status` field:

  - "declared"         : Blacksmith AI ran a command and a keyword/LLM lookup
                          mapped it to an ATT&CK technique. This is SELF-REPORTED
                          by the agent stack — it has NOT been verified against
                          what actually happened inside the target container.
  - "kernel_confirmed"  : A downstream eBPF correlator (Tetragon/Falco) matched
                          this declared event to a real kernel event (execve,
                          connect, openat...) within the expected time window
                          and the same target/binary. This status does not exist
                          yet in this codebase — it is set by the correlator
                          script once the eBPF pipeline is built (see
                          utils/exec_event_log.py for the join key strategy).
  - "disputed"          : A correlator found a kernel event in the time window
                           but it doesn't match what was declared (wrong binary,
                           no network activity when one was expected, etc.).
                           Also not yet implemented — reserved for the correlator.

As of this version, EVERY event will show "declared" because the eBPF
correlation pipeline does not exist yet. Do not present this report as proof
of what happened on the target system — it is proof of what Blacksmith AI
*attempted* and *claims* to have done. The `exec_event_id` field on each
event is the join key into utils/exec_event_log.py's JSONL log, which is
what a kernel-level correlator needs to verify these claims.

Accumulates ATT&CK-tagged events during a pentest engagement and produces a
structured Markdown report with the mapping:
    Event → Capability (tool/command) → ATT&CK TTP → Evidence Status

Usage:
    from utils.attck_report import ATTCKReportBuilder

    builder = ATTCKReportBuilder(target="10.10.1.5", engagement_id="BB-2025-001")
    builder.add_event(attck_tagger_result)  # dict returned by attck_tagger tool
                                             # or ATTCKAutoTagMiddleware
    ...
    builder.save_report("/reports/attck_report.md")
"""

from datetime import datetime, timedelta, timezone
from collections import defaultdict, Counter
import json
import os


class ATTCKReportBuilder:

    # Max total size of the evidence buffer — generous enough for a long
    # engagement (many pentest_shell/web_search/shell_documentation calls)
    # without unbounded memory growth over a session.
    MAX_EVIDENCE_CHARS = 2_000_000

    def __init__(self, target: str = "unknown", engagement_id: str = ""):
        self.target = target
        self.engagement_id = engagement_id or f"BB-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.start_time = datetime.now()
        self.events: list[dict] = []

        # ── Evidence buffer for CVE claim validation (utils/cve_validator.py) ──
        # PROBLEM THIS SOLVES: the orchestrator's own conversation history does
        # NOT contain the raw tool outputs from sub-agents (ReconAgent,
        # ScanEnumAgent, etc.) — deepagents sub-agents run their own internal
        # tool-call loop and only return a summarized final message to the
        # orchestrator. A CVE validator that only scans the orchestrator's
        # messages will therefore NEVER find real evidence, even when a CVE
        # was genuinely confirmed by a sub-agent's nmap/nuclei/searchsploit
        # output — confirmed by a real session where CVE-2011-2523 appeared
        # in vsftpd exploit code but the validator (looking at orchestrator
        # messages only) reported it as unverified even though it was
        # arguably legitimate.
        #
        # FIX: ATTCKAutoTagMiddleware runs INSIDE each sub-agent's own
        # wrap_tool_call/awrap_tool_call hook (see middleware/attck_autotag.py),
        # so it has direct access to real tool outputs regardless of which
        # agent produced them. It appends raw output text here via
        # add_evidence(), and cve_validator.py reads get_evidence_text()
        # instead of scanning the orchestrator's own message history.
        self.evidence_buffer: list[str] = []
        self._evidence_total_chars = 0

        # ── Command deduplication — TIME-WINDOW based rate limit ─────────────
        # PROBLEM THIS SOLVES: a real session showed the SAME exact pentest_shell
        # command repeated 3-8 times within milliseconds to ~1 second of each
        # other (e.g. "curl -s http://10.0.4.66:2121/" x3 within 3ms; "ls
        # /usr/share/nmap/scripts/ | grep ..." x8 within 7 seconds). The gaps
        # were far too short to be separate reasoning turns — this is a
        # DECODING-LEVEL repetition artifact of the small quantized local model
        # (qwen3-5-9b-awq-4bit): when generating a batch of tool calls in one
        # inference pass, it can get stuck looping on the same tokens and emit
        # near-identical or literally identical tool calls multiple times in a
        # single turn.
        #
        # ⚠️ IMPORTANT DESIGN CONSTRAINT: this project's real deployment target
        # is black-box network exploitation, where legitimately retrying the
        # SAME command minutes or hours apart is normal and necessary — e.g.
        # re-running an exploit after a service becomes available, retrying a
        # brute-force attempt, or re-checking a port after gaining a foothold
        # changes network conditions. A PERMANENT cap on identical commands
        # (the original design) would block this legitimate behavior and
        # actively prevent the agent from completing real engagements.
        #
        # FIX: track execution TIMESTAMPS per command, not a lifetime count.
        # Only short-circuit if the same command was executed
        # MAX_CALLS_IN_WINDOW times or more within the last RAPID_WINDOW_SECONDS
        # — this specifically catches sub-second/few-second decoding-repetition
        # spam while placing NO limit whatsoever on legitimate retries that
        # happen after the window has passed. Old timestamps outside the
        # window are pruned automatically, so there is no permanent penalty:
        # a command blocked at second 3 is freely runnable again at second 10.
        self.command_execution_times: dict[str, list[datetime]] = {}
        self.command_results: dict[str, str] = {}  # command -> last real output

    # A burst of identical commands within this window is almost certainly a
    # decoding-repetition artifact, not a deliberate retry — real reasoning
    # (even a fast local model) takes longer than this between genuine
    # separate decisions.
    RAPID_WINDOW_SECONDS = 5.0

    # Allow up to this many executions of the exact same command within the
    # window before treating further attempts as spam. Sub-second bursts of
    # the same command observed in real sessions were entirely artifact —
    # only the burst gets blocked, not the command in general.
    MAX_CALLS_IN_WINDOW = 3

    def get_recent_call_count(self, command: str) -> int:
        """
        Read-only: how many times this exact command has been executed within
        the last RAPID_WINDOW_SECONDS (not a lifetime count). Also prunes
        timestamps older than the window as a side effect, so old bursts never
        permanently penalize a command — this is the key difference from a
        lifetime cap: wait past the window and the command is fully available
        again, with no limit on how many times it can legitimately be retried
        over the course of a long engagement.
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.RAPID_WINDOW_SECONDS)
        times = self.command_execution_times.get(command, [])
        recent = [t for t in times if t >= cutoff]
        self.command_execution_times[command] = recent  # prune stale entries
        return len(recent)

    def get_cached_command_result(self, command: str) -> str | None:
        """Read-only: the most recent real output for this exact command, if any."""
        return self.command_results.get(command)

    def record_command_execution(self, command: str, output: str):
        """
        Record that `command` was REALLY executed (not short-circuited): adds
        a timestamp to the rolling window and stores the output. Call this
        ONLY after a genuine execution — never during a pre-execution check.
        """
        now = datetime.now(timezone.utc)
        self.command_execution_times.setdefault(command, []).append(now)
        self.command_results[command] = output

    def add_evidence(self, text: str):
        """
        Append raw tool output text to the session-wide evidence buffer, used
        by utils/cve_validator.py to check CVE claims against what actually
        happened — regardless of which agent (orchestrator or any sub-agent)
        produced the output. Stops accumulating once MAX_EVIDENCE_CHARS is
        reached to bound memory usage on very long engagements.
        """
        if not text or self._evidence_total_chars >= self.MAX_EVIDENCE_CHARS:
            return
        self.evidence_buffer.append(text)
        self._evidence_total_chars += len(text)

    def get_evidence_text(self) -> str:
        """Return all accumulated evidence text, concatenated."""
        return "\n".join(self.evidence_buffer)

    # -------------------------------------------------------------------------
    # Ingest
    # -------------------------------------------------------------------------

    def add_event(self, attck_result: dict, phase: str = ""):
        """
        Add a tagged event from the attck_tagger tool or ATTCKAutoTagMiddleware.

        Args:
            attck_result : dict returned by attck_tagger tool or produced by
                            ATTCKAutoTagMiddleware. May include:
                              - event, command, narrative, mitre_url, attck_mappings
                              - agent            : which sub-agent performed the action
                              - exec_event_id    : join key into exec_events.jsonl
                              - evidence_status   : "declared" | "kernel_confirmed" | "disputed"
            phase        : optional pentest phase label, e.g. "Reconnaissance"
        """
        record = {
            "timestamp":       datetime.now().isoformat(timespec="seconds"),
            "phase":           phase or attck_result.get("phase", ""),
            "event":           attck_result.get("event", ""),
            "command":         attck_result.get("command", ""),
            "narrative":       attck_result.get("narrative", ""),
            "mitre_url":       attck_result.get("mitre_url", ""),
            "attck_mappings":  attck_result.get("attck_mappings", []),
            "agent":           attck_result.get("agent", "unknown"),
            "exec_event_id":   attck_result.get("exec_event_id"),
            "evidence_status": attck_result.get("evidence_status", "declared"),
        }
        self.events.append(record)

    def add_raw_event(
        self,
        event: str,
        command: str = "",
        tactic: str = "",
        technique_id: str = "",
        technique_name: str = "",
        subtechnique_id: str = "",
        subtechnique_name: str = "",
        phase: str = "",
        confidence: str = "medium",
        agent: str = "unknown",
        exec_event_id: str | None = None,
        evidence_status: str = "declared",
    ):
        """
        Manually add an event without the attck_tagger tool.
        Useful for quick inline logging inside agent code.
        """
        stid = subtechnique_id or None
        slug = (stid or technique_id).replace(".", "/") if technique_id else ""
        mitre_url = f"https://attack.mitre.org/techniques/{slug}/" if slug else ""
        label = (
            f"{subtechnique_name} ({stid})" if subtechnique_name and stid
            else f"{technique_name} ({technique_id})"
        )
        narrative = f"[{tactic}] {label} — {event}"

        self.events.append({
            "timestamp":       datetime.now().isoformat(timespec="seconds"),
            "phase":           phase,
            "event":           event,
            "command":         command,
            "narrative":       narrative,
            "mitre_url":       mitre_url,
            "agent":           agent,
            "exec_event_id":   exec_event_id,
            "evidence_status": evidence_status,
            "attck_mappings": [{
                "tactic":             tactic,
                "technique_id":       technique_id,
                "technique_name":     technique_name,
                "subtechnique_id":    stid,
                "subtechnique_name":  subtechnique_name,
                "confidence":         confidence,
            }],
        })

    def upgrade_evidence_status(
        self, exec_event_id: str, new_status: str, kernel_details: str = ""
    ) -> bool:
        """
        Called by a future eBPF correlator to upgrade an event's evidence_status
        from "declared" to "kernel_confirmed" or "disputed" once kernel-level
        verification has happened. Not used anywhere yet in this codebase —
        provided as the integration point for that future component.

        Returns True if a matching event was found and updated, False otherwise.
        """
        for ev in self.events:
            if ev.get("exec_event_id") == exec_event_id:
                ev["evidence_status"] = new_status
                if kernel_details:
                    ev["kernel_details"] = kernel_details
                return True
        return False

    # -------------------------------------------------------------------------
    # Report generation
    # -------------------------------------------------------------------------

    def build_report(self) -> str:
        """Build and return the full Markdown ATT&CK engagement report."""
        now = datetime.now()
        duration = now - self.start_time
        hours, rem = divmod(int(duration.total_seconds()), 3600)
        minutes = rem // 60

        # ── Aggregate stats
        tactic_counts: dict[str, int] = defaultdict(int)
        technique_set: set[str] = set()
        evidence_counts: dict[str, int] = defaultdict(int)
        agent_counts: dict[str, int] = defaultdict(int)

        for ev in self.events:
            evidence_counts[ev.get("evidence_status", "declared")] += 1
            agent_counts[ev.get("agent", "unknown")] += 1
            for m in ev.get("attck_mappings", []):
                tactic_counts[m.get("tactic", "Unknown")] += 1
                tid = m.get("technique_id", "")
                if tid:
                    technique_set.add(tid)

        lines = []

        # ── Title block
        lines += [
            "# Blacksmith AI — ATT&CK Engagement Report",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Engagement ID** | `{self.engagement_id}` |",
            f"| **Target** | `{self.target}` |",
            f"| **Start** | {self.start_time.strftime('%Y-%m-%d %H:%M:%S')} |",
            f"| **End** | {now.strftime('%Y-%m-%d %H:%M:%S')} |",
            f"| **Duration** | {hours}h {minutes}m |",
            f"| **Total Events** | {len(self.events)} |",
            f"| **Distinct Techniques** | {len(technique_set)} |",
            f"| **Tactics Covered** | {len(tactic_counts)} |",
            "",
        ]

        # ── Evidence model warning — always shown, prominently
        lines += [
            "## ⚠️ Evidence Model",
            "",
            "Events in this report are tagged with an **evidence status**:",
            "",
            "- **declared** — Self-reported by the agent stack (command run → keyword/LLM "
            "ATT&CK lookup). NOT independently verified against kernel-level activity.",
            "- **kernel_confirmed** — Verified against real kernel events (execve, connect, "
            "openat...) captured via eBPF (Tetragon/Falco) in the target container.",
            "- **disputed** — A kernel event was found in the expected time window but does "
            "not match what was declared.",
            "",
            "| Evidence Status | Count |",
            "|------------------|-------|",
        ]
        for status in ("declared", "kernel_confirmed", "disputed"):
            count = evidence_counts.get(status, 0)
            if count:
                lines.append(f"| {status} | {count} |")
        lines.append("")

        if evidence_counts.get("kernel_confirmed", 0) == 0 and evidence_counts.get("disputed", 0) == 0:
            lines += [
                "> **Note:** All events below are `declared` only. No kernel-level eBPF "
                "correlation has been performed for this engagement yet. Treat this report "
                "as a record of agent *intent*, not verified ground truth.",
                "",
            ]

        # ── Executive Summary
        lines += [
            "## Executive Summary",
            "",
            f"This engagement against `{self.target}` produced **{len(self.events)} documented actions** "
            f"mapped to **{len(technique_set)} distinct ATT&CK techniques** across "
            f"**{len(tactic_counts)} tactics**.",
            "",
        ]

        # ── Per-agent breakdown
        if agent_counts:
            lines += [
                "## Actions by Agent",
                "",
                "| Agent | Actions |",
                "|-------|---------|",
            ]
            for agent, count in sorted(agent_counts.items(), key=lambda x: -x[1]):
                lines.append(f"| {agent} | {count} |")
            lines.append("")

        # ── Tactic coverage table
        lines += [
            "## Tactic Coverage",
            "",
            "| Tactic | Actions |",
            "|--------|---------|",
        ]
        for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {tactic} | {count} |")
        lines.append("")

        # ── ATT&CK technique list
        if technique_set:
            lines += [
                "## Techniques Used",
                "",
                "| Technique ID | Technique Name | Tactic |",
                "|-------------|----------------|--------|",
            ]
            seen_tids: dict[str, tuple] = {}
            for ev in self.events:
                for m in ev.get("attck_mappings", []):
                    tid = m.get("technique_id", "")
                    if tid and tid not in seen_tids:
                        seen_tids[tid] = (
                            m.get("technique_name", ""),
                            m.get("tactic", ""),
                        )
            for tid, (tname, tactic) in sorted(seen_tids.items()):
                slug = tid.replace(".", "/")
                url = f"https://attack.mitre.org/techniques/{slug}/"
                lines.append(f"| [{tid}]({url}) | {tname} | {tactic} |")
            lines.append("")

        # ── Event timeline: Event → Capability → ATT&CK → Evidence
        lines += [
            "## Event Timeline — Event → Capability → ATT&CK → Evidence",
            "",
            "| # | Timestamp | Agent | Phase | Command | Tactic | Technique | Sub-technique | Conf. | Evidence |",
            "|---|-----------|-------|-------|---------|--------|-----------|---------------|-------|----------|",
        ]

        for idx, ev in enumerate(self.events, 1):
            ts      = ev["timestamp"]
            agent   = ev.get("agent", "unknown")
            phase   = ev.get("phase") or "—"
            cmd     = f"`{ev['command']}`" if ev.get("command") else ev.get("event", "")[:60]
            maps    = ev.get("attck_mappings", [])
            evidence = ev.get("evidence_status", "declared")

            if not maps:
                lines.append(
                    f"| {idx} | {ts} | {agent} | {phase} | {cmd} | — | — | — | — | {evidence} |"
                )
                continue

            for i, m in enumerate(maps):
                tactic = m.get("tactic", "—")
                tid    = m.get("technique_id", "—")
                tname  = m.get("technique_name", "—")[:35]
                stid   = m.get("subtechnique_id") or "—"
                stname = (m.get("subtechnique_name") or "—")[:30]
                conf   = m.get("confidence", "—")

                url = ev.get("mitre_url", "")
                tid_display = f"[{tid}]({url})" if url and i == 0 else tid

                row_idx     = idx if i == 0 else ""
                row_ts      = ts  if i == 0 else ""
                row_agent   = agent if i == 0 else ""
                row_phase   = phase if i == 0 else ""
                row_cmd     = cmd if i == 0 else ""
                row_evidence = evidence if i == 0 else ""

                lines.append(
                    f"| {row_idx} | {row_ts} | {row_agent} | {row_phase} | {row_cmd} "
                    f"| {tactic} | {tid_display} {tname} | {stid} {stname} | {conf} | {row_evidence} |"
                )

        lines.append("")

        # ── Detailed event narratives
        lines += ["## Detailed Event Narratives", ""]
        for idx, ev in enumerate(self.events, 1):
            narrative = ev.get("narrative") or ev.get("event", "")
            command   = ev.get("command", "")
            url       = ev.get("mitre_url", "")
            evidence  = ev.get("evidence_status", "declared")
            exec_id   = ev.get("exec_event_id")

            lines += [f"### Event {idx} — {ev['timestamp']}", ""]
            lines += [f"**Agent:** {ev.get('agent', 'unknown')}", ""]
            lines += [f"**Phase:** {ev.get('phase') or '—'}", ""]
            lines += [f"**Evidence Status:** `{evidence}`" + (
                f" (exec_event_id: `{exec_id}`)" if exec_id else " (no linked exec event — investigate)"
            ), ""]
            lines += [f"**Narrative:** {narrative}", ""]

            if command:
                lines += ["**Command:**", "```bash", command, "```", ""]

            if ev.get("attck_mappings"):
                m = ev["attck_mappings"][0]
                lines += [
                    "**ATT&CK Mapping:**",
                    f"- Tactic: {m.get('tactic', '—')}",
                    f"- Technique: {m.get('technique_id', '—')} — {m.get('technique_name', '—')}",
                ]
                if m.get("subtechnique_id"):
                    lines.append(
                        f"- Sub-technique: {m['subtechnique_id']} — {m.get('subtechnique_name', '—')}"
                    )
                lines.append(f"- Confidence: {m.get('confidence', '—')}")
                lines.append("")

            if ev.get("kernel_details"):
                lines += [f"**Kernel Evidence:** {ev['kernel_details']}", ""]

            if url:
                lines += [f"**Reference:** [{url}]({url})", ""]

        # ── Raw JSON appendix
        lines += [
            "## Appendix — Raw ATT&CK Data (JSON)",
            "",
            "```json",
            json.dumps(self.events, indent=2, ensure_ascii=False),
            "```",
            "",
        ]

        return "\n".join(lines)

    def save_report(self, path: str = "./reports/attck_report.md") -> str:
        """
        Save the report to disk and return the path.

        Default path is project-local ("./reports/") rather than the
        system-wide "/reports/" to avoid requiring root permissions —
        same class of PermissionError originally hit by
        utils/exec_event_log.py's old default. Callers (e.g. main.py) can
        still point this anywhere writable, including a system path, as
        long as the running user has permission to create it.
        """
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        report = self.build_report()
        with open(path, "w", encoding="utf-8") as f:
            f.write(report)
        return path

    def to_json(self) -> str:
        """Export all events as a JSON string."""
        return json.dumps(
            {
                "engagement_id": self.engagement_id,
                "target": self.target,
                "start": self.start_time.isoformat(),
                "events": self.events,
            },
            indent=2,
            ensure_ascii=False,
        )
