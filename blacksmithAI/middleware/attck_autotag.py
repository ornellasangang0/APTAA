"""
middleware/attck_autotag.py — Automatic ATT&CK tagging middleware.

PROBLEM THIS SOLVES (confirmed from a real LangSmith trace):
A trace of a scan against 10.0.4.66 showed the orchestrator calling
pentest_shell (whois, dig, nmap x2) and create_file — with ZERO calls to
attck_tagger, despite the system prompt marking it "MANDATORY". This is a
known limitation of small local models (Qwen3 9B AWQ): they reliably follow
1-2 strong instructions but drop lower-priority ones from a long system
prompt, especially across many tool-call turns.

FIX:
Stop relying on the LLM to remember. This middleware uses the `wrap_tool_call`
/ `awrap_tool_call` hooks (confirmed present in langchain.agents.middleware.
AgentMiddleware as of langchain 1.3.x) to intercept every pentest_shell call
AFTER it executes and automatically tags it — no LLM decision required for
the common case.

⚠️ BOTH SYNC AND ASYNC HOOKS ARE REQUIRED:
main.py drives the orchestrator via `agent.astream()` (see runner() in
main.py), which runs in an async context. LangChain's AgentMiddleware does
NOT automatically fall back from async to sync — if only `wrap_tool_call`
(sync) is defined and the agent runs async, every tool call raises:
    NotImplementedError: Asynchronous implementation of awrap_tool_call
    is not available...
This class therefore implements BOTH `wrap_tool_call` (for invoke()/stream())
AND `awrap_tool_call` (for ainvoke()/astream()), sharing the actual tagging
logic via a private `_process_result()` helper so there's no duplicated logic
to keep in sync.

⚠️ CRITICAL DISTINCTION — DECLARED vs OBSERVED:
Everything this middleware produces is a SELF-DECLARED mapping: "Blacksmith
ran command X, therefore ATT&CK technique Y applies." This is NOT a kernel
observation. For a downstream consumer instrumenting the Kali container with
eBPF (Tetragon/Falco), self-declared mappings have no evidentiary value on
their own — there's no proof the command actually executed as claimed, that
it wasn't blocked, that its real effect matched its apparent intent, etc.

Every event recorded here is tagged "evidence_status": "declared" and carries
an "exec_event_id" pointing into utils/exec_event_log.py's JSONL log (which
has precise request/response timestamps for the actual container call). This
exec_event_id is the JOIN KEY a future eBPF correlator will use to match
declared intent against real kernel events (execve, connect, openat...) and
upgrade matched events to "evidence_status": "kernel_confirmed" — or flag
mismatches as "evidence_status": "disputed" when the kernel shows something
different than what was declared.

DO NOT present this middleware's output as ground truth to anyone doing
kernel-level detection engineering. It answers "what did the agent claim to
do", not "what actually happened in the container". See the correlator
design notes in utils/exec_event_log.py for how the two will be joined.

Tagging strategy (same as the attck_tagger tool, called as plain functions):
  1. Local keyword KB match — instant, no LLM call, covers ~60 common tools.
  2. Local LLM fallback (config.json model) — only for commands not in the KB.

This guarantees every pentest_shell execution lands in the ATT&CK report,
independent of whether the orchestrator/sub-agent "decides" to call the tool.

Usage in main.py / agents/*.py:

    from middleware.attck_autotag import ATTCKAutoTagMiddleware

    self.agent = create_agent(  # or create_deep_agent
        ...,
        middleware=[
            ATTCKAutoTagMiddleware(
                report_builder=report_builder,
                phase="Reconnaissance",
                agent_name="recon_agent",
            ),
            TodoListMiddleware(),
            ToolRetryMiddleware(...),
        ],
    )

The attck_tagger TOOL should still be kept available to the LLM (it costs
nothing and can give richer narratives when the model does use it — the
ATTCKReportBuilder simply receives events from both sources). This middleware
is the safety net, not a replacement.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable

from langchain.agents.middleware import AgentMiddleware
from langchain.messages import ToolMessage
from langgraph.types import Command

# Import the tools module itself (not the bound name) so we always read the
# CURRENT value of tools._exec_event_logger. Importing the name directly
# (e.g. `from tools.tools import _exec_event_logger`) would bind this module
# to whatever object existed at import time — if set_exec_event_engagement()
# later reassigns tools.tools._exec_event_logger to a new ExecEventLogger
# instance (different engagement_id), this middleware would keep using the
# stale one. Using `tools.tools.<name>` at call time avoids that.
import tools.tools as _tools_module
from tools.tools import _local_attck_lookup, _llm_attck_fallback
from utils.attck_report import ATTCKReportBuilder

logger = logging.getLogger("attck_autotag")

# Tool names whose execution triggers ATT&CK TACTIC/TECHNIQUE tagging.
# pentest_shell is the primary attacker-action tool — every command that
# touches the target system goes through it. File/read/todo tools are
# informational, not attacker TTPs, so they're excluded.
AUTO_TAG_TOOLS = {"pentest_shell"}

# Tool names whose RAW output is captured into the session-wide evidence
# buffer for CVE claim validation (utils/cve_validator.py). Broader than
# AUTO_TAG_TOOLS: any tool that could legitimately surface a real CVE ID
# should count as evidence, not just pentest_shell. web_search and
# shell_documentation (HackTricks RAG) are included because a CVE
# genuinely found via research is real evidence — even if it wasn't
# actively exploited by a shell command.
EVIDENCE_TOOLS = {"pentest_shell", "web_search", "shell_documentation"}

# Cap on how much raw output text we keep per tool call for the evidence
# buffer. Much larger than the 300-char ATT&CK narrative summary — CVE IDs
# printed by nmap NSE scripts, nuclei, or searchsploit can appear anywhere
# in a long output, so we need enough of it to not miss them, while still
# bounding memory on a long engagement (paired with
# ATTCKReportBuilder.MAX_EVIDENCE_CHARS as the overall session-wide cap).
MAX_EVIDENCE_CHARS_PER_CALL = 8_000


def _summarize_output(raw_output: Any, max_chars: int = 300) -> str:
    """Produce a short summary string from a tool result for ATT&CK context."""
    if isinstance(raw_output, dict):
        text = raw_output.get("stdout") or raw_output.get("output") or str(raw_output)
    else:
        text = str(raw_output)
    text = text.strip().replace("\n", " ")
    return text[:max_chars]


def _extract_evidence_text(raw_output: Any, max_chars: int = MAX_EVIDENCE_CHARS_PER_CALL) -> str:
    """
    Extract a larger chunk of raw output text for CVE evidence purposes.
    Unlike _summarize_output (300 chars, single-line, for readable ATT&CK
    narratives), this keeps much more content and preserves newlines, since
    a CVE ID could appear anywhere in a long nmap/nuclei/searchsploit output
    or web_search/shell_documentation result.
    """
    if isinstance(raw_output, dict):
        # Try common output fields across our tools' return shapes:
        # pentest_shell: {"stdout"/"output": ...}
        # web_search: {"results": [{"content": ...}, ...]}
        # shell_documentation: {"content": ...}
        text = (
            raw_output.get("stdout")
            or raw_output.get("output")
            or raw_output.get("content")
            or ""
        )
        if not text and "results" in raw_output:
            # web_search shape: list of {title, url, content, ...}
            try:
                text = " ".join(
                    r.get("content", "") for r in raw_output["results"] if isinstance(r, dict)
                )
            except (TypeError, AttributeError):
                text = ""
        if not text:
            text = json.dumps(raw_output, ensure_ascii=False)
    else:
        text = str(raw_output)
    return text[:max_chars]


class ATTCKAutoTagMiddleware(AgentMiddleware):
    """
    Auto-tags every pentest_shell execution with MITRE ATT&CK metadata using
    the wrap_tool_call hook, independent of LLM compliance with prompt
    instructions.

    IMPORTANT — this produces a SELF-DECLARED mapping (command string →
    ATT&CK technique via keyword/LLM lookup), not an OBSERVED one. It is
    NOT a substitute for kernel-level verification. Every event recorded
    here carries an `exec_event_id` that links it to the corresponding
    entry in utils/exec_event_log.py's JSONL log, which in turn is the
    join key a future eBPF (Tetragon/Falco) correlator will use to confirm
    — or contradict — what actually happened in the container at the
    kernel level. Treat this report as "declared intent", and the eBPF
    correlation output (once built) as "ground truth".

    Args:
        report_builder: shared ATTCKReportBuilder instance for this engagement.
        phase: optional phase label to attach to all events from this agent
               (e.g. "Reconnaissance" for ReconAgent, "Exploitation" for
               ExploitAgent). Helps the report group events by sub-agent role.
        agent_name: human-readable agent identifier (e.g. "recon_agent"),
               written into both the ATT&CK report and the exec event log so
               both can be joined per-agent during correlation.
    """

    def __init__(self, report_builder: ATTCKReportBuilder, phase: str = "", agent_name: str = "unknown"):
        super().__init__()
        self.report_builder = report_builder
        self.phase = phase
        self.agent_name = agent_name

    # Only pentest_shell hits the real container/network — that's the one
    # worth short-circuiting on duplicates. web_search/shell_documentation
    # duplicates are cheap (local RAG or search API) and don't hammer the
    # target, so they're left alone.
    DEDUP_TOOLS = {"pentest_shell"}

    def _build_dedup_response(self, request, cached_output: str, count: int) -> ToolMessage:
        """
        Build a short-circuited ToolMessage for a duplicate command, instead
        of hitting the container again. Includes the previously obtained
        REAL output (so the model still has the actual data) plus an
        explicit note flagging the repetition — this both saves a wasted
        network round-trip and gives the model a clear signal to stop
        re-issuing the same command.
        """
        note = (
            f"[DUPLICATE COMMAND DETECTED — execution #{count}]\n"
            f"This exact command has already been run {count - 1} time(s) before "
            f"in this session with the result shown below. It was NOT re-executed "
            f"to avoid wasting time/hammering the target. Use this result and move "
            f"on to a different action — repeating the same command will not "
            f"produce new information.\n\n"
            f"--- Previous result ---\n{cached_output}"
        )
        return ToolMessage(
            content=note,
            tool_call_id=request.tool_call.get("id", ""),
            name=request.tool_call.get("name", ""),
        )

    def wrap_tool_call(
        self,
        request,
        handler: Callable[[Any], "ToolMessage | Command[Any]"],
    ):
        """
        Synchronous version — used when the agent is invoked via invoke()/stream().
        Intercepts the tool call, lets it execute normally via handler(request),
        then tags the result if it's a pentest_shell call.

        ⚠️ DUPLICATE COMMAND SHORT-CIRCUIT (time-window based, not permanent):
        confirmed real incident — the same exact pentest_shell command was
        repeated 3-8 times within milliseconds to ~1 second of each other, a
        decoding-level repetition artifact of the small quantized local model.
        Before executing, we check how many times this exact command ran
        within the last RAPID_WINDOW_SECONDS (a few seconds) — NOT a lifetime
        count. If that recent-window count is already at MAX_CALLS_IN_WINDOW,
        we skip handler(request) and return the cached result instead of
        hitting the container again. Crucially, this places NO permanent limit
        on the command: once the window passes, it can be freely retried —
        essential for real black-box exploitation where legitimately retrying
        the same exploit/command minutes or hours later is normal and expected.
        """
        tool_name = request.tool_call.get("name", "")

        if tool_name in self.DEDUP_TOOLS:
            command = request.tool_call.get("args", {}).get("command", "")
            if command:
                recent_count = self.report_builder.get_recent_call_count(command)
                cached = self.report_builder.get_cached_command_result(command)
                if recent_count >= self.report_builder.MAX_CALLS_IN_WINDOW and cached is not None:
                    logger.warning(
                        f"[DEDUP] short-circuited rapid-fire repeat "
                        f"({recent_count} calls within "
                        f"{self.report_builder.RAPID_WINDOW_SECONDS}s) for: {command[:80]}"
                    )
                    return self._build_dedup_response(request, cached, recent_count + 1)

        call_started_at = datetime.now(timezone.utc)

        result = handler(request)

        call_ended_at = datetime.now(timezone.utc)

        # Record the real result for future dedup checks — adds a timestamp
        # to the rolling window, only reached here for a genuine execution
        # (never for a short-circuited duplicate, which returns early above).
        if tool_name in self.DEDUP_TOOLS:
            command = request.tool_call.get("args", {}).get("command", "")
            if command:
                try:
                    output_text = (
                        result.content if isinstance(result, ToolMessage) else str(result)
                    )
                    self.report_builder.record_command_execution(command, output_text)
                except Exception:
                    pass

        self._process_result(tool_name, request, result, call_started_at, call_ended_at)
        return result

    async def awrap_tool_call(
        self,
        request,
        handler: Callable[[Any], Any],
    ):
        """
        Asynchronous version — REQUIRED because main.py drives the orchestrator
        via agent.astream() (see runner() in main.py). Without this, LangChain
        raises NotImplementedError: only the sync wrap_tool_call was defined,
        but the agent runs in an async context. This mirrors wrap_tool_call's
        logic exactly (including the time-window duplicate short-circuit),
        just with `await handler(request)`.
        """
        tool_name = request.tool_call.get("name", "")

        if tool_name in self.DEDUP_TOOLS:
            command = request.tool_call.get("args", {}).get("command", "")
            if command:
                recent_count = self.report_builder.get_recent_call_count(command)
                cached = self.report_builder.get_cached_command_result(command)
                if recent_count >= self.report_builder.MAX_CALLS_IN_WINDOW and cached is not None:
                    logger.warning(
                        f"[DEDUP] short-circuited rapid-fire repeat "
                        f"({recent_count} calls within "
                        f"{self.report_builder.RAPID_WINDOW_SECONDS}s) for: {command[:80]}"
                    )
                    return self._build_dedup_response(request, cached, recent_count + 1)

        call_started_at = datetime.now(timezone.utc)

        result = await handler(request)

        call_ended_at = datetime.now(timezone.utc)

        if tool_name in self.DEDUP_TOOLS:
            command = request.tool_call.get("args", {}).get("command", "")
            if command:
                try:
                    output_text = (
                        result.content if isinstance(result, ToolMessage) else str(result)
                    )
                    self.report_builder.record_command_execution(command, output_text)
                except Exception:
                    pass

        self._process_result(tool_name, request, result, call_started_at, call_ended_at)
        return result

    def _process_result(
        self,
        tool_name: str,
        request,
        result,
        call_started_at: datetime,
        call_ended_at: datetime,
    ):
        """
        Shared post-execution logic for both wrap_tool_call and awrap_tool_call.

        Two independent things happen here, on different tool sets:
          1. Evidence capture (EVIDENCE_TOOLS — pentest_shell, web_search,
             shell_documentation): raw output text is appended to
             report_builder.evidence_buffer so utils/cve_validator.py can
             verify CVE claims against what actually happened, regardless
             of which agent (orchestrator or any sub-agent) produced it.
          2. ATT&CK tagging (AUTO_TAG_TOOLS — pentest_shell only): maps the
             command to a Tactic/Technique via KB/LLM lookup.
        A tool call can trigger evidence capture, tagging, both, or neither.
        """
        if tool_name not in EVIDENCE_TOOLS and tool_name not in AUTO_TAG_TOOLS:
            return

        # Extract the raw result content once, used by both paths below.
        raw_output = None
        try:
            if isinstance(result, ToolMessage):
                content = result.content
                raw_output = json.loads(content) if isinstance(content, str) else content
            elif isinstance(result, Command):
                update = getattr(result, "update", {}) or {}
                msgs = update.get("messages", []) if isinstance(update, dict) else []
                if msgs:
                    last = msgs[-1]
                    content = getattr(last, "content", "")
                    raw_output = json.loads(content) if isinstance(content, str) else content
        except (json.JSONDecodeError, TypeError, AttributeError) as e:
            logger.debug(f"[AUTO-TAG] could not parse tool output: {e}")

        # ── Evidence capture (broad tool set) ────────────────────────────────
        if tool_name in EVIDENCE_TOOLS and raw_output is not None:
            evidence_text = _extract_evidence_text(raw_output)
            if evidence_text:
                self.report_builder.add_evidence(evidence_text)

        # ── ATT&CK tagging (narrow tool set — pentest_shell only) ────────────
        if tool_name not in AUTO_TAG_TOOLS:
            return

        command = request.tool_call.get("args", {}).get("command", "")
        if not command:
            return

        output_summary = _summarize_output(raw_output) if raw_output is not None else ""

        # Find the matching exec_events.jsonl entry for this command, written
        # by pentest_shell itself (which has the precise request/response
        # timestamps for the actual container call). We match by command text
        # and a tight time window around this middleware's own bracket, since
        # pentest_shell logs with agent="unknown" (it doesn't know which agent
        # is calling it) — here we backfill the real agent name onto that
        # entry so the exec log and the ATT&CK report can be joined later.
        exec_event_id = self._backfill_agent_on_matching_exec_event(
            command, call_started_at, call_ended_at
        )

        event = f"Executed: {command}"
        self._tag_event(event, command, output_summary, exec_event_id=exec_event_id)

    def _backfill_agent_on_matching_exec_event(
        self, command: str, window_start: datetime, window_end: datetime
    ) -> str | None:
        """
        Best-effort: find the most recent exec_events.jsonl entry matching this
        command within the time window, and return its event_id so the ATT&CK
        report can reference it. Does NOT mutate the JSONL (append-only log) —
        the agent name correction is instead recorded as a side annotation in
        the ATT&CK report itself via the exec_event_id link, which the
        correlator can resolve at join time.

        Returns None if no matching entry is found (logged as a warning —
        this should be rare and indicates exec_events.jsonl and the agent's
        tool calls are out of sync, worth investigating).
        """
        try:
            events = _tools_module._exec_event_logger.read_all_events()
        except Exception as e:
            logger.debug(f"[AUTO-TAG] could not read exec event log: {e}")
            return None

        # Search from the most recent backwards for a command match within
        # a generous grace window (network/exec latency on top of our own
        # middleware bracket).
        grace_seconds = 5.0
        for ev in reversed(events):
            if ev.get("command") != command:
                continue
            try:
                resp_at = datetime.fromisoformat(ev["response_received_at"])
            except (KeyError, ValueError):
                continue

            delta = abs((resp_at - window_end).total_seconds())
            if delta <= grace_seconds:
                return ev.get("event_id")

        logger.debug(
            f"[AUTO-TAG] no matching exec_events.jsonl entry found for command "
            f"within {grace_seconds}s window: {command[:60]}"
        )
        return None

    def _tag_event(
        self,
        event: str,
        command: str,
        output_summary: str,
        exec_event_id: str | None = None,
    ):
        """Tag a single event using local KB first, then local LLM fallback."""
        combined_text = f"{event} {command} {output_summary}"

        # ── Step 1: local keyword KB (instant, no LLM call) ─────────────────
        local_matches = _local_attck_lookup(combined_text)

        if local_matches:
            primary = local_matches[0]
            tid = primary["technique_id"]
            stid = primary.get("subtechnique_id") or ""
            slug = (stid or tid).replace(".", "/")
            mitre_url = f"https://attack.mitre.org/techniques/{slug}/" if tid else ""

            tactic = primary["tactic"]
            tname = primary["technique_name"]
            stname = primary.get("subtechnique_name") or ""
            label = f"{stname} ({stid})" if stname and stid else f"{tname} ({tid})"
            narrative = f"[{tactic}] {label} — {event}"

            self.report_builder.add_event(
                {
                    "event": event,
                    "command": command,
                    "attck_mappings": local_matches,
                    "narrative": narrative,
                    "mitre_url": mitre_url,
                    "agent": self.agent_name,
                    "exec_event_id": exec_event_id,
                    "evidence_status": "declared",  # vs "kernel_confirmed" once eBPF correlation exists
                },
                phase=self.phase,
            )
            logger.debug(f"[AUTO-TAG] KB match: {narrative}")
            return

        # ── Step 2: local LLM fallback (config.json model — never external) ─
        mapping = _llm_attck_fallback(event, command, output_summary)

        if mapping:
            tid = mapping.get("technique_id", "")
            stid = mapping.get("subtechnique_id") or ""
            slug = (stid or tid).replace(".", "/")
            mitre_url = f"https://attack.mitre.org/techniques/{slug}/" if tid else ""

            tactic = mapping.get("tactic", "")
            tname = mapping.get("technique_name", "")
            stname = mapping.get("subtechnique_name") or ""
            label = f"{stname} ({stid})" if stname and stid else f"{tname} ({tid})"
            narrative = f"[{tactic}] {label} — {event}"

            self.report_builder.add_event(
                {
                    "event": event,
                    "command": command,
                    "attck_mappings": [mapping],
                    "narrative": narrative,
                    "mitre_url": mitre_url,
                    "agent": self.agent_name,
                    "exec_event_id": exec_event_id,
                    "evidence_status": "declared",
                },
                phase=self.phase,
            )
            logger.debug(f"[AUTO-TAG] LLM fallback: {narrative}")
            return

        # ── Step 3: total failure — still record an untagged event ──────────
        logger.warning(f"[AUTO-TAG] could not tag event: {event[:80]}")
        self.report_builder.add_event(
            {
                "event": event,
                "command": command,
                "attck_mappings": [],
                "narrative": f"[UNTAGGED] {event}",
                "mitre_url": "",
                "agent": self.agent_name,
                "exec_event_id": exec_event_id,
                "evidence_status": "declared",
            },
            phase=self.phase,
        )
