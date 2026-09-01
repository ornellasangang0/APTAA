"""
utils/cve_validator.py — Post-hoc CVE claim validation against real evidence.

PROBLEM THIS SOLVES (confirmed from a real session):
The orchestrator's final summary cited 4 specific CVEs with precise CVSS
scores (CVE-2026-47101 8.8, CVE-2026-35030 9.8, CVE-2025-62168 10.0,
CVE-2025-54574 9.8) in a penetration test report. None of these CVE IDs
appeared ANYWHERE in the 96 real events actually executed during the
session (confirmed via grep against the ATT&CK report). The small local
model (qwen3-5-9b-awq-4bit) fabricated them wholesale while completing a
"CVE / Severity / Impact" table format — a known failure mode where models
generate plausible-looking structured content even without real data behind
it.

This is a serious problem for a pentest report: acting on fabricated CVEs
wastes remediation effort while real vulnerabilities go unaddressed, and
discovering even one fabricated CVE destroys trust in the whole report.

FIX:
Before displaying the agent's final response to the user, extract every
CVE identifier mentioned (CVE-YYYY-NNNNN pattern) and check whether it
appears in the REAL evidence collected during this session — the actual
tool output text (nmap/nuclei/searchsploit/curl stdout, RAG results, web
search results), not the LLM's own summary of itself. Any CVE not found in
real evidence is flagged as UNVERIFIED directly in the displayed response,
so the person using Blacksmith AI is warned before trusting it.

This does NOT try to verify that a CVE is real in the abstract (that would
require an external CVE database lookup and is a separate, useful but
different check) — it verifies that the CVE actually appeared somewhere in
this session's real tool outputs, i.e. that the model didn't just invent it
while summarizing.

USAGE (wired into main.py's runner()):

    from utils.cve_validator import validate_cve_claims

    # After collecting all ToolMessage contents during agent.astream():
    validated_response = validate_cve_claims(full_response, evidence_text)
    print(validated_response)
"""

import re
import logging

logger = logging.getLogger("cve_validator")

# Matches CVE-YYYY-NNNN (4-7 digit sequence number, per CVE spec)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cve_claims(text: str) -> list[str]:
    """Extract all unique CVE identifiers mentioned in a text, normalized to uppercase."""
    matches = CVE_PATTERN.findall(text)
    # Normalize case and dedupe while preserving order of first appearance
    seen = set()
    result = []
    for m in matches:
        normalized = m.upper()
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def validate_cve_claims(response_text: str, evidence_text: str) -> str:
    """
    Check every CVE cited in response_text against evidence_text (the real,
    concatenated tool output content from this session). Annotate the
    response with a warning banner listing any CVE that could not be found
    in the real evidence.

    Args:
        response_text: the agent's final response to be shown to the user.
        evidence_text: concatenation of all real tool output content
                       (ToolMessage.content) collected during this session's
                       agent.astream() run — i.e. what actually happened,
                       not what the LLM said happened.

    Returns:
        response_text, optionally prefixed with an unverified-CVE warning
        banner if any citation could not be matched against real evidence.
    """
    claimed_cves = extract_cve_claims(response_text)

    if not claimed_cves:
        return response_text  # nothing to validate

    evidence_upper = evidence_text.upper()

    unverified = [
        cve for cve in claimed_cves
        if cve not in evidence_upper
    ]

    if not unverified:
        return response_text  # every claimed CVE was found in real evidence

    logger.warning(
        f"[CVE-VALIDATOR] {len(unverified)}/{len(claimed_cves)} CVE citation(s) "
        f"could not be verified against session evidence: {', '.join(unverified)}"
    )

    warning_banner = (
        "\n\n"
        "⚠️  ═══════════════ UNVERIFIED CVE WARNING ═══════════════\n"
        f"The following CVE(s) cited above do NOT appear in any actual tool\n"
        f"output from this session (nmap, nuclei, searchsploit, curl, RAG, or\n"
        f"web search results). They may have been fabricated by the model\n"
        f"while summarizing — this is a known failure mode of small local\n"
        f"models when completing structured report formats.\n"
        f"\n"
        f"DO NOT use these CVE IDs in any deliverable without independently\n"
        f"verifying them (e.g. searching nvd.nist.gov or cve.org directly):\n"
        f"\n"
    )
    for cve in unverified:
        warning_banner += f"  • {cve}\n"
    warning_banner += (
        "═══════════════════════════════════════════════════════════\n"
    )

    return response_text + warning_banner


def collect_evidence_text(messages: list, max_chars: int = 500_000) -> str:
    """
    Concatenate the content of every ToolMessage in a list of LangChain
    messages into a single evidence string, for use with validate_cve_claims.

    Args:
        messages: list of LangChain message objects (from agent.astream() chunks).
        max_chars: safety cap on total evidence text size (default 500k chars,
                   generous enough for a long session without unbounded growth).

    Returns:
        Concatenated tool output text.
    """
    # Local import to avoid a hard dependency for callers that only need
    # validate_cve_claims() with evidence they've already collected another way.
    from langchain.messages import ToolMessage

    parts = []
    total_len = 0

    for msg in messages:
        if not isinstance(msg, ToolMessage):
            continue
        content = msg.content
        if not isinstance(content, str):
            content = str(content)
        parts.append(content)
        total_len += len(content)
        if total_len >= max_chars:
            break

    return "\n".join(parts)[:max_chars]
