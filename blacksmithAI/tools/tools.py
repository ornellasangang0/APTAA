from langchain.tools import tool
import requests
import os
from langgraph.config import get_stream_writer
import json
from langchain_mcp_adapters.client import MultiServerMCPClient
import asyncio
from utils.vectors import storage_manager
from agents.base import init_model, init_embedding_model
from utils.exec_event_log import ExecEventLogger
import urllib.request
import urllib.parse
import shlex
import base64
import logging
from datetime import datetime, timezone
from langchain.messages import HumanMessage, SystemMessage

logger = logging.getLogger("tools")


def _serialize_tool_result(result) -> str:
    """
    Serialize a tool return value to a JSON string.

    deepagents' internal filesystem middleware (filesystem.py) intercepts
    large tool results and calls result.error on the return value, expecting
    an object with that attribute. A plain Python dict doesn't have it and
    causes: AttributeError: 'dict' object has no attribute 'error'.

    Returning a JSON string sidesteps this entirely — deepagents treats
    strings as opaque content and does not try to access attributes on them.
    The LLM receives the same information either way (LangChain serializes
    both to string in the ToolMessage content before sending to the model).

    Apply this to EVERY @tool that would otherwise return a dict.
    """
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(result)

# Shared exec event logger — engagement_id is set lazily via
# set_exec_event_engagement() once main.py knows the engagement ID for this
# session. Until then, events are logged under a generic "unassigned" ID so
# nothing is silently dropped, but the correlator can still flag them for
# manual review.
_exec_event_logger = ExecEventLogger(engagement_id="unassigned")


def set_exec_event_engagement(engagement_id: str):
    """
    Called once at session start (from main.py / pentest.py) to attach all
    subsequent pentest_shell calls to the correct engagement ID, so the
    eBPF correlation pipeline can group events by engagement.
    """
    global _exec_event_logger
    _exec_event_logger = ExecEventLogger(engagement_id=engagement_id)

config_tools = json.load(open("./config.json", "r"))['tools']
code_interpreter_config = json.load(open("./mcp/mcp-code-interpreter.json", "r"))['mcpServers']
playwright_config = json.load(open("./mcp/mcp-playwright.json", "r"))['mcpServers']
mcp_full = json.load(open("./mcp/mcp.json", "r"))['mcpServers']
sleep = 2

# SearXNG configuration
_cfg = json.load(open("./config.json", "r"))
SEARXNG_URL = _cfg.get('searxng', {}).get('url', 'http://10.0.4.1:8888')
SEARXNG_TIMEOUT = _cfg.get('searxng', {}).get('timeout', 30)


# =============================================================================
# SHELL
# =============================================================================

@tool
def pentest_shell(command: str, timeout: int = 300) -> str:
    """Run a shell command for penetration testing in an isolated container.
    For internet searches (CVEs, exploits, documentation), prefer the
    web_search tool which uses SearXNG.

    Available tool categories:
    - reconnaissance: whois, dig, dnsrecon, assetfinder, subfinder, theharvester,
                      amass, fierce, dnsx, httpx, recon-ng
    - scanning_enumeration: nmap, masscan, rustscan, nikto, gobuster, feroxbuster,
                            ffuf, dirb, enum4linux-ng, smbmap, netexec, wpscan
    - vulnerability_mapping: nuclei, sslscan, searchsploit, whatweb, wafw00f
    - exploitation: sqlmap, hydra, medusa, ncrack, commix, responder,
                   ( msfconsole (/opt/metasploit/msfconsole) but not for the moment)
    - post_exploitation: netcat, socat, hping3, proxychains4, chisel,
                         bloodhound, impacket CLIs
    - passwords_crypto: hashcat, john, crunch, cewl
    - general: python3, curl, ssh, httpie, go, ruby, gem, npm

    Args:
        command: bash command to execute, e.g. "nmap -sV -p 80,21 10.10.1.173"
        timeout: command execution timeout in seconds (default: 300)
    """
    writer = get_stream_writer()
    writer(f"running command {command}")

    # Precise timestamps bracketing the actual container call — this is the
    # data a future eBPF/Tetragon correlator will use to match this command
    # against real kernel execve/connect events in the Kali container.
    # See utils/exec_event_log.py for the correlation strategy.
    request_sent_at = datetime.now(timezone.utc)

    # ── CRITICAL: client-side timeout ────────────────────────────────────────
    # The "timeout" field in the JSON body only tells the /exec SERVER how
    # long to let the command run before it responds. It does NOT protect
    # against the HTTP request itself hanging forever — e.g. if the container
    # crashes, the network connection stalls, or the server never sends a
    # response. Without a client-side timeout, requests.post() blocks
    # INDEFINITELY, which freezes the entire agent run (confirmed: LangSmith
    # showed a run stuck "Incomplete" with no error, no timeout, nothing —
    # classic symptom of a hung synchronous HTTP call with no timeout).
    #
    # timeout=(connect_timeout, read_timeout):
    #   - connect_timeout=10s: fail fast if the container is unreachable
    #     (down, network issue, wrong container_uri).
    #   - read_timeout = the requested command timeout + 15s grace period,
    #     so the client waits at least as long as the server-side execution
    #     timeout, plus a margin for network/processing overhead, before
    #     giving up even if the server itself never responds.
    try:
        response = requests.post(
            os.getenv('container_uri', 'http://localhost:9756/exec'),
            json={"cmd": command, "timeout": timeout},
            timeout=(10, timeout + 15),
        )
    except requests.exceptions.ConnectTimeout:
        writer(f"container unreachable (connect timeout) for command: {command}")
        return _serialize_tool_result({
            "status": "error",
            "error": "connect_timeout",
            "message": (
                f"Could not connect to the pentest container within 10s. "
                f"It may be down, restarting, or unreachable. Check with: "
                f"docker ps | grep shell-executor"
            ),
        })
    except requests.exceptions.ReadTimeout:
        writer(f"container did not respond in time for command: {command}")
        return _serialize_tool_result({
            "status": "error",
            "error": "read_timeout",
            "message": (
                f"The container did not respond within {timeout + 15}s. "
                f"The command may still be running inside the container "
                f"(e.g. a hung process) — check with: docker exec shell-executor ps aux"
            ),
        })
    except requests.exceptions.ConnectionError as e:
        writer(f"connection error for command: {command} — {e}")
        return _serialize_tool_result({
            "status": "error",
            "error": "connection_error",
            "message": f"Connection to the pentest container failed: {e}",
        })

    response_received_at = datetime.now(timezone.utc)

    try:
        _exec_event_logger.log_event(
            agent="unknown",  # overwritten per-agent by ATTCKAutoTagMiddleware's
                               # richer correlation when available; kept here as
                               # a safety net so no execution goes unlogged even
                               # if middleware isn't attached.
            command=command,
            request_sent_at=request_sent_at,
            response_received_at=response_received_at,
            status_code=response.status_code,
        )
    except Exception as e:
        logger.warning(f"[EXEC-LOG] failed to log execution intent event: {e}")

    if response.status_code != 200:
        writer(f"command execution failed with status code {response.status_code}")
        return f"Error: Command execution failed with status code {response.status_code}"

    writer("command executed, processing response...")

    # Parse response
    try:
        result = response.json()
    except Exception:
        result = response.text

    # ── Output truncation ────────────────────────────────────────────────────
    # Large tool outputs (nmap full scans, nuclei results, sqlmap verbose mode)
    # are the primary cause of ContextWindowExceededError with qwen3-5-9b-awq-4bit
    # (200k token limit). We truncate before returning so the LLM context stays
    # manageable. SummarizationMiddleware handles long conversations, but we also
    # need to cap individual tool results at the source.
    #
    # Limit: 20000 chars ≈ 5000 tokens — enough for any meaningful scan result
    # while leaving room for the agent's reasoning + other messages.
    # Override via MAX_TOOL_OUTPUT_CHARS env var if your model has more headroom.
    MAX_CHARS = int(os.getenv("MAX_TOOL_OUTPUT_CHARS", "20000"))

    if isinstance(result, str):
        output_text = result
    elif isinstance(result, dict):
        # Flatten dict to string for length check
        output_text = json.dumps(result, ensure_ascii=False)
    else:
        output_text = str(result)

    if len(output_text) > MAX_CHARS:
        # Keep the tail (most recent output) — more relevant than the header
        # for tools like nmap that print metadata first then findings at the end.
        # Also keep the first 2000 chars for context (command summary, headers).
        head = output_text[:2000]
        tail = output_text[-(MAX_CHARS - 2000):]
        truncated = (
            f"{head}\n\n"
            f"[... OUTPUT TRUNCATED — {len(output_text)} chars total, "
            f"showing first 2000 + last {MAX_CHARS - 2000} chars "
            f"to stay within context limits. "
            f"Use 'pentest_shell' with -oN to save full output to a file if needed ...]\n\n"
            f"{tail}"
        )
        writer(f"output truncated: {len(output_text)} → {len(truncated)} chars")
        return truncated

    # Return a JSON string rather than a raw dict.
    # deepagents' internal filesystem middleware (deepagents/middleware/filesystem.py)
    # intercepts large tool results and calls result.error on the return value,
    # expecting an object with that attribute — a plain Python dict doesn't have
    # it and causes: AttributeError: 'dict' object has no attribute 'error'.
    # Returning a JSON string sidesteps this: deepagents treats strings as opaque
    # content and does not try to access attributes on them.
    if isinstance(result, str):
        return result
    return json.dumps(result, ensure_ascii=False)


# =============================================================================
# WEB SEARCH
# =============================================================================

@tool
def web_search(query: str, num_results: int = 10) -> str:
    """Search the internet using SearXNG metasearch engine.
    Use this tool to find information about CVEs, exploits, tools,
    techniques, documentation, or any web content needed during a pentest.

    ALWAYS use this tool BEFORE pentest_shell when you need to:
    - Look up CVE details or exploits
    - Find documentation about a tool or technique
    - Research a technology, version, or service
    - Find default credentials
    - Search for wordlists or payloads
    - Gather OSINT information

    DO NOT use curl or pentest_shell for web searches — use this tool instead.

    Examples of good queries:
    - "CVE-2021-44228 log4shell exploit poc"
    - "Apache 2.4.49 path traversal vulnerability"
    - "nmap NSE scripts SMB enumeration"
    - "default credentials Tomcat manager"
    - "privilege escalation linux SUID binaries"

    Args:
        query: search query string
        num_results: number of results to return (default: 10, max: 50)

    Returns:
        dict with keys:
            - results: list of {title, url, content, engines, score}
            - suggestions: list of suggested queries
            - query: original query
            - total: number of results returned
            - error: error message if search failed
    """
    writer = get_stream_writer()
    writer(f"searching the web for: {query}")

    try:
        params = urllib.parse.urlencode({
            "q": query,
            "format": "json",
            "pageno": 1
        })
        url = f"{SEARXNG_URL}/search?{params}"

        req = urllib.request.urlopen(url, timeout=SEARXNG_TIMEOUT)
        data = json.loads(req.read().decode())

        raw_results = data.get("results", [])[:num_results]
        results = []
        for r in raw_results:
            results.append({
                "title":   r.get("title", "No title"),
                "url":     r.get("url", ""),
                "content": r.get("content", ""),
                "engines": r.get("engines", []),
                "score":   r.get("score", 0)
            })

        writer(f"found {len(results)} results for query: {query}")

        return _serialize_tool_result({
            "query":       query,
            "total":       len(results),
            "results":     results,
            "suggestions": data.get("suggestions", [])[:5],
            "error":       None
        })

    except urllib.error.URLError as e:
        writer(f"SearXNG unreachable: {str(e)}")
        return _serialize_tool_result({
            "query": query, "total": 0, "results": [],
            "suggestions": [], "error": f"SearXNG inaccessible : {str(e)}"
        })
    except Exception as e:
        writer(f"web_search unexpected error: {str(e)}")
        return _serialize_tool_result({
            "query": query, "total": 0, "results": [],
            "suggestions": [], "error": f"Erreur inattendue : {str(e)}"
        })


# =============================================================================
# FILE TOOLS
# =============================================================================

@tool
def create_file(path: str = "", content: str = "", file_path: str = "") -> str:
    """Create or overwrite a file in the container.

    Args:
        path: Full path where to create the file (e.g. "/reports/test.md")
        file_path: Alias for path (e.g. "/reports/test.md")
        content: Content to write in the file

    Returns:
        Dictionary with creation status and details
    """
    resolved_path = path or file_path
    if not resolved_path:
        return _serialize_tool_result({
            "status": "error",
            "path": "",
            "message": "Missing required parameter: 'path' or 'file_path'",
            "error": "No path specified"
        })

    writer = get_stream_writer()
    writer(f"creating file at {resolved_path}")

    # Encode content as base64 to avoid shell escaping issues
    content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")

    write_cmd = (
        f"python3 -c \""
        f"import base64; "
        f"content = base64.b64decode('{content_b64}').decode('utf-8'); "
        f"import os; os.makedirs(os.path.dirname('{resolved_path}') or '.', exist_ok=True); "
        f"open('{resolved_path}', 'w').write(content); "
        f"print('written', len(content), 'bytes')"
        f"\""
    )

    writer("writing file via python3 + base64")
    try:
        response = requests.post(
            os.getenv('container_uri', 'http://localhost:9756/exec'),
            json={"cmd": write_cmd, "timeout": 30},
            timeout=(10, 45),  # write should be fast; 45s client-side ceiling
        )
    except requests.exceptions.RequestException as e:
        writer(f"file creation request failed: {e}")
        return _serialize_tool_result({
            "status": "error",
            "path": resolved_path,
            "message": "Request to container failed",
            "error": str(e),
        })

    if response.status_code != 200:
        writer(f"file creation failed: {response.status_code}")
        return _serialize_tool_result({
            "status": "error",
            "path": resolved_path,
            "message": "Failed to create file",
            "error": response.text
        })

    verify_cmd = (
        f"test -f {shlex.quote(resolved_path)} "
        f"&& wc -c {shlex.quote(resolved_path)} "
        f"|| echo 'FILE_NOT_FOUND'"
    )
    try:
        verify_response = requests.post(
            os.getenv('container_uri', 'http://localhost:9756/exec'),
            json={"cmd": verify_cmd, "timeout": 10},
            timeout=(10, 25),
        )
    except requests.exceptions.RequestException as e:
        writer(f"file verification request failed: {e}")
        return _serialize_tool_result({
            "status": "unknown",
            "path": resolved_path,
            "message": "File may have been created, but verification request failed",
            "error": str(e),
        })

    if verify_response.status_code == 200:
        verify_result = verify_response.json()
        output = (
            verify_result.get("output", "").strip()
            if isinstance(verify_result, dict)
            else str(verify_result).strip()
        )

        writer(f"verification result: {output}")

        if "FILE_NOT_FOUND" in output:
            writer("❌ file not found after write attempt")
            return _serialize_tool_result({
                "status": "error",
                "path": resolved_path,
                "message": "File was not created despite successful write command",
                "error": "File not found after write"
            })

        writer(f"✅ file successfully created at {resolved_path}")
        return _serialize_tool_result({
            "status": "success",
            "path": resolved_path,
            "size_bytes": len(content),
            "message": f"File created successfully at {resolved_path}",
            "container_size": output
        })

    return _serialize_tool_result({
        "status": "unknown",
        "path": resolved_path,
        "message": "File creation attempted but verification inconclusive",
        "note": f"Try verifying manually with 'ls -la {resolved_path}'"
    })


@tool
def read_file(path: str) -> str:
    """Read a file from the container.

    Args:
        path: Full path to the file to read

    Returns:
        File content as string
    """
    writer = get_stream_writer()
    writer(f"reading file at {path}")

    cmd = f"cat {shlex.quote(path)}"

    try:
        response = requests.post(
            os.getenv('container_uri', 'http://localhost:9756/exec'),
            json={"cmd": cmd, "timeout": 30},
            timeout=(10, 45),
        )
    except requests.exceptions.RequestException as e:
        return f"Error reading file: request failed — {e}"

    if response.status_code != 200:
        return f"Error reading file: {response.status_code}"

    result = response.json()
    content = result.get("output", "") if isinstance(result, dict) else str(result)

    writer(f"✓ file read successfully ({len(content)} bytes)")
    return content


@tool
def list_directory(path: str = ".") -> str:
    """List files in a directory in the container.

    Args:
        path: Directory path to list (default: current directory)

    Returns:
        Directory listing
    """
    writer = get_stream_writer()
    writer(f"listing directory {path}")

    cmd = f"ls -la {shlex.quote(path)}"

    try:
        response = requests.post(
            os.getenv('container_uri', 'http://localhost:9756/exec'),
            json={"cmd": cmd, "timeout": 30},
            timeout=(10, 45),
        )
    except requests.exceptions.RequestException as e:
        return f"Error listing directory: request failed — {e}"

    if response.status_code != 200:
        return f"Error listing directory: {response.status_code}"

    result = response.json()
    return result.get("output", "") if isinstance(result, dict) else str(result)


# =============================================================================
# RAG — HackTricks documentation
# =============================================================================

# Initialize vector store once at module load
_embedding_model = init_embedding_model().get_model()

shell_documentation_vector_store = storage_manager(
    collection_name="tools_documentation",
    persist_directory="./store/vector_db",
    embedding_function=_embedding_model,
)


@tool
def shell_documentation(query: str) -> str:
    """Search HackTricks documentation for pentest commands, techniques and tools.
    Returns the most relevant passages with their source section and relevance score.

    Use this tool to find:
    - Specific tool usage examples (flags, options, workflows)
    - Pentest techniques and methodologies
    - Attack patterns, payloads, wordlists references
    - Service-specific enumeration procedures

    Args:
        query: natural language query, e.g. "ffuf directory enumeration recursive"
               or "SMB null session enumeration enum4linux"

    Returns:
        dict with keys:
            - found: bool
            - content: formatted context passages with source breadcrumbs
            - top_score: best relevance score (0–1)
            - num_chunks: number of passages returned
    """
    writer = get_stream_writer()
    writer(f"[RAG] searching documentation: {query}")

    # Score-filtered retrieval — returns list of (Document, float) tuples
    results_with_scores = shell_documentation_vector_store.query(
        query_text=query,
        n_results=8,
        score_threshold=0.35,
    )

    writer(f"[RAG] retrieved {len(results_with_scores)} relevant documents")

    if not results_with_scores:
        return _serialize_tool_result({
            "found": False,
            "source": "no_results",
            "query": query,
            "content": None,
            "top_score": None,
            "num_chunks": 0,
            "note": (
                "No sufficiently similar documentation found. "
                "Try rephrasing with tool names or technique keywords, "
                "or use web_search for up-to-date CVE/exploit information."
            ),
        })

    # Build structured context: one section per chunk with breadcrumb header
    sections = []
    for doc, score in results_with_scores:
        meta = doc.metadata or {}
        breadcrumb_parts = [
            meta.get("h1", ""),
            meta.get("h2", ""),
            meta.get("h3", ""),
        ]
        breadcrumb = " › ".join(p for p in breadcrumb_parts if p)
        src = meta.get("source", "unknown")
        header = f"### [{breadcrumb or src}] (score: {score:.2f})\n"
        sections.append(header + doc.page_content.strip())

    docs_content = "\n\n---\n\n".join(sections)
    top_score = results_with_scores[0][1]

    return _serialize_tool_result({
        "found": True,
        "source": "hacktricks_rag",
        "query": query,
        "content": docs_content,
        "top_score": round(top_score, 3),
        "num_chunks": len(results_with_scores),
    })


# =============================================================================
# ATT&CK TAGGER
# =============================================================================

# Local knowledge base: keyword → list of (tactic, T-id, name, ST-id, ST-name)
# Covers the most common pentest tools and commands.
# The local LLM fallback handles everything not in this table.
_ATTCK_KB: dict[str, list[tuple]] = {
    # Reconnaissance
    "nmap":            [("Reconnaissance", "T1595", "Active Scanning", "T1595.001", "Scanning IP Blocks")],
    "masscan":         [("Reconnaissance", "T1595", "Active Scanning", "T1595.001", "Scanning IP Blocks")],
    "rustscan":        [("Reconnaissance", "T1595", "Active Scanning", "T1595.001", "Scanning IP Blocks")],
    "port scan":       [("Reconnaissance", "T1595", "Active Scanning", "T1595.002", "Vulnerability Scanning")],
    "nikto":           [("Reconnaissance", "T1595", "Active Scanning", "T1595.002", "Vulnerability Scanning")],
    "nuclei":          [("Reconnaissance", "T1595", "Active Scanning", "T1595.002", "Vulnerability Scanning")],
    "gobuster":        [("Reconnaissance", "T1595", "Active Scanning", "T1595.003", "Wordlist Scanning")],
    "ffuf":            [("Reconnaissance", "T1595", "Active Scanning", "T1595.003", "Wordlist Scanning")],
    "feroxbuster":     [("Reconnaissance", "T1595", "Active Scanning", "T1595.003", "Wordlist Scanning")],
    "dirb":            [("Reconnaissance", "T1595", "Active Scanning", "T1595.003", "Wordlist Scanning")],
    "whois":           [("Reconnaissance", "T1590", "Gather Victim Network Information", None, None)],
    "dns":             [("Reconnaissance", "T1590", "Gather Victim Network Information", "T1590.002", "DNS")],
    "dnsrecon":        [("Reconnaissance", "T1590", "Gather Victim Network Information", "T1590.002", "DNS")],
    "dig":             [("Reconnaissance", "T1590", "Gather Victim Network Information", "T1590.002", "DNS")],
    "subfinder":       [("Reconnaissance", "T1590", "Gather Victim Network Information", "T1590.001", "Domain Properties")],
    "amass":           [("Reconnaissance", "T1590", "Gather Victim Network Information", "T1590.001", "Domain Properties")],
    "theharvester":    [("Reconnaissance", "T1593", "Search Open Websites/Domains", "T1593.001", "Social Media")],
    "shodan":          [("Reconnaissance", "T1596", "Search Open Technical Databases", "T1596.005", "Scan Databases")],
    "whatweb":         [("Reconnaissance", "T1592", "Gather Victim Host Information", "T1592.002", "Software")],
    "wafw00f":         [("Reconnaissance", "T1592", "Gather Victim Host Information", "T1592.002", "Software")],
    # Resource Development
    "msfvenom":        [("Resource Development", "T1587", "Develop Capabilities", "T1587.001", "Malware")],
    "payload":         [("Resource Development", "T1587", "Develop Capabilities", "T1587.001", "Malware")],
    # Initial Access
    "sqlmap":          [("Initial Access", "T1190", "Exploit Public-Facing Application", None, None)],
    "wpscan":          [("Initial Access", "T1190", "Exploit Public-Facing Application", None, None)],
    "commix":          [("Initial Access", "T1190", "Exploit Public-Facing Application", None, None)],
    "phishing":        [("Initial Access", "T1566", "Phishing", None, None)],
    # Execution
    "msfconsole":      [("Execution", "T1203", "Exploitation for Client Execution", None, None)],
    "exploit":         [("Execution", "T1203", "Exploitation for Client Execution", None, None)],
    "python3 -c":      [("Execution", "T1059", "Command and Scripting Interpreter", "T1059.006", "Python")],
    "python -c":       [("Execution", "T1059", "Command and Scripting Interpreter", "T1059.006", "Python")],
    "bash -i":         [("Execution", "T1059", "Command and Scripting Interpreter", "T1059.004", "Unix Shell")],
    "sh -i":           [("Execution", "T1059", "Command and Scripting Interpreter", "T1059.004", "Unix Shell")],
    "powershell":      [("Execution", "T1059", "Command and Scripting Interpreter", "T1059.001", "PowerShell")],
    # Persistence
    "crontab":         [("Persistence", "T1053", "Scheduled Task/Job", "T1053.003", "Cron")],
    "authorized_keys": [("Persistence", "T1098", "Account Manipulation", "T1098.004", "SSH Authorized Keys")],
    "webshell":        [("Persistence", "T1505", "Server Software Component", "T1505.003", "Web Shell")],
    "backdoor":        [("Persistence", "T1505", "Server Software Component", "T1505.003", "Web Shell")],
    # Privilege Escalation
    "suid":            [("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism", "T1548.001", "Setuid and Setgid")],
    "sudo -l":         [("Privilege Escalation", "T1548", "Abuse Elevation Control Mechanism", "T1548.003", "Sudo and Sudo Caching")],
    "linpeas":         [("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", None, None)],
    "kernel exploit":  [("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", None, None)],
    "winpeas":         [("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", None, None)],
    # Defense Evasion
    "proxychains":     [("Defense Evasion", "T1090", "Proxy", "T1090.001", "Internal Proxy")],
    "chisel":          [("Defense Evasion", "T1090", "Proxy", "T1090.002", "External Proxy")],
    "history -c":      [("Defense Evasion", "T1070", "Indicator Removal", "T1070.003", "Clear Command History")],
    "clear logs":      [("Defense Evasion", "T1070", "Indicator Removal", "T1070.002", "Clear Linux or Mac System Logs")],
    "rm /var/log":     [("Defense Evasion", "T1070", "Indicator Removal", "T1070.002", "Clear Linux or Mac System Logs")],
    # Credential Access
    "hydra":           [("Credential Access", "T1110", "Brute Force", "T1110.001", "Password Guessing")],
    "medusa":          [("Credential Access", "T1110", "Brute Force", "T1110.001", "Password Guessing")],
    "ncrack":          [("Credential Access", "T1110", "Brute Force", "T1110.001", "Password Guessing")],
    "ssh brute":       [("Credential Access", "T1110", "Brute Force", "T1110.003", "Password Spraying")],
    "hashcat":         [("Credential Access", "T1110", "Brute Force", "T1110.002", "Password Cracking")],
    "john":            [("Credential Access", "T1110", "Brute Force", "T1110.002", "Password Cracking")],
    "mimikatz":        [("Credential Access", "T1003", "OS Credential Dumping", "T1003.001", "LSASS Memory")],
    "secretsdump":     [("Credential Access", "T1003", "OS Credential Dumping", "T1003.002", "Security Account Manager")],
    "/etc/shadow":     [("Credential Access", "T1003", "OS Credential Dumping", "T1003.008", "/etc/passwd and /etc/shadow")],
    "responder":       [("Credential Access", "T1557", "Adversary-in-the-Middle", "T1557.001", "LLMNR/NBT-NS Poisoning")],
    # Discovery
    "enum4linux":      [("Discovery", "T1018", "Remote System Discovery", None, None)],
    "netexec":         [("Discovery", "T1018", "Remote System Discovery", None, None)],
    "smbmap":          [("Discovery", "T1135", "Network Share Discovery", None, None)],
    "bloodhound":      [("Discovery", "T1069", "Permission Groups Discovery", "T1069.002", "Domain Groups")],
    "whoami":          [("Discovery", "T1033", "System Owner/User Discovery", None, None)],
    "uname -a":        [("Discovery", "T1082", "System Information Discovery", None, None)],
    "ifconfig":        [("Discovery", "T1016", "System Network Configuration Discovery", None, None)],
    "ip route":        [("Discovery", "T1016", "System Network Configuration Discovery", None, None)],
    "netstat":         [("Discovery", "T1049", "System Network Connections Discovery", None, None)],
    "ps aux":          [("Discovery", "T1057", "Process Discovery", None, None)],
    "find / -name":    [("Discovery", "T1083", "File and Directory Discovery", None, None)],
    # Lateral Movement
    "ssh ":            [("Lateral Movement", "T1021", "Remote Services", "T1021.004", "SSH")],
    "psexec":          [("Lateral Movement", "T1021", "Remote Services", "T1021.002", "SMB/Windows Admin Shares")],
    "winrm":           [("Lateral Movement", "T1021", "Remote Services", "T1021.006", "Windows Remote Management")],
    # Command and Control
    "nc -e":           [("Command and Control", "T1095", "Non-Application Layer Protocol", None, None)],
    "nc -lvnp":        [("Command and Control", "T1095", "Non-Application Layer Protocol", None, None)],
    "socat":           [("Command and Control", "T1095", "Non-Application Layer Protocol", None, None)],
    # Exfiltration
    "curl -F":         [("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol", None, None)],
    "scp ":            [("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol", "T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol")],
}


def _local_attck_lookup(text: str) -> list[dict]:
    """Fast keyword-based ATT&CK lookup before calling the LLM."""
    text_lower = text.lower()
    matches = []
    seen: set[tuple] = set()

    for keyword, entries in _ATTCK_KB.items():
        if keyword in text_lower:
            for tactic, tid, tname, stid, stname in entries:
                key = (tid, stid)
                if key not in seen:
                    seen.add(key)
                    matches.append({
                        "tactic":             tactic,
                        "technique_id":       tid,
                        "technique_name":     tname,
                        "subtechnique_id":    stid,
                        "subtechnique_name":  stname,
                        "matched_keyword":    keyword,
                        "confidence":         "high" if stid else "medium",
                        "source":             "local_kb",
                    })

    return matches


def _llm_attck_fallback(event: str, command: str, output_summary: str) -> dict | None:
    """
    LLM fallback for ATT&CK mapping using the local model defined in config.json.

    Uses init_model() from agents/base.py, which reads config.json and points
    to the local vLLM-compatible endpoint (base_url = http://10.0.0.3/v1,
    model = qwen3-5-9b-awq-4bit). No data ever leaves the local network —
    this matches the project's local-inference-for-security-and-confidentiality
    requirement, same as the main agents.

    The model is invoked directly with .invoke() (no tools, no agent loop)
    with a strict JSON-only system prompt. We robustly extract the JSON object
    from the response in case the model adds <think> tags, markdown fences,
    or other preamble — common with Qwen3-style reasoning models.

    Returns a mapping dict on success, or None on any failure.
    """
    system_prompt = (
        "You are a MITRE ATT&CK v15 expert. "
        "When given a penetration testing event, you respond ONLY with a single "
        "valid JSON object — no markdown, no explanation, no preamble, no thinking.\n\n"
        "JSON schema:\n"
        "{\n"
        '  "tactic": "<ATT&CK Tactic name>",\n'
        '  "technique_id": "<T1XXX>",\n'
        '  "technique_name": "<Technique name>",\n'
        '  "subtechnique_id": "<T1XXX.XXX or null>",\n'
        '  "subtechnique_name": "<Sub-technique name or null>",\n'
        '  "confidence": "high|medium|low",\n'
        '  "reasoning": "<one sentence explaining the mapping>"\n'
        "}"
    )

    user_prompt = (
        f"Penetration testing event:\n"
        f"  Description : {event}\n"
        f"  Command     : {command or 'N/A'}\n"
        f"  Output      : {output_summary or 'N/A'}\n\n"
        "Map this to the most precise MITRE ATT&CK Enterprise entry and return "
        "ONLY the JSON object."
    )

    try:
        # init_model() reads config.json → base_url = http://10.0.0.3/v1 (local vLLM)
        # temperature=0 for deterministic structured output
        llm = init_model(temperature=0).get_model()

        response = llm.invoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_prompt),
        ])

        raw_text = (response.content or "").strip()

        # Some reasoning models (Qwen3 family) may prefix output with <think>...</think>
        if "<think>" in raw_text and "</think>" in raw_text:
            raw_text = raw_text.split("</think>")[-1].strip()

        # Strip markdown fences if the model added them despite instructions
        if "```" in raw_text:
            parts = raw_text.split("```")
            raw_text = parts[1].strip() if len(parts) > 1 else raw_text
            if raw_text.startswith("json"):
                raw_text = raw_text[4:].strip()

        # Extract the first {...} block to be robust against any remaining preamble
        start = raw_text.find("{")
        end = raw_text.rfind("}") + 1
        if start == -1 or end == 0:
            logger.error(f"[ATT&CK] local LLM response has no JSON object: {raw_text[:200]}")
            return None

        mapping = json.loads(raw_text[start:end])
        mapping["source"] = "llm_local"
        return mapping

    except json.JSONDecodeError as e:
        logger.error(f"[ATT&CK] JSON parse error in local LLM response: {e}")
        return None
    except Exception as e:
        logger.error(f"[ATT&CK] local LLM fallback failed: {e}")
        return None


@tool
def attck_tagger(
    event: str,
    command: str = "",
    output_summary: str = "",
) -> str:
    """Map a penetration testing action to MITRE ATT&CK framework entries.

    Call this tool AFTER every significant pentest action to build an audit
    trail mapped to ATT&CK Tactics, Techniques and Sub-techniques.
    The result feeds directly into the final engagement report.

    Lookup strategy (fast → accurate, fully local):
      1. Local keyword KB    — instant, covers ~60 common pentest tools/commands.
      2. Local LLM fallback  — calls the local model configured in config.json
                                (vLLM endpoint) for cases not in the KB.
                                No data ever leaves the local network.

    Args:
        event: Human description of what happened, e.g.
               "Ran nmap SYN scan on 10.10.1.5, found ports 22, 80, 443 open"
        command: The actual command or tool used (optional but improves accuracy),
                 e.g. "nmap -sS -p- 10.10.1.5"
        output_summary: Brief summary of what the command returned (optional),
                        e.g. "22/tcp open ssh, 80/tcp open http Apache 2.4.49"

    Returns:
        dict with:
            - event          : original event description
            - command        : command used
            - attck_mappings : list of { tactic, technique_id, technique_name,
                               subtechnique_id, subtechnique_name, confidence, source }
            - narrative      : one-line ATT&CK narrative for the report
            - mitre_url      : URL to the primary technique on attack.mitre.org
    """
    writer = get_stream_writer()
    writer(f"[ATT&CK] tagging: {event[:80]}...")

    combined_text = f"{event} {command} {output_summary}"

    # ── Step 1: fast local KB lookup ─────────────────────────────────────────
    local_matches = _local_attck_lookup(combined_text)

    if local_matches:
        writer(f"[ATT&CK] {len(local_matches)} local KB match(es) — no LLM call needed")
        primary = local_matches[0]
        tid  = primary["technique_id"]
        stid = primary.get("subtechnique_id") or ""
        slug = (stid or tid).replace(".", "/")
        mitre_url = f"https://attack.mitre.org/techniques/{slug}/" if tid else ""

        tactic = primary["tactic"]
        tname  = primary["technique_name"]
        stname = primary.get("subtechnique_name") or ""
        label  = f"{stname} ({stid})" if stname and stid else f"{tname} ({tid})"
        narrative = f"[{tactic}] {label} — {event}"

        return _serialize_tool_result({
            "event":          event,
            "command":        command,
            "attck_mappings": local_matches,
            "narrative":      narrative,
            "mitre_url":      mitre_url,
        })

    # ── Step 2: local LLM fallback (config.json model — never external) ──────
    writer("[ATT&CK] no local KB match — calling local LLM (config.json model)")

    mapping = _llm_attck_fallback(event, command, output_summary)

    if mapping:
        tid  = mapping.get("technique_id", "")
        stid = mapping.get("subtechnique_id") or ""
        slug = (stid or tid).replace(".", "/")
        mitre_url = f"https://attack.mitre.org/techniques/{slug}/" if tid else ""

        tactic = mapping.get("tactic", "")
        tname  = mapping.get("technique_name", "")
        stname = mapping.get("subtechnique_name") or ""
        label  = f"{stname} ({stid})" if stname and stid else f"{tname} ({tid})"
        narrative = f"[{tactic}] {label} — {event}"

        writer(f"[ATT&CK] local LLM mapped → {tid}/{stid} ({mapping.get('confidence', '?')})")

        return _serialize_tool_result({
            "event":          event,
            "command":        command,
            "attck_mappings": [mapping],
            "narrative":      narrative,
            "mitre_url":      mitre_url,
        })

    # ── Step 3: total failure — return untagged event so the report isn't broken
    writer("[ATT&CK] ⚠️  could not map event — returning untagged")
    return _serialize_tool_result({
        "event":          event,
        "command":        command,
        "attck_mappings": [],
        "narrative":      f"[UNTAGGED] {event}",
        "mitre_url":      "",
        "error":          "Both local KB and local LLM fallback failed to produce a mapping.",
    })


# =============================================================================
# MCP Tools
# =============================================================================

async def browser():
    """Returns MCP Playwright browser tools."""
    mcp_data = MultiServerMCPClient(playwright_config)
    tools = await mcp_data.get_tools()
    await asyncio.sleep(sleep)
    return tools


async def code_executor():
    """Returns MCP code interpreter tools."""
    mcp_data = MultiServerMCPClient(code_interpreter_config)
    tools = await mcp_data.get_tools()
    await asyncio.sleep(sleep)
    return tools
