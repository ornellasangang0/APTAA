from langchain.tools import tool
import requests
import os
from langgraph.config import get_stream_writer
import json
from langchain_mcp_adapters.client import MultiServerMCPClient
import asyncio
from utils.vectors import storage_manager
from agents.base import init_embedding_model
import urllib.request
import urllib.parse

config_tools = json.load(open("./config.json", "r"))['tools']
code_interpreter_config = json.load(open("./mcp/mcp-code-interpreter.json", "r"))['mcpServers']
playwright_config = json.load(open("./mcp/mcp-playwright.json", "r"))['mcpServers']
mcp_full = json.load(open("./mcp/mcp.json", "r"))['mcpServers']
sleep = 2

# SearXNG configuration
SEARXNG_URL = json.load(open("./config.json", "r")).get('searxng', {}).get('url', 'http://10.0.4.1:8888')
SEARXNG_TIMEOUT = json.load(open("./config.json", "r")).get('searxng', {}).get('timeout', 30)


@tool
def pentest_shell(command: str, timeout: int = 300) -> dict:
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
                   ( msfconsole (/opt/metasploit/msfconsole)but not for the moment)
    - post_exploitation: netcat, socat, hping3, proxychains4, chisel,
                         bloodhound, impacket CLIs
    - passwords_crypto: hashcat, john, crunch, cewl
    - general: python3, curl, ssh, httpie, go, ruby, gem, npm

    Args:
        command: bash command to execute, e.g. "nmap -sV -p 80,21 10.10.1.173"
        timeout: command execution timeout in seconds (default: 300)
    """

    # initialize custom stream writer
    writer = get_stream_writer()
    writer(f"running command {command}")

    response = requests.post(
        os.getenv('container_uri', 'http://localhost:9756/exec'),
        json={"cmd": command, "timeout": timeout}
    )

    if response.status_code != 200:
        writer(f"command execution failed with status code {response.status_code}")
        return f"Error: Command execution failed with status code {response.status_code}"

    writer("command executed, processing response...")

    return response.json()


@tool
def web_search(query: str, num_results: int = 10) -> dict:
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

    # initialize custom stream writer
    writer = get_stream_writer()
    writer(f"searching the web for: {query}")

    try:
        # Construire l'URL de recherche
        params = urllib.parse.urlencode({
            "q": query,
            "format": "json",
            "pageno": 1
        })
        url = f"{SEARXNG_URL}/search?{params}"

        # Effectuer la requête
        req = urllib.request.urlopen(url, timeout=SEARXNG_TIMEOUT)
        data = json.loads(req.read().decode())

        # Extraire et formater les résultats
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

        return {
            "query":       query,
            "total":       len(results),
            "results":     results,
            "suggestions": data.get("suggestions", [])[:5],
            "error":       None
        }

    except urllib.error.URLError as e:
        writer(f"SearXNG unreachable: {str(e)}")
        return {
            "query":       query,
            "total":       0,
            "results":     [],
            "suggestions": [],
            "error":       f"SearXNG inaccessible : {str(e)}"
        }
    except Exception as e:
        writer(f"web_search unexpected error: {str(e)}")
        return {
            "query":       query,
            "total":       0,
            "results":     [],
            "suggestions": [],
            "error":       f"Erreur inattendue : {str(e)}"
        }
@tool
def create_file(path: str = "", content: str = "", file_path: str = "") -> dict:
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
        return {
            "status": "error",
            "path": "",
            "message": "Missing required parameter: 'path' or 'file_path'",
            "error": "No path specified"
        }

    writer = get_stream_writer()
    writer(f"creating file at {resolved_path}")

    import shlex
    import base64

    # Encoder le contenu en base64 pour éviter tout problème d'échappement
    content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")

    # Utiliser python3 pour décoder et écrire — fiable pour tout type de contenu
    write_cmd = (
        f"python3 -c \""
        f"import base64; "
        f"content = base64.b64decode('{content_b64}').decode('utf-8'); "
        f"import os; os.makedirs(os.path.dirname('{resolved_path}') or '.', exist_ok=True); "
        f"open('{resolved_path}', 'w').write(content); "
        f"print('written', len(content), 'bytes')"
        f"\""
    )

    writer(f"writing file via python3 + base64")
    response = requests.post(
        os.getenv('container_uri', 'http://localhost:9756/exec'),
        json={"cmd": write_cmd, "timeout": 30}
    )

    if response.status_code != 200:
        writer(f"file creation failed: {response.status_code}")
        return {
            "status": "error",
            "path": resolved_path,
            "message": "Failed to create file",
            "error": response.text
        }

    # Vérifier que le fichier existe et a du contenu
    verify_cmd = (
        f"test -f {shlex.quote(resolved_path)} "
        f"&& wc -c {shlex.quote(resolved_path)} "
        f"|| echo 'FILE_NOT_FOUND'"
    )
    verify_response = requests.post(
        os.getenv('container_uri', 'http://localhost:9756/exec'),
        json={"cmd": verify_cmd, "timeout": 10}
    )

    if verify_response.status_code == 200:
        verify_result = verify_response.json()
        output = (
            verify_result.get("output", "").strip()
            if isinstance(verify_result, dict)
            else str(verify_result).strip()
        )

        writer(f"verification result: {output}")

        if "FILE_NOT_FOUND" in output:
            writer(f"❌ file not found after write attempt")
            return {
                "status": "error",
                "path": resolved_path,
                "message": "File was not created despite successful write command",
                "error": "File not found after write"
            }

        writer(f"✅ file successfully created at {resolved_path}")
        return {
            "status": "success",
            "path": resolved_path,
            "size_bytes": len(content),
            "message": f"File created successfully at {resolved_path}",
            "container_size": output
        }

    return {
        "status": "unknown",
        "path": resolved_path,
        "message": "File creation attempted but verification inconclusive",
        "note": f"Try verifying manually with 'ls -la {resolved_path}'"
    }        

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

    import shlex
    cmd = f"cat {shlex.quote(path)}"

    response = requests.post(
        os.getenv('container_uri', 'http://localhost:9756/exec'),
        json={"cmd": cmd, "timeout": 30}
    )

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

    import shlex
    cmd = f"ls -la {shlex.quote(path)}"

    response = requests.post(
        os.getenv('container_uri', 'http://localhost:9756/exec'),
        json={"cmd": cmd, "timeout": 30}
    )

    if response.status_code != 200:
        return f"Error listing directory: {response.status_code}"

    result = response.json()
    content = result.get("output", "") if isinstance(result, dict) else str(result)

    return content


# initialize vector store for tool documentation
embedding_model = init_embedding_model().get_model()

shell_documentation_vector_store = storage_manager(
        collection_name="tools_documentation",
        persist_directory="./store/vector_db",
        embedding_function=embedding_model
    )


@tool
def shell_documentation(query: str) -> dict:
    """
    Search HackTricks documentation for pentest commands, techniques and tools.

    Args:
        query: user query (e.g. "ffuf directory enumeration", "nmap syn scan")
    """

    writer = get_stream_writer()
    writer(f"[RAG] searching documentation: {query}")

    # 🔍 retrieval
    results = shell_documentation_vector_store.query(query, n_results=30)

    writer(f"[RAG] retrieved {len(results)} documents")

    # ❌ NO RESULTS CASE
    if not results or len(results) == 0:
        return {
            "found": False,
            "source": "llm_general",
            "query": query,
            "content": None,
            "top_score": None
        }

    # 📄 build context
    docs_content = "\n\n".join([doc.page_content for doc in results])

    # 📊 optional score extraction (safe fallback)
    top_score = None
    try:
        if hasattr(results[0], "metadata") and "score" in results[0].metadata:
            top_score = results[0].metadata["score"]
    except:
        pass

    return {
        "found": True,
        "source": "hacktricks_rag",
        "query": query,
        "content": docs_content,
        "top_score": top_score
    }

#####################################################################################
# MCP Tools
#####################################################################################

async def browser():
    """
    Returns MCP Playwright browser tools with responses wrapped to extract text content.
    This ensures tool responses are plain strings compatible with all LLM providers.
    """
    mcp_data = MultiServerMCPClient(playwright_config)
    tools = await mcp_data.get_tools()
    await asyncio.sleep(sleep)

    return tools


async def code_executor():

    mcp_data = MultiServerMCPClient(code_interpreter_config)
    tools = await mcp_data.get_tools()
    await asyncio.sleep(sleep)

    return tools
