from langchain.tools import tool
import requests
import os
from langgraph.config import get_stream_writer
import json
from langchain_mcp_adapters.client import MultiServerMCPClient
import asyncio
from utils.vectors import storage_manager
from agents.base import init_embedding_model, get_context_limits
from utils.context_manager import limit_command_result, calculate_safe_result_size

config_tools = json.load(open("./config.json", "r"))['tools']
code_interpreter_config = json.load(open("./mcp/mcp-code-interpreter.json", "r"))['mcpServers']
playwright_config = json.load(open("./mcp/mcp-playwright.json", "r"))['mcpServers']
mcp_full = json.load(open("./mcp/mcp.json", "r"))['mcpServers']
sleep = 2


@tool
def pentest_shell(command: str, timeout: int = 300) -> dict:
    """Run a shell command for penetration testing in an isolated container.

    Available tool categories:
    - reconnaissance: whois, dig, dnsrecon, assetfinder, subfinder, theharvester,
                      amass, fierce, dnsx, httpx, recon-ng
    - scanning_enumeration: nmap, masscan, rustscan, nikto, gobuster, feroxbuster,
                            ffuf, dirb, enum4linux-ng, smbmap, netexec, wpscan
    - vulnerability_mapping: nuclei, sslscan, searchsploit, whatweb, wafw00f
    - exploitation: sqlmap, hydra, medusa, ncrack, commix, responder,
                    msfconsole (/opt/metasploit/msfconsole)
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

    result = response.json()
    
    # Apply context size limits to prevent LLM overflow
    context_size, safety_margin, max_result_chars = get_context_limits()
    if max_result_chars is None:
        max_result_chars = calculate_safe_result_size(context_size, safety_margin)
    
    writer(f"applying context limit: max {max_result_chars} characters")
    result = limit_command_result(result, max_result_chars)
    
    return result


@tool
def create_file(path: str, content: str) -> dict:
    """Create or overwrite a file in the container.
    
    This tool reliably creates files in the isolated container environment
    with proper handling of the file creation process.
    
    Args:
        path: Full path where to create the file (e.g. "/reports/test.md")
        content: Content to write in the file
    
    Returns:
        Dictionary with creation status and details
    """
    
    writer = get_stream_writer()
    writer(f"creating file at {path}")
    
    import shlex
    
    # First ensure the directory exists
    dir_path = os.path.dirname(path)
    if dir_path:
        mkdir_cmd = f"mkdir -p {shlex.quote(dir_path)}"
        mkdir_response = requests.post(
            os.getenv('container_uri', 'http://localhost:9756/exec'),
            json={"cmd": mkdir_cmd, "timeout": 30}
        )
        if mkdir_response.status_code != 200:
            writer(f"failed to create directory {dir_path}")
            return {
                "status": "error",
                "path": path,
                "message": f"Failed to create directory {dir_path}",
                "error": mkdir_response.text
            }
    
    # Use tee to write file reliably - echo piped to tee is very robust
    # This avoids shell escaping issues and works with any content
    escaped_content = shlex.quote(content)
    write_cmd = f"echo {escaped_content} | tee {shlex.quote(path)} > /dev/null"
    
    writer(f"executing write command: {write_cmd}")
    response = requests.post(
        os.getenv('container_uri', 'http://localhost:9756/exec'),
        json={"cmd": write_cmd, "timeout": 30}
    )
    
    if response.status_code != 200:
        writer(f"file creation failed with status code {response.status_code}: {response.text}")
        return {
            "status": "error",
            "path": path,
            "message": "Failed to create file",
            "error": response.text
        }
    
    writer("write command executed, verifying...")
    
    # Verify file was created
    verify_cmd = f"test -f {shlex.quote(path)} && echo 'exists' || echo 'not_found'"
    verify_response = requests.post(
        os.getenv('container_uri', 'http://localhost:9756/exec'),
        json={"cmd": verify_cmd, "timeout": 10}
    )
    
    if verify_response.status_code == 200:
        verify_result = verify_response.json()
        output = verify_result.get("output", "").strip() if isinstance(verify_result, dict) else str(verify_result).strip()
        
        writer(f"verification result: {output}")
        if "exists" in output:
            writer(f"✓ file successfully created at {path}")
            return {
                "status": "success",
                "path": path,
                "size_bytes": len(content),
                "message": f"File created successfully at {path}"
            }
    
    writer(f"⚠️ file creation may have failed - verification inconclusive")
    return {
        "status": "unknown",
        "path": path,
        "message": "File creation attempted but verification inconclusive",
        "note": "Try verifying manually with 'ls -la /path/to/file'"
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

# tool for shell command documentation
@tool
def shell_documentation(query: str) -> str:
    """Search documentation for pentest shell commands available in the pentest shell tool.

    Args:
        query: The documentation query string to search for.
    """
    # initialize custom stream writer
    writer = get_stream_writer()
    writer(f"searching documentation for query: {query}")
    results = shell_documentation_vector_store.query(query, n_results=5)
    writer(f"found {len(results)} relevant documents.")
    docs_content = "\n\n".join([doc.page_content for doc in results])
    return f"Here are some relevant documentation snippets:\n\n{docs_content}"

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
