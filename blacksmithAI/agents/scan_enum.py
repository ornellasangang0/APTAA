from .base import init_model, get_retry_config
from langchain.agents import create_agent
from datetime import datetime
import json
import logging
from langchain.agents.middleware import ToolRetryMiddleware, SummarizationMiddleware
from tools.tools import pentest_shell, shell_documentation, web_search, create_file, read_file, attck_tagger
from middleware.attck_autotag import ATTCKAutoTagMiddleware
from deepagents import CompiledSubAgent

# fetch tool header from config
available_tools = json.load(open("./config.json", "r"))['tools']['scanning_enumeration']
general_tools = json.load(open("./config.json", "r"))['tools']['general']
available_tools.extend(general_tools)
available_tools.extend([shell_documentation, "file creation/reading"])
available_tools.extend([web_search])

today = datetime.now().strftime("%Y-%m-%d")

# setup logging
logger = logging.getLogger('scan_enum_agent')
logger.setLevel(logging.INFO)

instrctions = """
You are a scanning and enumeration agent. Your goal is to perform comprehensive scanning and enumeration of the target system or network using the available tools.
Use the tools effectively to identify open ports, services, and potential vulnerabilities.
Be thorough in your scanning and document your findings clearly.

⚠️ IMPORTANT: You have special file tools available:
  * create_file(path, content) - Creates files in the container (e.g., /reports/scan_results.md)
  * read_file(path) - Reads file contents from the container

When user asks to CREATE/WRITE/SAVE a file → ALWAYS use create_file() tool
When user asks to READ a file → use read_file() tool

Follow these guidelines:
0. ⚠️ CHECK YOUR TASK CONTEXT FIRST: if the orchestrator's delegation message already
   lists open ports/services (e.g. "Known open ports: 21/ftp, 22/ssh..."), do NOT
   re-run a full port scan from scratch — use that information directly and move on
   to deeper enumeration of those specific services. Only run your own port scan if
   no such information was provided.
1. Start with network scanning to identify live hosts and open ports.
2. Use enumeration tools to gather detailed information about services and applications running on the target.
3. Analyze the gathered data to identify patterns or potential vulnerabilities.
4. Always document your findings with timestamps for future reference.
5. When documenting scan results, ALWAYS use create_file() to save reports to /reports/
6. Prioritize stealth and avoid detection while performing scanning and enumeration tasks.
7. If you encounter any issues or need additional information, adjust your approach accordingly.
Remember, the quality of your scanning and enumeration will significantly impact the success of subsequent penetration testing phases

Note: every shell command you run is automatically logged against MITRE ATT&CK in the
background — you don't need to call any extra tool for this, just focus on the task.

Use the following tools as needed: {available_tools}
Use the shell documentation tool to search for pentest tools usage and examples.
Make sure to log the date and time of each action you take. today is {today}.
"""


class ScanEnumAgent:
    def __init__(self, report_builder=None):
        """
        Args:
            report_builder: shared ATTCKReportBuilder instance for this engagement.
                             If provided, every pentest_shell call this agent makes
                             is automatically tagged against MITRE ATT&CK in the
                             background — independent of LLM compliance.
        """
        # initialize model
        model = init_model().get_model()

        # Get retry configuration
        _, subagent_max_retries, _ = get_retry_config()

        middleware = [
            # SummarizationMiddleware prevents ContextWindowExceededError during
            # long pentest sessions. Triggers at 70% of 200k context window
            # (~140k tokens) and keeps 8 most recent messages verbatim.
            # Replaces TodoListMiddleware which caused write_todos ValidationError
            # (Qwen3 9B produces {service: pending} instead of {status: pending})
            # due to Qwen3 9B's schema compliance limitations with strict Pydantic.
            SummarizationMiddleware(
                model=model,
                trigger=("fraction", 0.70),
                keep=("messages", 8),
            ),
            ToolRetryMiddleware(
                max_retries=subagent_max_retries,
                on_failure="continue"
            ),
        ]

        if report_builder is not None:
            middleware.insert(0, ATTCKAutoTagMiddleware(
                report_builder=report_builder,
                phase="Scanning & Enumeration",
                agent_name="scan_enum_agent",
            ))

        self.agent = create_agent(
            model=model,
            tools=[pentest_shell, shell_documentation, web_search, create_file, read_file, attck_tagger],
            system_prompt=instrctions.format(available_tools=available_tools, today=today),
            name='scan_enum_agent',
            middleware=middleware,
        )

        logger.info("Scanning and Enumeration Agent initialized.")

    def get_agent(self):
        return self.agent

    def get_compiled_agent(self) -> CompiledSubAgent:
        compiled_agent = CompiledSubAgent(
            name="scan_enum_agent",
            description="A scanning and enumeration agent for gathering information about target systems and networks.",
            runnable=self.agent,
        )
        return compiled_agent
