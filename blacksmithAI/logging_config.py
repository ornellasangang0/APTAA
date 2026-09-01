"""
logging_config.py — Centralized logging configuration for Blacksmith AI.

PROBLEM THIS SOLVES:
Every module does `logger = logging.getLogger('some_name')` (recon_agent,
exploit_agent, tools, attck_autotag, exec_event_log, cve_validator, main...)
but nothing anywhere calls `logging.basicConfig()` or attaches a handler.
Without a configured root logger, Python's logging module silently discards
most of these messages (or dumps them to stderr with no formatting, no file,
no persistence) — none of the diagnostic info from ATTCKAutoTagMiddleware,
exec_event_log, cve_validator, etc. was actually being captured anywhere
durable, even though the code was calling logger.warning()/info()/debug()
correctly throughout.

WHAT THIS FILE DOES:
Call configure_logging() ONCE, at the very start of main.py (or pentest.py),
before anything else runs. It sets up:
  - A rotating file handler writing to ./logs/blacksmith.log (project-local,
    same pattern as EXEC_EVENT_LOG_PATH and ATTCK_REPORT_DIR — no root
    permissions required, override via BLACKSMITH_LOG_PATH env var).
  - A console handler for warnings/errors only (keeps the terminal clean for
    the Rich-based UI in main.py, while still surfacing real problems).
  - Consistent formatting across every module's logger, including the
    module name, so log lines are traceable to their source
    (recon_agent vs exploit_agent vs attck_autotag, etc.).

USAGE (add this near the top of main.py, before other blacksmith imports
if possible, so early-import-time log calls are also captured):

    from logging_config import configure_logging
    configure_logging()

    from agents.recon import ReconAgent
    ...
"""

import logging
import logging.handlers
import os


DEFAULT_LOG_PATH = os.getenv("BLACKSMITH_LOG_PATH", "./logs/blacksmith.log")

# Rotate at 10MB, keep 5 backups — bounds disk usage on long-running sessions
# without ever needing manual log cleanup.
MAX_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5

_configured = False


def configure_logging(
    log_path: str = DEFAULT_LOG_PATH,
    file_level: int = logging.DEBUG,
    console_level: int = logging.WARNING,
) -> None:
    """
    Configure the root logger once for the whole application. Every module's
    `logging.getLogger('xyz')` call automatically inherits this configuration
    — no per-module setup needed beyond the existing `getLogger(name)` calls
    already present in agents/*.py, tools/tools.py, middleware/*.py, utils/*.py.

    Args:
        log_path: where the rotating log file is written. Defaults to a
                  project-local "./logs/blacksmith.log" (same permission-safe
                  pattern as EXEC_EVENT_LOG_PATH / ATTCK_REPORT_DIR — avoids
                  requiring root access to write to a system path). Override
                  via the BLACKSMITH_LOG_PATH env var or this argument.
        file_level: minimum level written to the log file. DEBUG by default
                    so nothing is lost — the file is for post-hoc diagnosis,
                    not real-time reading.
        console_level: minimum level printed to the console. WARNING by
                       default so routine INFO/DEBUG messages from the 6
                       agents don't clutter the Rich-based interactive UI in
                       main.py — only real problems interrupt the session.

    Safe to call multiple times — only configures once (idempotent), so it's
    safe to import and call from both main.py and pentest.py without risk of
    duplicate handlers / duplicated log lines.
    """
    global _configured
    if _configured:
        return

    try:
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    except (PermissionError, OSError) as e:
        # Same resilience pattern as exec_event_log.py / attck_report.py:
        # never let a logging path issue crash the whole application.
        # Fall back to console-only logging in that case.
        logging.basicConfig(level=console_level)
        logging.getLogger("logging_config").warning(
            f"Could not create log directory for '{log_path}' ({e}). "
            f"Falling back to console-only logging."
        )
        _configured = True
        return

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(file_level)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # handlers below filter what's shown/written
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # ── Silence noisy third-party libraries ──────────────────────────────────
    # Without this, DEBUG-level root logging captures every internal message
    # from chromadb, httpcore, urllib3, langsmith, openai's HTTP client, etc.
    # — hundreds of lines per session with no diagnostic value for Blacksmith
    # itself, drowning out the actually useful agent/tool/middleware messages.
    # Only WARNING+ from these libraries reaches the log; Blacksmith's own
    # modules (agents.*, tools, middleware.*, utils.*, main) keep full DEBUG.
    _NOISY_THIRD_PARTY_LOGGERS = [
        "chromadb",
        "httpcore",
        "httpx",
        "urllib3",
        "openai._base_client",
        "langsmith.client",
        "posthog",
    ]
    for name in _NOISY_THIRD_PARTY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    _configured = True

    logging.getLogger("logging_config").info(
        f"Logging configured — file: {log_path} (level={logging.getLevelName(file_level)}), "
        f"console (level={logging.getLevelName(console_level)})"
    )

    # ── ⚠️ External network calls detected — flagged for awareness ──────────
    # Two third-party libraries used in this project make OUTBOUND network
    # calls to external services by default, which may be undesirable given
    # the project's local-only inference requirement for confidentiality:
    #
    #   1. ChromaDB (utils/vectors.py) sends ANONYMIZED TELEMETRY to
    #      PostHog (us.i.posthog.com) by default on every run. To disable:
    #        - Set env var: ANONYMIZED_TELEMETRY=False
    #        - Or in code, when constructing the Chroma client:
    #          Chroma(..., client_settings=Settings(anonymized_telemetry=False))
    #
    #   2. LangSmith tracing (used by langchain/langgraph for observability —
    #      this is what shows up as the LangSmith traces you've been
    #      inspecting throughout this project) sends run data to
    #      api.smith.langchain.com. This is likely intentional here since
    #      you've been using LangSmith traces for debugging (e.g. the
    #      run-*.json trace file analyzed earlier). To disable if needed:
    #        - Unset LANGCHAIN_TRACING_V2 / LANGSMITH_TRACING env var, or
    #          set it to "false"
    #
    # Neither is disabled by this function automatically — telemetry opt-out
    # and tracing on/off are deployment decisions, not something a logging
    # config module should silently change. Set the env vars above in your
    # shell profile or .env if you want them off.
    logging.getLogger("logging_config").debug(
        "Note: chromadb (PostHog telemetry) and langsmith (tracing) make "
        "external network calls by default. See logging_config.py comments "
        "for opt-out env vars if this matters for your environment."
    )
