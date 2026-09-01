"""
Context management utilities for handling large outputs from shell commands.
Ensures that command results don't exceed LLM context limits.
"""

import json
import logging

logger = logging.getLogger('context_manager')


def estimate_tokens(text: str, chars_per_token: float = 4.0) -> int:
    """
    Estimate the number of tokens in text.
    Rough approximation: 1 token ≈ 4 characters (varies by content).
    
    Args:
        text: Text to estimate tokens for
        chars_per_token: Average characters per token (default 4.0)
    
    Returns:
        Estimated token count
    """
    return int(len(text) / chars_per_token)


def truncate_text(
    text: str,
    max_chars: int,
    summary_prefix: str = "[Output truncated] "
) -> tuple[str, bool]:
    """
    Truncate text to a maximum character limit.
    
    Args:
        text: Text to truncate
        max_chars: Maximum characters to keep
        summary_prefix: Prefix to add if text is truncated
    
    Returns:
        Tuple of (truncated_text, was_truncated)
    """
    if len(text) <= max_chars:
        return text, False
    
    # Keep last portion of output (usually most relevant for debugging)
    truncated = text[-max_chars:]
    summary = f"{summary_prefix}Showing last {max_chars} characters. "
    summary += f"Total output was {len(text)} characters.\n\n{truncated}"
    
    return summary, True


def limit_command_result(
    result: dict,
    max_chars: int,
    keys_to_check: list[str] = None
) -> dict:
    """
    Limit the size of a command result dictionary.
    
    Args:
        result: Command result dictionary (typically from shell command)
        max_chars: Maximum characters for output fields
        keys_to_check: Which keys to truncate (default: ["output", "stdout", "stderr", "result"])
    
    Returns:
        Modified result dictionary with truncated outputs
    """
    if keys_to_check is None:
        keys_to_check = ["output", "stdout", "stderr", "result", "data"]
    
    result_copy = result.copy() if isinstance(result, dict) else {"output": str(result)}
    truncation_occurred = False
    
    for key in keys_to_check:
        if key in result_copy and isinstance(result_copy[key], str):
            original_len = len(result_copy[key])
            result_copy[key], was_truncated = truncate_text(
                result_copy[key],
                max_chars
            )
            if was_truncated:
                truncation_occurred = True
                logger.warning(
                    f"Truncated '{key}' from {original_len} to {max_chars} characters"
                )
    
    if truncation_occurred:
        result_copy["_truncation_warning"] = (
            "Output was truncated to fit within LLM context limits. "
            "Some data may have been omitted."
        )
    
    return result_copy


def calculate_safe_result_size(
    context_size: int,
    safety_margin_percent: float = 30.0
) -> int:
    """
    Calculate a safe maximum character size for command results.
    
    Args:
        context_size: LLM context window size in tokens
        safety_margin_percent: Percentage of context to reserve for other messages (default 30%)
    
    Returns:
        Maximum characters for command results
    """
    # Reserve safety margin for other messages in conversation
    available_tokens = context_size * (1.0 - safety_margin_percent / 100.0)
    # Convert tokens back to approximate characters (1 token ≈ 4 chars)
    max_chars = int(available_tokens * 4.0)
    
    logger.info(
        f"Calculated safe result size: {max_chars} characters "
        f"(from {context_size} token context with {safety_margin_percent}% safety margin)"
    )
    
    return max_chars
