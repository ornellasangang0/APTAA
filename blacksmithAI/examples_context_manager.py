"""
Example usage of context manager utilities.
Shows practical scenarios where large outputs are automatically limited.
"""

from utils.context_manager import (
    estimate_tokens,
    truncate_text,
    limit_command_result,
    calculate_safe_result_size
)
from agents.base import get_context_limits
import json

# ============================================================================
# EXAMPLE 1: Automatic context limit calculation
# ============================================================================
print("=" * 70)
print("EXAMPLE 1: Automatic Context Limit Calculation")
print("=" * 70)

context_size, safety_margin, max_result_chars = get_context_limits()
print(f"\nCurrent configuration:")
print(f"  - LLM Context Size: {context_size:,} tokens")
print(f"  - Safety Margin: {safety_margin}%")
print(f"  - Max Result Chars (override): {max_result_chars}")

if max_result_chars is None:
    calculated_max = calculate_safe_result_size(context_size, safety_margin)
    print(f"\n✓ Auto-calculated max result size: {calculated_max:,} characters")
    print(f"  Calculation: {context_size:,} tokens × (1 - {safety_margin}%) × 4 chars/token")

# ============================================================================
# EXAMPLE 2: Token estimation
# ============================================================================
print("\n" + "=" * 70)
print("EXAMPLE 2: Token Estimation")
print("=" * 70)

sample_texts = {
    "short": "Hello, world!",
    "medium": "The quick brown fox jumps over the lazy dog. " * 10,
    "large": ("Lorem ipsum dolor sit amet. " * 100)
}

for name, text in sample_texts.items():
    tokens = estimate_tokens(text)
    print(f"\n{name.upper()}:")
    print(f"  - Characters: {len(text):,}")
    print(f"  - Estimated tokens: {tokens:,}")
    print(f"  - Text: {text[:50]}...")

# ============================================================================
# EXAMPLE 3: Text truncation
# ============================================================================
print("\n" + "=" * 70)
print("EXAMPLE 3: Text Truncation")
print("=" * 70)

long_output = """
=== SCAN RESULTS ===
Port 80: HTTP - Apache Web Server
Port 443: HTTPS - SSL/TLS Enabled
Port 22: SSH - OpenSSH
Port 3306: MySQL - Database Server
Port 5432: PostgreSQL - Database Server

=== DISCOVERED SERVICES ===
- Web Server: Apache 2.4.41
- Database: MySQL 8.0.23
- Operating System: Linux Ubuntu 20.04 LTS

=== VULNERABILITIES FOUND ===
CVE-2021-12345: XXE Injection in XML Parser - CRITICAL
CVE-2021-54321: SQL Injection in User Search - HIGH
CVE-2021-99999: Weak SSL Configuration - MEDIUM

=== RECOMMENDATIONS ===
1. Update Apache to latest version
2. Apply security patches to MySQL
3. Configure SSL/TLS properly
4. Implement input validation
""" * 100  # Create a very long output

print(f"\nOriginal output size: {len(long_output):,} characters")

truncated, was_truncated = truncate_text(long_output, max_chars=500)

print(f"Truncated output size: {len(truncated):,} characters")
print(f"Was truncated: {was_truncated}")
print(f"\nTruncated output preview:")
print(truncated[:200] + "...")

# ============================================================================
# EXAMPLE 4: Command result limiting
# ============================================================================
print("\n" + "=" * 70)
print("EXAMPLE 4: Command Result Limiting")
print("=" * 70)

# Simulate a large command result (like from pentest_shell)
large_result = {
    "cmd": "nmap -A -p- 192.168.1.1",
    "status": 0,
    "output": "Nmap scan report:\n" * 1000 + "Host is up\n" * 1000,
    "stdout": "Starting Nmap...\n" * 500,
    "stderr": "",
    "execution_time": 45.2
}

print(f"\nOriginal result:")
print(f"  - output size: {len(large_result['output']):,} characters")
print(f"  - stdout size: {len(large_result['stdout']):,} characters")

limited_result = limit_command_result(large_result, max_chars=1000)

print(f"\nLimited result:")
print(f"  - output size: {len(limited_result['output']):,} characters")
print(f"  - Has truncation warning: {'_truncation_warning' in limited_result}")
if '_truncation_warning' in limited_result:
    print(f"  - Warning: {limited_result['_truncation_warning']}")

# ============================================================================
# EXAMPLE 5: Safe size for different LLM contexts
# ============================================================================
print("\n" + "=" * 70)
print("EXAMPLE 5: Safe Result Sizes for Different LLMs")
print("=" * 70)

models = {
    "GPT-3.5 (4k context)": 4000,
    "GPT-4 (8k context)": 8000,
    "Claude 2 (100k context)": 100000,
    "Mistral (32k context)": 32000,
    "Hunter Alpha (200k context)": 200000,
}

print("\nMax safe result size with 30% safety margin:")
for model_name, context_tokens in models.items():
    max_chars = calculate_safe_result_size(context_tokens, 30)
    print(f"  {model_name:.<40} {max_chars:>10,} chars")

# ============================================================================
# EXAMPLE 6: JSON serialization of limited results
# ============================================================================
print("\n" + "=" * 70)
print("EXAMPLE 6: JSON Serialization")
print("=" * 70)

result_with_warning = {
    "status": 0,
    "output": "Command result " * 100,
    "_truncation_warning": "Output was truncated"
}

limited = limit_command_result(result_with_warning, max_chars=500)

print("\nJSON serialization of limited result:")
json_output = json.dumps(limited, indent=2, default=str)
print(json_output[:300] + "...")

# ============================================================================
# EXAMPLE 7: Dynamic adjustment based on conversation length
# ============================================================================
print("\n" + "=" * 70)
print("EXAMPLE 7: Estimating Available Space")
print("=" * 70)

def estimate_conversation_tokens(messages_count, avg_chars_per_message=500):
    """Estimate tokens used by existing conversation"""
    total_chars = messages_count * avg_chars_per_message
    return estimate_tokens(str(total_chars))

context_size, _, _ = get_context_limits()
conversation_turns = 5
avg_msg_size = 1000

conv_tokens = estimate_conversation_tokens(conversation_turns, avg_msg_size)
available = context_size - conv_tokens

print(f"\nContext analysis:")
print(f"  - Total context: {context_size:,} tokens")
print(f"  - Conversation so far: ~{conversation_turns} turns × {avg_msg_size} chars = {conv_tokens:,} tokens")
print(f"  - Available for new command result: ~{available:,} tokens")
print(f"  - Max safe result size: ~{available * 4 * 0.7:,.0f} characters")

print("\n" + "=" * 70)
print("✓ All examples completed!")
print("=" * 70)
