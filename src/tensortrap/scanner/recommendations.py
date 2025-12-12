"""Remediation recommendations for security findings.

Provides simple, actionable advice for users based on finding type and severity.
"""

from tensortrap.scanner.results import Severity

# Recommendations by finding pattern (keyword matching on message)
RECOMMENDATIONS = {
    # CRITICAL - Do not load
    "known malicious": "DO NOT LOAD. Delete this file immediately.",
    "path traversal": "DO NOT LOAD. This file attempts to write outside its directory.",
    "zipslip": "DO NOT LOAD. This archive contains path traversal attacks.",
    "reverse shell": "DO NOT LOAD. This file contains remote access code.",
    "dangerous yaml pattern": "DO NOT LOAD. Use yaml.safe_load() if you must parse this file.",
    # HIGH - Convert or verify source
    "dangerous import": "Convert to safetensors format or verify the model source.",
    "7z archive": "Extract and scan contents before loading.",
    "nested pickle": "Verify model source - may be multi-stage attack.",
    "lambda layer": "Remove Lambda layers or verify code is safe before loading.",
    "embedded pickle": "Convert to a safer format without embedded pickle.",
    "external_data": "Verify external data paths before loading.",
    # MEDIUM - Caution
    "reduce opcode": "Normal for pickle models. Convert to safetensors for safer loading.",
    "build opcode": "Normal for pickle models. Convert to safetensors for safer loading.",
    "object creation opcode": "Normal for models. Verify source if untrusted.",
    "stack_global": "Dynamic import detected. Verify model source.",
    "base64": "Potential obfuscation. Verify model source.",
    "high entropy": "Potential obfuscation. Verify model source.",
    "pickle format detected": "Unexpected pickle file. Verify this is intentional.",
    "shell command": "Review YAML file for unintended command execution.",
    # LOW/INFO - Informational
    "pytorch zip": "No action needed - standard PyTorch format.",
    "no unsafe patterns": "No action needed.",
    "safetensors": "Safe format - no action needed.",
}

# Default recommendations by severity
DEFAULT_BY_SEVERITY = {
    Severity.CRITICAL: "DO NOT LOAD this file. It contains code that will execute on your system.",
    Severity.HIGH: "Convert to safetensors format or verify model source before loading.",
    Severity.MEDIUM: "Consider converting to safetensors format for safer loading.",
    Severity.LOW: "Low risk - verify model source if from untrusted origin.",
    Severity.INFO: "No action needed.",
}


def get_recommendation(message: str, severity: Severity) -> str:
    """Get remediation recommendation for a finding.

    Args:
        message: The finding message
        severity: The finding severity

    Returns:
        Simple, actionable recommendation string
    """
    message_lower = message.lower()

    # Check for specific patterns in the message
    for pattern, recommendation in RECOMMENDATIONS.items():
        if pattern in message_lower:
            return recommendation

    # Fall back to severity-based default
    return DEFAULT_BY_SEVERITY.get(severity, "Verify model source.")


def add_recommendations(findings: list) -> list:
    """Add recommendations to a list of findings.

    Modifies findings in place and returns the list.

    Args:
        findings: List of Finding objects

    Returns:
        Same list with recommendations added
    """
    for finding in findings:
        if finding.recommendation is None:
            finding.recommendation = get_recommendation(finding.message, finding.severity)
    return findings
