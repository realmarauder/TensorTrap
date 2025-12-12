"""Safetensors file security scanner.

Safetensors is designed to be safe (no code execution), but we validate
structure and check for anomalies or embedded malicious content.
"""

import re
from pathlib import Path

from tensortrap.formats.safetensors_parser import (
    parse_header,
    validate_tensor_offsets,
)
from tensortrap.scanner.results import Finding, Severity
from tensortrap.signatures.patterns import SUSPICIOUS_PATTERNS

# Maximum reasonable header size (10MB)
MAX_HEADER_SIZE = 10_000_000

# Suspicious header size threshold (1MB - unusually large)
SUSPICIOUS_HEADER_SIZE = 1_000_000


def scan_safetensors(filepath: Path) -> list[Finding]:
    """Scan a safetensors file for security issues.

    Args:
        filepath: Path to safetensors file

    Returns:
        List of security findings
    """
    findings = []

    # Parse header
    header, error = parse_header(filepath)

    if error:
        findings.append(
            Finding(
                severity=Severity.HIGH if "size" in error.lower() else Severity.MEDIUM,
                message=f"Header parse error: {error}",
                location=0,
                details={"error": error},
            )
        )
        # If we can't parse header, we can't do further analysis
        if header is None:
            return findings

    # At this point header is guaranteed to not be None
    if header is None:
        return findings

    # Check header size
    if header.header_size > SUSPICIOUS_HEADER_SIZE:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message=f"Unusually large header: {header.header_size:,} bytes",
                location=0,
                details={"header_size": header.header_size},
            )
        )

    # Validate tensor offsets
    offset_errors = validate_tensor_offsets(filepath, header)

    # Separate truncation errors (offsets exceed file size) from other errors
    truncation_errors = []
    other_errors = []
    for tensor_name, error_msg in offset_errors:
        if "exceeds file size" in error_msg:
            truncation_errors.append((tensor_name, error_msg))
        else:
            other_errors.append((tensor_name, error_msg))

    # Consolidate truncation errors into single finding
    if truncation_errors:
        # Get file size from first error message for context
        file_size = None
        for _, msg in truncation_errors:
            if "file size" in msg:
                # Extract file size from message like "offset (X) exceeds file size (Y)"
                match = re.search(r"file size \((\d+)\)", msg)
                if match:
                    file_size = int(match.group(1))
                    break

        count = len(truncation_errors)
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=f"Invalid tensor offset: {count} tensor(s) exceed file size",
                location=8,
                details={
                    "truncated_tensors": count,
                    "total_tensors": len(header.tensors),
                    "file_size": file_size,
                    "sample_tensors": [t[0] for t in truncation_errors[:5]],
                },
            )
        )

    # Report other offset errors individually (these are more likely malicious)
    for tensor_name, error_msg in other_errors:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=f"Invalid tensor '{tensor_name}': {error_msg}",
                location=8,  # Header starts after size bytes
                details={"tensor": tensor_name, "error": error_msg},
            )
        )

    # Check metadata for suspicious content
    findings.extend(_scan_metadata(header.metadata))

    # Scan raw header JSON for suspicious patterns
    findings.extend(_scan_raw_header(header.raw_json.encode("utf-8")))

    return findings


def _scan_metadata(metadata: dict[str, str]) -> list[Finding]:
    """Scan metadata dictionary for suspicious content.

    Args:
        metadata: Safetensors metadata dictionary

    Returns:
        List of findings
    """
    findings = []

    for key, value in metadata.items():
        if not isinstance(value, str):
            continue

        # Check for embedded pickle (starts with protocol marker)
        if value.startswith("\\x80") or (len(value) > 0 and ord(value[0]) == 0x80):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    message=f"Possible embedded pickle in metadata key: {key}",
                    location=8,
                    details={"key": key, "pattern": "pickle_marker"},
                )
            )

        # Check for suspicious code patterns
        suspicious_strings = [
            ("eval(", "eval function call"),
            ("exec(", "exec function call"),
            ("import os", "os module import"),
            ("import subprocess", "subprocess module import"),
            ("__import__", "dynamic import"),
            ("os.system", "system command execution"),
            ("subprocess.run", "subprocess execution"),
            ("subprocess.Popen", "subprocess execution"),
            ("socket.socket", "network socket"),
        ]

        value_lower = value.lower()
        for pattern, description in suspicious_strings:
            if pattern.lower() in value_lower:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        message=f"Suspicious pattern in metadata key '{key}': {description}",
                        location=8,
                        details={"key": key, "pattern": pattern},
                    )
                )

        # Check for very long metadata values (potential payload)
        if len(value) > 100_000:  # 100KB
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message=f"Unusually large metadata value for key '{key}': {len(value):,} bytes",
                    location=8,
                    details={"key": key, "size": len(value)},
                )
            )

    return findings


def _scan_raw_header(header_bytes: bytes) -> list[Finding]:
    """Scan raw header bytes for suspicious patterns.

    Args:
        header_bytes: Raw header JSON as bytes

    Returns:
        List of findings
    """
    findings = []

    for pattern_name, pattern_regex, description in SUSPICIOUS_PATTERNS:
        matches = list(pattern_regex.finditer(header_bytes))
        if matches:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message=f"Suspicious pattern in header: {description}",
                    location=8 + matches[0].start(),
                    details={
                        "pattern": pattern_name,
                        "match_count": len(matches),
                    },
                )
            )

    return findings
