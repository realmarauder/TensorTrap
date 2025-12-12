"""Keras/HDF5 model file scanner.

Keras .h5 and .keras files can contain pickle-serialized custom objects
that execute code on load. This scanner detects embedded pickle data
and suspicious patterns in HDF5 model files.
"""

import re
from pathlib import Path

from tensortrap.scanner.pickle_scanner import scan_pickle
from tensortrap.scanner.results import Finding, Severity

# HDF5 magic number
HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"

# Patterns that indicate pickle data in HDF5
PICKLE_MARKERS = [
    b"\x80\x02",  # Pickle protocol 2
    b"\x80\x03",  # Pickle protocol 3
    b"\x80\x04",  # Pickle protocol 4
    b"\x80\x05",  # Pickle protocol 5
    b"ccopy_reg",  # copy_reg module (pickle)
    b"c__builtin__",  # builtins (pickle)
]

# Suspicious patterns in Keras config
SUSPICIOUS_CONFIG_PATTERNS = [
    (rb"lambda\s*:", "Lambda function (may execute code)", Severity.HIGH),
    (rb"__call__", "Callable object", Severity.MEDIUM),
    (rb"custom_objects", "Custom objects (may contain code)", Severity.MEDIUM),
    (rb"get_custom_objects", "Custom object retrieval", Severity.MEDIUM),
    (rb"eval\s*\(", "eval() call", Severity.CRITICAL),
    (rb"exec\s*\(", "exec() call", Severity.CRITICAL),
    (rb"__import__", "Dynamic import", Severity.CRITICAL),
    (rb"os\.(system|popen)", "OS command execution", Severity.CRITICAL),
    (rb"subprocess", "Subprocess execution", Severity.CRITICAL),
]


def is_hdf5_file(filepath: Path) -> bool:
    """Check if file is an HDF5 file.

    Args:
        filepath: Path to check

    Returns:
        True if file has HDF5 magic number
    """
    try:
        with open(filepath, "rb") as f:
            magic = f.read(8)
            return magic == HDF5_MAGIC
    except OSError:
        return False


def scan_keras(filepath: Path) -> list[Finding]:
    """Scan a Keras/HDF5 model file for security issues.

    Args:
        filepath: Path to .h5 or .keras file

    Returns:
        List of security findings
    """
    findings = []
    filepath = Path(filepath)

    # Verify HDF5 format
    if not is_hdf5_file(filepath):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message="File does not have HDF5 magic number",
                location=0,
                details={},
            )
        )
        # Continue anyway - might be a Keras v3 format

    # Read file content for scanning
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError as e:
        return [
            Finding(
                severity=Severity.MEDIUM,
                message=f"Failed to read file: {e}",
                location=None,
                details={"error": str(e)},
            )
        ]

    # Check file size
    if len(data) > 10 * 1024 * 1024 * 1024:  # 10GB
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message="Very large file - scanning may be incomplete",
                location=None,
                details={"size_bytes": len(data)},
            )
        )

    # Scan for embedded pickle data
    pickle_findings = _scan_for_pickle(data, filepath)
    findings.extend(pickle_findings)

    # Scan for suspicious config patterns
    config_findings = _scan_config_patterns(data)
    findings.extend(config_findings)

    # Check for Lambda layers (common attack vector)
    if b"Lambda" in data and b"function" in data:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message="Keras Lambda layer detected (executes arbitrary code)",
                location=None,
                details={
                    "description": "Lambda layers execute Python code on model load",
                    "recommendation": "Avoid Lambda layers from untrusted sources",
                },
            )
        )

    return findings


# Alias for consistency with other scanners
scan_keras_file = scan_keras


def _scan_for_pickle(data: bytes, filepath: Path) -> list[Finding]:
    """Scan HDF5 data for embedded pickle content.

    Args:
        data: Raw file bytes
        filepath: Path for context

    Returns:
        List of findings
    """
    findings = []
    pickle_regions = []

    # Find pickle markers
    for marker in PICKLE_MARKERS:
        start = 0
        while True:
            pos = data.find(marker, start)
            if pos == -1:
                break
            pickle_regions.append(pos)
            start = pos + 1

    if pickle_regions:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=f"Embedded pickle data detected ({len(pickle_regions)} region(s))",
                location=pickle_regions[0] if pickle_regions else None,
                details={
                    "pickle_count": len(pickle_regions),
                    "positions": pickle_regions[:10],  # First 10
                },
            )
        )

        # Try to extract and scan pickle regions
        for pos in pickle_regions[:5]:  # Scan first 5 pickle regions
            # Extract pickle data (heuristic: look for STOP opcode)
            pickle_data = _extract_pickle_region(data, pos)
            if pickle_data:
                pickle_findings = scan_pickle(pickle_data, filepath)
                for finding in pickle_findings:
                    if finding.details is None:
                        finding.details = {}
                    finding.details["embedded_at"] = pos
                    finding.details["context"] = "Embedded in HDF5"
                findings.extend(pickle_findings)

    return findings


def _extract_pickle_region(data: bytes, start: int) -> bytes | None:
    """Extract a pickle region from HDF5 data.

    Args:
        data: Full file data
        start: Start position of pickle marker

    Returns:
        Extracted pickle bytes or None
    """
    # Look for STOP opcode (.) which ends pickle
    # Limit search to 10MB to avoid scanning huge regions
    max_len = min(10 * 1024 * 1024, len(data) - start)

    for i in range(start, start + max_len):
        if data[i : i + 1] == b".":
            # Verify this looks like a valid pickle ending
            # (STOP is the last opcode)
            return data[start : i + 1]

    # If no STOP found, return first 64KB
    return data[start : start + 65536]


def _scan_config_patterns(data: bytes) -> list[Finding]:
    """Scan for suspicious patterns in Keras config.

    Args:
        data: Raw file bytes

    Returns:
        List of findings
    """
    findings = []

    for pattern, description, severity in SUSPICIOUS_CONFIG_PATTERNS:
        matches = list(re.finditer(pattern, data, re.IGNORECASE))
        if matches:
            findings.append(
                Finding(
                    severity=severity,
                    message=f"Suspicious pattern: {description}",
                    location=matches[0].start(),
                    details={
                        "pattern": pattern.decode("utf-8", errors="ignore"),
                        "match_count": len(matches),
                    },
                )
            )

    return findings
