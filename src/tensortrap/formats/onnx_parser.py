"""ONNX file parser for security analysis.

ONNX files are Protocol Buffers that can contain external_data
references which may point to arbitrary file paths, enabling
path traversal attacks (CVE-2024-27318, CVE-2024-5187).
"""

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ONNXInfo:
    """Information extracted from ONNX file."""

    ir_version: int | None
    producer_name: str | None
    producer_version: str | None
    external_data_refs: list[str]
    has_path_traversal: bool
    suspicious_refs: list[str]


# Path traversal patterns - only flag actual traversal attacks
# Absolute paths alone are NOT flagged (too many false positives from binary data)
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",  # Unix relative path traversal
    r"\.\.\\",  # Windows relative path traversal
]


def _is_likely_real_path(s: str) -> bool:
    """Check if a string looks like a real file path, not binary garbage.

    Real paths have mostly alphanumeric characters with path separators.
    Binary garbage looks like: /=zT[=v, K:/y, />Wa, /L;s9

    Args:
        s: String to check

    Returns:
        True if looks like a real path
    """
    if len(s) < 4:
        return False

    # Count alphanumeric vs other characters
    alnum_count = sum(1 for c in s if c.isalnum() or c in "._-")

    # Real paths should be mostly alphanumeric (at least 70%)
    # e.g., "../../../etc/passwd" has high alnum ratio
    # vs "/=zT[=v" or "/L;s9" which have low alnum ratio
    alnum_ratio = alnum_count / len(s)
    if alnum_ratio < 0.7:
        return False

    # Should have at least one proper path segment (3+ alnum chars together)
    # e.g., "etc", "passwd", "data.bin" - not just "L" or "s9"
    if not re.search(r"[a-zA-Z0-9_]{3,}", s):
        return False

    # Must not contain non-path special characters
    # Real paths only have: alphanumeric, /, \, ., _, -
    invalid_chars = set(s) - set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/\\._-"
    )
    if invalid_chars:
        return False

    return True


def analyze_onnx(filepath: Path) -> tuple[ONNXInfo | None, str | None]:
    """Analyze an ONNX file for security issues.

    This performs pattern-based analysis without full protobuf parsing.

    Args:
        filepath: Path to ONNX file

    Returns:
        Tuple of (ONNXInfo, error_message)
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError as e:
        return None, f"Failed to read file: {e}"

    # Extract string-like data from binary
    # ONNX stores strings as length-prefixed in protobuf
    strings = _extract_strings(data)

    # Look for external_data references
    external_refs = []
    suspicious_refs = []

    for s in strings:
        # Check if this looks like a file path (and not binary garbage)
        if _is_likely_real_path(s) and (
            "/" in s or "\\" in s or s.endswith((".bin", ".weight", ".data"))
        ):
            external_refs.append(s)

            # Check for path traversal patterns
            for pattern in PATH_TRAVERSAL_PATTERNS:
                if re.search(pattern, s):
                    suspicious_refs.append(s)
                    break

    # Try to extract version info
    ir_version = _extract_ir_version(data)

    return (
        ONNXInfo(
            ir_version=ir_version,
            producer_name=_find_producer_name(strings),
            producer_version=None,
            external_data_refs=external_refs,
            has_path_traversal=len(suspicious_refs) > 0,
            suspicious_refs=suspicious_refs,
        ),
        None,
    )


def _extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable strings from binary data.

    Args:
        data: Binary data
        min_length: Minimum string length

    Returns:
        List of extracted strings
    """
    strings = []
    current = []

    for byte in data:
        if 32 <= byte < 127:  # Printable ASCII
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []

    if len(current) >= min_length:
        strings.append("".join(current))

    return strings


def _extract_ir_version(data: bytes) -> int | None:
    """Extract IR version from ONNX data.

    The IR version is typically the first field (field 1) as a varint.

    Args:
        data: ONNX file data

    Returns:
        IR version or None
    """
    if len(data) < 2:
        return None

    # Field 1, wire type 0 (varint) = 0x08
    if data[0] == 0x08:
        # Simple varint decoding for small numbers
        if data[1] < 128:
            return data[1]

    return None


def _find_producer_name(strings: list[str]) -> str | None:
    """Find producer name in extracted strings.

    Args:
        strings: List of extracted strings

    Returns:
        Producer name or None
    """
    known_producers = ["pytorch", "tensorflow", "onnx", "keras", "caffe", "mxnet"]

    for s in strings:
        s_lower = s.lower()
        for producer in known_producers:
            if producer in s_lower:
                return s

    return None
