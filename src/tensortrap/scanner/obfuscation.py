"""Obfuscation detection for model files.

Detects attempts to hide malicious payloads through:
- Base64 encoding
- Compression
- String manipulation
- High entropy regions
- Unusual byte patterns
"""

import base64
import math
import re
import zlib
from dataclasses import dataclass

from tensortrap.scanner.results import Finding, Severity


@dataclass
class ObfuscationAnalysis:
    """Results of obfuscation analysis."""

    entropy: float
    has_base64: bool
    has_compressed: bool
    has_hex_strings: bool
    has_unicode_escape: bool
    suspicious_regions: list[dict]


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data.

    High entropy (> 7.5) suggests encryption or compression.

    Args:
        data: Bytes to analyze

    Returns:
        Entropy value (0-8 for bytes)
    """
    if not data:
        return 0.0

    # Count byte frequencies
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1

    # Calculate entropy
    entropy = 0.0
    data_len = len(data)

    for count in freq:
        if count > 0:
            prob = count / data_len
            entropy -= prob * math.log2(prob)

    return entropy


def detect_base64(data: bytes) -> list[dict]:
    """Detect base64-encoded regions in data.

    Args:
        data: Bytes to analyze

    Returns:
        List of detected base64 regions
    """
    regions = []

    # Look for base64 patterns
    # Base64 uses A-Za-z0-9+/= characters
    # Minimum length for meaningful base64 is ~20 chars
    b64_pattern = rb"[A-Za-z0-9+/]{20,}={0,2}"

    for match in re.finditer(b64_pattern, data):
        candidate = match.group(0)

        # Try to decode
        try:
            # Add padding if needed
            padded = (
                candidate + b"=" * (4 - len(candidate) % 4) if len(candidate) % 4 else candidate
            )
            decoded = base64.b64decode(padded, validate=True)

            # Check if decoded content looks suspicious
            if len(decoded) >= 10:
                decoded_entropy = calculate_entropy(decoded)

                # Check for suspicious decoded content
                suspicious_patterns = [
                    b"import ",
                    b"exec(",
                    b"eval(",
                    b"os.",
                    b"subprocess",
                    b"socket",
                    b"__",
                    b"system(",
                ]

                is_suspicious = any(p in decoded for p in suspicious_patterns)

                if is_suspicious or (decoded_entropy > 4.0 and decoded_entropy < 7.0):
                    regions.append(
                        {
                            "type": "base64",
                            "position": match.start(),
                            "length": len(candidate),
                            "decoded_length": len(decoded),
                            "decoded_entropy": decoded_entropy,
                            "suspicious": is_suspicious,
                            "preview": decoded[:50].hex() if is_suspicious else None,
                        }
                    )

        except Exception:
            pass  # Not valid base64

    return regions


def detect_compressed(data: bytes) -> list[dict]:
    """Detect compressed/deflated regions in data.

    Args:
        data: Bytes to analyze

    Returns:
        List of detected compressed regions
    """
    regions = []

    # Look for zlib/deflate magic bytes
    zlib_headers = [
        (b"\x78\x01", "zlib_low"),
        (b"\x78\x5e", "zlib_default"),
        (b"\x78\x9c", "zlib_default2"),
        (b"\x78\xda", "zlib_best"),
    ]

    for magic, compression_type in zlib_headers:
        start = 0
        while True:
            pos = data.find(magic, start)
            if pos == -1:
                break

            # Try to decompress
            try:
                decompressed = zlib.decompress(data[pos : pos + 65536])
                if len(decompressed) > 20:
                    regions.append(
                        {
                            "type": "zlib",
                            "position": pos,
                            "compression": compression_type,
                            "decompressed_size": len(decompressed),
                        }
                    )
            except Exception:
                pass

            start = pos + 1

    # Look for gzip magic
    gzip_pos = data.find(b"\x1f\x8b\x08")
    if gzip_pos != -1:
        regions.append(
            {
                "type": "gzip",
                "position": gzip_pos,
            }
        )

    return regions


def detect_hex_strings(data: bytes) -> list[dict]:
    """Detect hex-encoded strings.

    Args:
        data: Bytes to analyze

    Returns:
        List of detected hex regions
    """
    regions = []

    # Look for hex strings (40+ chars of 0-9a-fA-F)
    hex_pattern = rb"[0-9a-fA-F]{40,}"

    for match in re.finditer(hex_pattern, data):
        candidate = match.group(0)

        # Try to decode as hex
        try:
            decoded = bytes.fromhex(candidate.decode("ascii"))

            # Check for suspicious content
            suspicious_patterns = [b"import", b"exec", b"eval", b"os.", b"__"]
            is_suspicious = any(p in decoded for p in suspicious_patterns)

            if is_suspicious or len(decoded) > 50:
                regions.append(
                    {
                        "type": "hex",
                        "position": match.start(),
                        "length": len(candidate),
                        "decoded_length": len(decoded),
                        "suspicious": is_suspicious,
                    }
                )

        except Exception:
            pass

    return regions


def detect_unicode_escape(data: bytes) -> list[dict]:
    """Detect unicode escape sequences used for obfuscation.

    Args:
        data: Bytes to analyze

    Returns:
        List of detected unicode escape regions
    """
    regions = []

    # Look for unicode escapes like \x00, \u0000, etc.
    escape_patterns = [
        (rb"(\\x[0-9a-fA-F]{2}){10,}", "hex_escape"),
        (rb"(\\u[0-9a-fA-F]{4}){5,}", "unicode_escape"),
        (rb"(\\[0-7]{3}){10,}", "octal_escape"),
    ]

    for pattern, escape_type in escape_patterns:
        for match in re.finditer(pattern, data):
            regions.append(
                {
                    "type": escape_type,
                    "position": match.start(),
                    "length": len(match.group(0)),
                }
            )

    return regions


def analyze_obfuscation(data: bytes) -> ObfuscationAnalysis:
    """Perform comprehensive obfuscation analysis.

    Args:
        data: Bytes to analyze

    Returns:
        ObfuscationAnalysis with results
    """
    entropy = calculate_entropy(data)
    base64_regions = detect_base64(data)
    compressed_regions = detect_compressed(data)
    hex_regions = detect_hex_strings(data)
    unicode_regions = detect_unicode_escape(data)

    suspicious_regions = []
    suspicious_regions.extend(base64_regions)
    suspicious_regions.extend(compressed_regions)
    suspicious_regions.extend(hex_regions)
    suspicious_regions.extend(unicode_regions)

    return ObfuscationAnalysis(
        entropy=entropy,
        has_base64=len(base64_regions) > 0,
        has_compressed=len(compressed_regions) > 0,
        has_hex_strings=len(hex_regions) > 0,
        has_unicode_escape=len(unicode_regions) > 0,
        suspicious_regions=suspicious_regions,
    )


def scan_for_obfuscation(data: bytes) -> list[Finding]:
    """Scan data for obfuscation techniques.

    Args:
        data: Raw bytes to scan

    Returns:
        List of findings
    """
    findings = []

    analysis = analyze_obfuscation(data)

    # High entropy warning
    if analysis.entropy > 7.5:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message=f"Very high entropy ({analysis.entropy:.2f}) - possible encryption",
                location=None,
                details={
                    "entropy": analysis.entropy,
                    "threshold": 7.5,
                },
            )
        )

    # Base64 obfuscation
    suspicious_b64 = [
        r for r in analysis.suspicious_regions if r.get("type") == "base64" and r.get("suspicious")
    ]
    if suspicious_b64:
        count = len(suspicious_b64)
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=f"Suspicious base64-encoded payload detected ({count} region(s))",
                location=suspicious_b64[0].get("position"),
                details={
                    "regions": suspicious_b64[:5],
                    "technique": "base64_obfuscation",
                },
            )
        )

    # Embedded compressed data
    if analysis.has_compressed:
        compressed = [r for r in analysis.suspicious_regions if r.get("type") in ("zlib", "gzip")]
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message=f"Embedded compressed data detected ({len(compressed)} region(s))",
                location=compressed[0].get("position") if compressed else None,
                details={
                    "regions": compressed[:5],
                    "technique": "compression_hiding",
                },
            )
        )

    # Hex string obfuscation
    suspicious_hex = [
        r for r in analysis.suspicious_regions if r.get("type") == "hex" and r.get("suspicious")
    ]
    if suspicious_hex:
        count = len(suspicious_hex)
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=f"Suspicious hex-encoded payload detected ({count} region(s))",
                location=suspicious_hex[0].get("position") if suspicious_hex else None,
                details={
                    "regions": suspicious_hex[:5],
                    "technique": "hex_obfuscation",
                },
            )
        )

    # Unicode escape obfuscation
    if analysis.has_unicode_escape:
        unicode_regions = [r for r in analysis.suspicious_regions if "escape" in r.get("type", "")]
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message=f"Unicode escape obfuscation detected ({len(unicode_regions)} region(s))",
                location=(unicode_regions[0].get("position") if unicode_regions else None),
                details={
                    "regions": unicode_regions[:5],
                    "technique": "unicode_escape",
                },
            )
        )

    return findings
