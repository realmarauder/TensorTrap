"""GGUF file security scanner.

Analyzes GGUF files for structural integrity and potential security issues,
including Jinja template injection in chat templates (CVE-2024-34359).
"""

from pathlib import Path

from tensortrap.formats.gguf_parser import (
    SUPPORTED_VERSIONS,
    get_chat_template,
    parse_header,
)
from tensortrap.scanner.results import Finding, Severity

# Sanity limits
MAX_REASONABLE_TENSORS = 100_000
MAX_REASONABLE_METADATA = 10_000

# Jinja template injection patterns (CVE-2024-34359)
JINJA_DANGEROUS_PATTERNS = [
    ("{{", "}}", "Jinja expression"),
    ("{%", "%}", "Jinja statement"),
    ("__class__", None, "__class__ access"),
    ("__mro__", None, "__mro__ access"),
    ("__subclasses__", None, "__subclasses__ access"),
    ("__globals__", None, "__globals__ access"),
    ("__builtins__", None, "__builtins__ access"),
    ("__import__", None, "__import__ call"),
    ("os.popen", None, "os.popen call"),
    ("subprocess", None, "subprocess reference"),
]


def scan_gguf(filepath: Path) -> list[Finding]:
    """Scan a GGUF file for security issues.

    Args:
        filepath: Path to GGUF file

    Returns:
        List of security findings
    """
    findings = []

    # Parse header
    header, error = parse_header(filepath)

    if error:
        severity = Severity.CRITICAL if "magic" in error.lower() else Severity.MEDIUM
        findings.append(
            Finding(
                severity=severity,
                message=f"GGUF parse error: {error}",
                location=0,
                details={"error": error},
            )
        )
        if header is None:
            return findings

    # Ensure header is not None for type checker
    if header is None:
        return findings

    # Check version
    if header.version not in SUPPORTED_VERSIONS:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message=f"Unknown GGUF version: {header.version}",
                location=4,
                details={
                    "version": header.version,
                    "supported": list(SUPPORTED_VERSIONS),
                },
            )
        )

    # Check tensor count sanity
    if header.tensor_count > MAX_REASONABLE_TENSORS:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=f"Unusually high tensor count: {header.tensor_count:,}",
                location=8,
                details={"tensor_count": header.tensor_count},
            )
        )

    # Check metadata count sanity
    if header.metadata_kv_count > MAX_REASONABLE_METADATA:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=f"Unusually high metadata count: {header.metadata_kv_count:,}",
                location=16,
                details={"metadata_kv_count": header.metadata_kv_count},
            )
        )

    # Check for chat template (potential Jinja injection - CVE-2024-34359)
    chat_template = get_chat_template(header)
    if chat_template:
        findings.append(
            Finding(
                severity=Severity.INFO,
                message="Chat template present (review for Jinja injection - CVE-2024-34359)",
                location=None,
                details={"has_chat_template": True},
            )
        )

        # Scan template for dangerous patterns
        template_findings = _scan_chat_template(chat_template)
        findings.extend(template_findings)

    # Scan all metadata values for suspicious content
    findings.extend(_scan_metadata(header.metadata))

    return findings


def _scan_chat_template(template: str) -> list[Finding]:
    """Scan chat template for Jinja injection patterns.

    Args:
        template: Chat template string

    Returns:
        List of findings
    """
    findings = []

    for pattern_start, pattern_end, description in JINJA_DANGEROUS_PATTERNS:
        if pattern_start in template:
            if pattern_end is None or pattern_end in template:
                # Check for actual exploit patterns vs normal Jinja usage
                is_exploit_pattern = any(
                    exploit in template.lower()
                    for exploit in [
                        "__class__",
                        "__mro__",
                        "__subclasses__",
                        "__globals__",
                        "__builtins__",
                        "popen",
                        "subprocess",
                        "os.system",
                    ]
                )

                if is_exploit_pattern:
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            message=f"Potential Jinja injection in chat template: {description}",
                            location=None,
                            details={
                                "pattern": pattern_start,
                                "description": description,
                                "cve": "CVE-2024-34359",
                            },
                        )
                    )
                elif pattern_start in ("{{", "{%"):
                    # Normal Jinja usage - just informational
                    pass
                else:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            message=f"Suspicious pattern in chat template: {description}",
                            location=None,
                            details={
                                "pattern": pattern_start,
                                "description": description,
                            },
                        )
                    )

    return findings


def _scan_metadata(metadata: dict) -> list[Finding]:
    """Scan metadata for suspicious content.

    Args:
        metadata: GGUF metadata dictionary

    Returns:
        List of findings
    """
    findings = []

    suspicious_keys = [
        "script",
        "code",
        "exec",
        "eval",
        "command",
        "shell",
    ]

    for key, value in metadata.items():
        # Check for suspicious key names
        key_lower = key.lower()
        for suspicious in suspicious_keys:
            if suspicious in key_lower:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        message=f"Suspicious metadata key: {key}",
                        location=None,
                        details={"key": key},
                    )
                )
                break

        # Check string values for suspicious content
        if isinstance(value, str) and len(value) > 0:
            # Very long strings might be payloads
            if len(value) > 1_000_000:  # 1MB
                size = len(value)
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        message=f"Unusually large metadata value for key '{key}': {size:,} bytes",
                        location=None,
                        details={"key": key, "size": size},
                    )
                )

            # Check for code patterns
            code_patterns = [
                "import os",
                "import subprocess",
                "eval(",
                "exec(",
                "__import__",
            ]
            for pattern in code_patterns:
                if pattern in value:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            message=f"Code pattern in metadata key '{key}': {pattern}",
                            location=None,
                            details={"key": key, "pattern": pattern},
                        )
                    )

    return findings
