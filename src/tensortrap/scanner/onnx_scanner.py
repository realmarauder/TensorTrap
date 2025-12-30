"""ONNX file security scanner.

Scans ONNX files for path traversal vulnerabilities in external data
references (CVE-2024-27318, CVE-2024-5187).
"""

from pathlib import Path

from tensortrap.formats.onnx_parser import analyze_onnx
from tensortrap.scanner.results import Finding, Severity


def scan_onnx(filepath: Path) -> list[Finding]:
    """Scan an ONNX file for security issues.

    Primary focus: Path traversal via external_data references.

    Args:
        filepath: Path to ONNX file

    Returns:
        List of security findings
    """
    findings = []

    # Analyze the ONNX file
    onnx_info, error = analyze_onnx(filepath)

    if error:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message=f"ONNX analysis error: {error}",
                location=None,
                details={"error": error},
            )
        )
        return findings

    if onnx_info is None:
        return findings

    # Check for path traversal (CVE-2024-27318, CVE-2024-5187)
    if onnx_info.has_path_traversal:
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                message="Path traversal in external data reference (CVE-2024-27318)",
                location=None,
                details={
                    "suspicious_refs": onnx_info.suspicious_refs,
                    "cve": ["CVE-2024-27318", "CVE-2024-5187"],
                    "description": "ONNX external data references can read/write arbitrary files",
                },
            )
        )

    # Report all external data references (even if not obviously malicious)
    if onnx_info.external_data_refs:
        # Check for suspicious patterns even if not explicit traversal
        suspicious_patterns = [
            ("/etc/", "System config directory"),
            ("/tmp/", "Temp directory"),  # nosec B108 - detection pattern, not usage
            ("passwd", "Password file"),
            ("shadow", "Shadow file"),
            (".ssh", "SSH directory"),
            ("id_rsa", "SSH key"),
            (".env", "Environment file"),
            ("credentials", "Credentials file"),
            ("secret", "Secrets file"),
            ("token", "Token file"),
        ]

        for ref in onnx_info.external_data_refs:
            ref_lower = ref.lower()

            for pattern, description in suspicious_patterns:
                if pattern in ref_lower:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            message=f"Suspicious external data path: {description}",
                            location=None,
                            details={
                                "path": ref,
                                "pattern": pattern,
                            },
                        )
                    )
                    break

        # Info-level note about external data usage
        non_suspicious = [
            ref for ref in onnx_info.external_data_refs if ref not in onnx_info.suspicious_refs
        ]
        if non_suspicious:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    message=f"Model uses {len(non_suspicious)} external data file(s)",
                    location=None,
                    details={"external_refs": non_suspicious},
                )
            )

    # Report version info if available
    if onnx_info.ir_version:
        findings.append(
            Finding(
                severity=Severity.INFO,
                message=f"ONNX IR version: {onnx_info.ir_version}",
                location=None,
                details={"ir_version": onnx_info.ir_version},
            )
        )

    return findings


# Alias for consistency with other scanners
scan_onnx_file = scan_onnx
