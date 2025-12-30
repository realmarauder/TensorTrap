"""Pickle file security scanner.

Analyzes pickle bytecode to detect potentially malicious code execution.
"""

from pathlib import Path

from tensortrap.formats.pickle_parser import (
    extract_globals,
    get_dangerous_opcodes,
    is_valid_pickle,
)
from tensortrap.scanner.results import Finding, Severity
from tensortrap.signatures.dangerous_imports import (
    DANGEROUS_FUNCTIONS,
    DANGEROUS_MODULES,
    KNOWN_MALICIOUS_CALLS,
)


def scan_pickle(data: bytes, filepath: Path | None = None) -> list[Finding]:
    """Scan pickle bytecode for security issues.

    Args:
        data: Raw pickle bytecode
        filepath: Optional path for error messages

    Returns:
        List of security findings
    """
    findings = []

    # Validate pickle format
    is_valid, error_msg = is_valid_pickle(data)
    if not is_valid:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message=f"Invalid pickle format: {error_msg}",
                location=0,
                details={"error": error_msg},
            )
        )
        # Continue analysis even with invalid pickle - may still extract useful info

    # Check for dangerous imports via GLOBAL opcode
    globals_found = extract_globals(data)

    for module, name, pos in globals_found:
        # Check for stack-based globals (can't determine actual value)
        if module == "<stack>":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message="STACK_GLOBAL opcode found (dynamic import)",
                    location=pos,
                    details={"opcode": "STACK_GLOBAL"},
                )
            )
            continue

        # Check for known malicious combinations first
        if (module, name) in KNOWN_MALICIOUS_CALLS:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    message=f"Known malicious call: {module}.{name}",
                    location=pos,
                    details={
                        "module": module,
                        "function": name,
                        "known_malicious": True,
                    },
                )
            )
            continue

        # Check for dangerous modules
        # Also check parent modules (e.g., "urllib.request" -> check "urllib")
        module_parts = module.split(".")
        is_dangerous_module = any(
            ".".join(module_parts[: i + 1]) in DANGEROUS_MODULES for i in range(len(module_parts))
        )

        if is_dangerous_module:
            # Determine severity based on the specific module/function
            if module in ("os", "subprocess", "builtins", "socket"):
                severity = Severity.CRITICAL
            elif module in ("sys", "importlib", "pickle", "marshal"):
                severity = Severity.HIGH
            else:
                severity = Severity.HIGH

            findings.append(
                Finding(
                    severity=severity,
                    message=(
                        f"Dangerous import: {module}.{name}"
                        if name
                        else f"Dangerous import: {module}"
                    ),
                    location=pos,
                    details={"module": module, "function": name},
                )
            )

        # Check for dangerous functions from any module
        if name in DANGEROUS_FUNCTIONS:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    message=f"Dangerous function: {module}.{name}",
                    location=pos,
                    details={"module": module, "function": name},
                )
            )

    # Check for code execution opcodes
    dangerous_ops = get_dangerous_opcodes(data)

    reduce_count = 0
    for op in dangerous_ops:
        if op.name == "REDUCE":
            reduce_count += 1
        elif op.name in ("INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"):
            # Object creation - suspicious but context-dependent
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message=f"Object creation opcode: {op.name}",
                    location=op.pos,
                    details={"opcode": op.name},
                )
            )
        elif op.name == "BUILD":
            # BUILD can trigger __setstate__ which may execute code
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message="BUILD opcode found (may trigger __setstate__)",
                    location=op.pos,
                    details={"opcode": op.name},
                )
            )

    # Report REDUCE opcodes (function calls)
    # Only flag as high severity if we also found dangerous imports
    has_dangerous_imports = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH) and f.details and "module" in f.details
        for f in findings
    )

    if reduce_count > 0:
        severity = Severity.HIGH if has_dangerous_imports else Severity.MEDIUM
        findings.append(
            Finding(
                severity=severity,
                message=f"REDUCE opcode found {reduce_count} time(s) (function calls)",
                location=None,
                details={"opcode": "REDUCE", "count": reduce_count},
            )
        )

    # Check if pickle imports nested pickle (potential multi-stage attack)
    for module, name, pos in globals_found:
        if module == "pickle" or (module == "_pickle"):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    message="Nested pickle import detected (potential multi-stage attack)",
                    location=pos,
                    details={"module": module, "function": name},
                )
            )

    return findings


def scan_pickle_file(filepath: Path) -> list[Finding]:
    """Scan a pickle file for security issues.

    Handles both raw pickle files and PyTorch ZIP archives containing pickles.

    Args:
        filepath: Path to pickle file

    Returns:
        List of security findings
    """
    from tensortrap.formats.pytorch_zip import (
        is_7z_archive,
        is_pytorch_zip,
    )

    findings = []
    filepath = Path(filepath)

    # Check for 7z archive (nullifAI bypass - CVE-2025-1716)
    if is_7z_archive(filepath):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message="7z archive detected - potential nullifAI bypass (CVE-2025-1716)",
                location=0,
                details={"format": "7z", "cve": "CVE-2025-1716"},
            )
        )
        return findings

    # Check if this is a PyTorch ZIP archive
    if is_pytorch_zip(filepath):
        findings.extend(_scan_pytorch_archive(filepath))
        return findings

    # Handle raw pickle file
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

    return scan_pickle(data, filepath)


def _scan_pytorch_archive(filepath: Path) -> list[Finding]:
    """Scan a PyTorch ZIP archive for security issues.

    Args:
        filepath: Path to PyTorch .pt/.pth file

    Returns:
        List of findings from internal pickle files
    """
    from tensortrap.formats.pytorch_zip import (
        analyze_zip_structure,
        extract_pickle_files,
    )

    findings = []

    # Analyze ZIP structure
    zip_info = analyze_zip_structure(filepath)

    if not zip_info["is_valid_zip"]:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                message=f"Invalid ZIP archive: {zip_info.get('error', 'unknown error')}",
                location=None,
                details=zip_info,
            )
        )
        return findings

    # Check for path traversal (ZipSlip)
    if zip_info["suspicious_paths"]:
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                message="Path traversal detected in ZIP archive (ZipSlip)",
                location=None,
                details={
                    "suspicious_paths": zip_info["suspicious_paths"],
                    "vulnerability": "ZipSlip",
                },
            )
        )

    # Note that this is a ZIP archive
    findings.append(
        Finding(
            severity=Severity.INFO,
            message=f"PyTorch ZIP archive with {len(zip_info['pickle_files'])} pickle file(s)",
            location=None,
            details={
                "file_count": zip_info["file_count"],
                "pickle_files": zip_info["pickle_files"],
            },
        )
    )

    # Extract and scan internal pickle files
    pickle_files = extract_pickle_files(filepath)

    for name, data in pickle_files:
        internal_findings = scan_pickle(data, filepath)

        # Add context about which internal file
        for finding in internal_findings:
            if finding.details is None:
                finding.details = {}
            finding.details["internal_file"] = name
            finding.details["archive"] = str(filepath)

        findings.extend(internal_findings)

    return findings
