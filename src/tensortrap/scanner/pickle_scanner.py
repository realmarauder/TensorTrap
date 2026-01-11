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
            # Check if the base module is in CRITICAL category
            base_module = module_parts[0]
            if base_module in (
                "os",
                "subprocess",
                "builtins",
                "socket",
                "posix",
                "nt",
                "_posixsubprocess",
                "_winapi",
                "asyncio",
                "pip",
                "multiprocessing",
            ):
                severity = Severity.CRITICAL
            elif base_module in ("sys", "importlib", "pickle", "marshal"):
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
    Also detects archive-based bypass techniques (CVE-2025-1889).

    Args:
        filepath: Path to pickle file

    Returns:
        List of security findings
    """
    from tensortrap.formats.pytorch_zip import (
        is_7z_archive,
        is_pytorch_zip,
        scan_7z_for_pickle,
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

        # Scan 7z for embedded pickle data
        scan_result = scan_7z_for_pickle(filepath)
        if scan_result["contains_pickle"]:
            offsets = scan_result["pickle_offsets"]
            protocols = scan_result["pickle_protocols"]
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    message=f"Pickle data found inside 7z archive at {len(offsets)} location(s)",
                    location=offsets[0] if offsets else 0,
                    details={
                        "technique": "7z_embedded_pickle",
                        "pickle_offsets": offsets,
                        "pickle_protocols": protocols,
                        "cve": "CVE-2025-1889",
                        "warning": "Malicious pickle hidden inside 7z archive",
                    },
                )
            )

            # Try to scan the pickle content
            try:
                with open(filepath, "rb") as f:
                    data = f.read()
                # Scan pickle starting from first found offset
                if offsets:
                    pickle_data = data[offsets[0] :]
                    pickle_findings = scan_pickle(pickle_data, filepath)
                    for pf in pickle_findings:
                        if pf.details is None:
                            pf.details = {}
                        pf.details["source"] = "7z_embedded_pickle"
                        pf.details["base_offset"] = offsets[0]
                    findings.extend(pickle_findings)
            except OSError:
                pass

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

    Also checks for trailing data after the ZIP archive (CVE-2025-1889 bypass)
    and zeroed CRC attacks (CVE-2025-10156 bypass).

    Args:
        filepath: Path to PyTorch .pt/.pth file

    Returns:
        List of findings from internal pickle files
    """
    from tensortrap.formats.pytorch_zip import (
        analyze_zip_structure,
        check_zip_trailing_data,
        extract_pickle_files,
        extract_trailing_pickle,
        scan_zip_raw_for_pickle,
    )

    findings = []

    # CVE-2025-10156: Scan raw ZIP structure for zeroed CRCs
    # This bypasses zipfile.ZipFile which may fail on corrupted CRCs
    raw_scan = scan_zip_raw_for_pickle(filepath)

    if raw_scan["has_zeroed_crc"]:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=(
                    f"ZIP archive has zeroed CRC values (CVE-2025-10156 bypass): "
                    f"{', '.join(raw_scan['zeroed_crc_files'][:3])}"
                ),
                location=0,
                details={
                    "technique": "zip_crc_bypass",
                    "zeroed_crc_files": raw_scan["zeroed_crc_files"],
                    "cve": "CVE-2025-10156",
                    "warning": "Zeroed CRCs may bypass integrity checks",
                },
            )
        )

    if raw_scan["contains_pickle"]:
        # Scan the pickle content from raw offsets to check if actually malicious
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            for fname, offset in zip(raw_scan["pickle_files_found"], raw_scan["pickle_offsets"]):
                pickle_data = data[offset:]
                pickle_findings = scan_pickle(pickle_data, filepath)

                # Add metadata to pickle findings
                for pf in pickle_findings:
                    if pf.details is None:
                        pf.details = {}
                    pf.details["source"] = "zip_raw_extraction"
                    pf.details["base_offset"] = offset
                    pf.details["filename"] = fname
                    if raw_scan["has_zeroed_crc"] and fname in raw_scan.get("zeroed_crc_files", []):
                        pf.details["zeroed_crc"] = True
                        pf.details["cve"] = "CVE-2025-10156"
                findings.extend(pickle_findings)
        except OSError:
            pass

    # Analyze ZIP structure (may fail with zeroed CRCs, but try anyway)
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

    # Check for trailing data after ZIP (CVE-2025-1889 style bypass)
    trailing_info = check_zip_trailing_data(filepath)
    if trailing_info["has_trailing_data"]:
        if trailing_info["trailing_contains_pickle"]:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    message=(
                        f"Pickle data appended after ZIP archive at offset "
                        f"{trailing_info['pickle_offset']} (CVE-2025-1889 bypass)"
                    ),
                    location=trailing_info["pickle_offset"],
                    details={
                        "technique": "zip_trailing_pickle",
                        "zip_end_offset": trailing_info["zip_end_offset"],
                        "trailing_size": trailing_info["trailing_size"],
                        "pickle_offset": trailing_info["pickle_offset"],
                        "pickle_protocol": trailing_info["pickle_protocol"],
                        "cve": "CVE-2025-1889",
                        "warning": "Archive bypass - malicious pickle hidden after ZIP",
                    },
                )
            )

            # Extract and scan the trailing pickle
            trailing_pickle = extract_trailing_pickle(filepath)
            if trailing_pickle:
                trailing_findings = scan_pickle(trailing_pickle, filepath)
                for tf in trailing_findings:
                    if tf.details is None:
                        tf.details = {}
                    tf.details["source"] = "zip_trailing_data"
                    tf.details["base_offset"] = trailing_info["pickle_offset"]
                findings.extend(trailing_findings)
        else:
            # Trailing data but not pickle - still suspicious
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message=(
                        f"Suspicious trailing data after ZIP archive: "
                        f"{trailing_info['trailing_size']} bytes"
                    ),
                    location=trailing_info["zip_end_offset"],
                    details={
                        "technique": "zip_trailing_data",
                        "zip_end_offset": trailing_info["zip_end_offset"],
                        "trailing_size": trailing_info["trailing_size"],
                        "warning": "Data appended after archive end",
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
