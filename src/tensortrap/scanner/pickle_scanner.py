"""Pickle file security scanner.

Analyzes pickle bytecode to detect potentially malicious code execution.

Performance optimizations (v1.1.0):
- Early termination after finding imports (don't parse tensor data)
- Don't count all REDUCE opcodes - just detect presence
- Avoid double-scanning same pickle data in archives
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

    # Check for code execution opcodes using streaming parser
    # This scans ALL opcodes while skipping binary data for performance
    dangerous_ops = get_dangerous_opcodes(data, full_scan=False)

    # For performance, we don't count all REDUCE opcodes - just detect their presence
    # The count doesn't matter for security - what matters is dangerous imports + execution
    has_reduce = False
    has_other_dangerous = False
    unknown_opcodes: list[tuple[int, str]] = []

    for op in dangerous_ops:
        if op.name == "REDUCE":
            has_reduce = True
        elif op.name == "UNKNOWN":
            # Track unknown opcodes - potential evasion technique
            unknown_opcodes.append((op.pos, op.arg or ""))
        elif op.name in ("INST", "OBJ", "NEWOBJ", "NEWOBJ_EX"):
            has_other_dangerous = True
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message=f"Object creation opcode: {op.name}",
                    location=op.pos,
                    details={"opcode": op.name},
                )
            )
        elif op.name == "BUILD":
            has_other_dangerous = True
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message="BUILD opcode found (may trigger __setstate__)",
                    location=op.pos,
                    details={"opcode": op.name},
                )
            )

    # Report unknown opcodes (potential evasion technique)
    if unknown_opcodes:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=f"Unknown pickle opcodes found ({len(unknown_opcodes)} occurrences)",
                location=unknown_opcodes[0][0],
                details={
                    "opcode": "UNKNOWN",
                    "unknown_count": len(unknown_opcodes),
                    "first_unknown": unknown_opcodes[0][1],
                    "warning": "Unknown opcodes may indicate evasion attempt or newer pickle version",
                },
            )
        )

    # Report REDUCE opcodes (function calls)
    # Only flag as high severity if we also found dangerous imports
    has_dangerous_imports = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH) and f.details and "module" in f.details
        for f in findings
    )

    if has_reduce:
        severity = Severity.HIGH if has_dangerous_imports else Severity.MEDIUM
        findings.append(
            Finding(
                severity=severity,
                message="REDUCE opcode found (function calls present)",
                location=None,
                details={"opcode": "REDUCE", "has_reduce": True},
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


def scan_pickle_file(filepath: Path, data: bytes | None = None) -> list[Finding]:
    """Scan a pickle file for security issues.

    Handles both raw pickle files and PyTorch ZIP archives containing pickles.
    Also detects archive-based bypass techniques (CVE-2025-1889).

    Args:
        filepath: Path to pickle file
        data: Optional pre-loaded file data (avoids re-reading)

    Returns:
        List of security findings
    """
    from tensortrap.formats.pytorch_zip import scan_7z_for_pickle

    findings = []
    filepath = Path(filepath)

    # Read file data once if not provided
    if data is None:
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

    # Check for 7z archive (nullifAI bypass - CVE-2025-1716)
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message="7z archive detected - potential nullifAI bypass (CVE-2025-1716)",
                location=0,
                details={"format": "7z", "cve": "CVE-2025-1716"},
            )
        )

        # Scan 7z for embedded pickle data (pass data to avoid re-read)
        scan_result = scan_7z_for_pickle(filepath, data=data)
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

        return findings

    # Check if this is a PyTorch ZIP archive
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        findings.extend(_scan_pytorch_archive(filepath, data=data))
        return findings

    # Handle raw pickle file
    return scan_pickle(data, filepath)


def _scan_pytorch_archive(filepath: Path, data: bytes | None = None) -> list[Finding]:
    """Scan a PyTorch ZIP archive for security issues.

    Also checks for trailing data after the ZIP archive (CVE-2025-1889 bypass)
    and zeroed CRC attacks (CVE-2025-10156 bypass).

    Performance optimization: Only scan each pickle file once, using raw
    extraction which is faster than zipfile.ZipFile for large archives.

    Args:
        filepath: Path to PyTorch .pt/.pth file
        data: Optional pre-loaded file data (avoids re-reading)

    Returns:
        List of findings from internal pickle files
    """
    from tensortrap.formats.pytorch_zip import (
        analyze_zip_structure,
        check_zip_trailing_data,
        scan_zip_raw_for_pickle,
    )

    findings = []
    scanned_files: set[str] = set()  # Track which files we've scanned

    # Use provided data or read file once
    if data is None:
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
    file_data = data

    # CVE-2025-10156: Scan raw ZIP structure for zeroed CRCs
    # This is faster than zipfile.ZipFile and works with corrupted CRCs
    raw_scan = scan_zip_raw_for_pickle(filepath, data=file_data)

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

    # Scan pickle files found via raw extraction (faster, single pass)
    if raw_scan["contains_pickle"]:
        for fname, offset in zip(raw_scan["pickle_files_found"], raw_scan["pickle_offsets"]):
            # SECURITY FIX: Pass full data from offset, not just first 10MB
            # The streaming parser efficiently skips binary data but must see
            # all opcodes to detect malicious code hidden after large data blocks
            pickle_data = file_data[offset:]
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
            scanned_files.add(fname)

    # Analyze ZIP structure for metadata (quick operation)
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
    trailing_info = check_zip_trailing_data(filepath, data=file_data)
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

            # Extract and scan the trailing pickle from file_data directly
            # SECURITY FIX: Don't truncate - streaming parser handles large data efficiently
            pickle_offset = trailing_info["pickle_offset"]
            if pickle_offset is not None and pickle_offset < len(file_data):
                trailing_pickle = file_data[pickle_offset:]
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

    # SECURITY FIX: Also scan via Central Directory to catch files that may differ
    # from Local Headers (CVE-style attack where CD points to different content)
    # Only scan files NOT already covered by raw extraction to avoid double-scanning
    from tensortrap.formats.pytorch_zip import extract_pickle_files

    try:
        cd_pickle_files = extract_pickle_files(filepath)
        for fname, pickle_data in cd_pickle_files:
            # Skip if already scanned via raw extraction
            if fname in scanned_files:
                continue

            # This file was only visible via Central Directory
            # This is NORMAL for compressed ZIP files (raw scan only finds uncompressed)
            # Only flag as suspicious if raw scan found OTHER pickle files (suggesting evasion)
            if raw_scan["contains_pickle"]:
                # Raw scan found some pickles but not this one - suspicious
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        message=f"Pickle file found only in Central Directory: {fname}",
                        location=None,
                        details={
                            "technique": "cd_only_file",
                            "filename": fname,
                            "warning": "File not in Local Headers but others were - possible evasion",
                        },
                    )
                )
            # else: Normal - ZIP is compressed, raw scan couldn't see pickle signatures

            pickle_findings = scan_pickle(pickle_data, filepath)
            for pf in pickle_findings:
                if pf.details is None:
                    pf.details = {}
                pf.details["source"] = "central_directory_extraction"
                pf.details["filename"] = fname
            findings.extend(pickle_findings)
            scanned_files.add(fname)
    except Exception:
        # If Central Directory extraction fails, continue with what we have
        pass

    return findings
