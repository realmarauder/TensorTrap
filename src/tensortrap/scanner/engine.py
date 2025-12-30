"""Main scanning engine that orchestrates format-specific scanners.

Enhanced with multi-tier context analysis (v0.3.0):
- Tier 2: Context Analysis (entropy, AI metadata, structure validation)
- Tier 3: External Validation (exiftool, binwalk - optional)
"""

import hashlib
import time
from collections.abc import Callable, Generator
from pathlib import Path
from typing import Any

from tensortrap.formats.magic import detect_format as detect_by_magic
from tensortrap.scanner.comfyui_scanner import scan_comfyui_workflow
from tensortrap.scanner.gguf_scanner import scan_gguf
from tensortrap.scanner.keras_scanner import scan_keras_file
from tensortrap.scanner.obfuscation import scan_for_obfuscation
from tensortrap.scanner.onnx_scanner import scan_onnx_file
from tensortrap.scanner.pickle_scanner import scan_pickle_file
from tensortrap.scanner.polyglot_scanner import (
    scan_polyglot,
    scan_polyglot_with_context,
)
from tensortrap.scanner.recommendations import add_recommendations
from tensortrap.scanner.results import Finding, ScanResult, Severity
from tensortrap.scanner.safetensors_scanner import scan_safetensors
from tensortrap.scanner.yaml_scanner import scan_yaml_file
from tensortrap.signatures.patterns import FORMAT_EXTENSIONS, detect_format


def scan_file(
    filepath: Path,
    compute_hash: bool = True,
    use_context_analysis: bool = True,
    use_external_validation: bool = False,
    confidence_threshold: float = 0.5,
    entropy_threshold: float = 7.0,
) -> ScanResult:
    """Scan a single file for security issues.

    Args:
        filepath: Path to file to scan
        compute_hash: Whether to compute SHA-256 hash
        use_context_analysis: Whether to run context analysis on findings
        use_external_validation: Whether to run external tool validation
        confidence_threshold: Minimum confidence to report as actionable
        entropy_threshold: Entropy threshold for compressed region detection

    Returns:
        ScanResult with findings
    """
    filepath = Path(filepath)
    start_time = time.perf_counter()

    # Build scan options for internal use
    scan_options: dict[str, Any] = {
        "use_context_analysis": use_context_analysis,
        "use_external_validation": use_external_validation,
        "confidence_threshold": confidence_threshold,
        "entropy_threshold": entropy_threshold,
    }

    # Check file exists
    if not filepath.exists():
        return ScanResult(
            filepath=filepath,
            format="unknown",
            findings=[
                Finding(
                    severity=Severity.MEDIUM,
                    message=f"File not found: {filepath}",
                    location=None,
                )
            ],
        )

    if not filepath.is_file():
        return ScanResult(
            filepath=filepath,
            format="unknown",
            findings=[
                Finding(
                    severity=Severity.MEDIUM,
                    message=f"Not a file: {filepath}",
                    location=None,
                )
            ],
        )

    # Get file info
    try:
        file_size = filepath.stat().st_size
    except OSError as e:
        return ScanResult(
            filepath=filepath,
            format="unknown",
            findings=[
                Finding(
                    severity=Severity.MEDIUM,
                    message=f"Cannot access file: {e}",
                    location=None,
                )
            ],
        )

    # Detect format
    file_format = detect_format(filepath)

    # Compute hash if requested
    file_hash = ""
    if compute_hash:
        file_hash = _compute_sha256(filepath)

    # Run appropriate scanner
    findings = _scan_by_format(filepath, file_format, scan_options)

    # Run external validation if enabled
    if use_external_validation and findings:
        findings = _apply_external_validation(filepath, findings)

    # Calculate scan time
    scan_time_ms = (time.perf_counter() - start_time) * 1000

    return ScanResult(
        filepath=filepath,
        format=file_format,
        findings=findings,
        scan_time_ms=scan_time_ms,
        file_size=file_size,
        file_hash=file_hash,
    )


def collect_files(
    dirpath: Path,
    recursive: bool = True,
    extensions: set[str] | None = None,
) -> list[Path]:
    """Collect all model files in a directory without scanning.

    Args:
        dirpath: Directory to search
        recursive: Whether to search subdirectories
        extensions: File extensions to collect (default: all known formats)

    Returns:
        List of file paths
    """
    dirpath = Path(dirpath)

    if not dirpath.exists() or not dirpath.is_dir():
        return []

    # Default to all known extensions
    if extensions is None:
        extensions = set(FORMAT_EXTENSIONS.keys())

    # Find matching files
    files = []
    pattern = "**/*" if recursive else "*"

    for ext in extensions:
        for filepath in dirpath.glob(f"{pattern}{ext}"):
            if filepath.is_file():
                files.append(filepath)

    return files


def scan_files_with_progress(
    files: list[Path],
    compute_hash: bool = True,
    progress_callback: Callable[[Path, int, int], None] | None = None,
    use_context_analysis: bool = True,
    use_external_validation: bool = False,
    confidence_threshold: float = 0.5,
    entropy_threshold: float = 7.0,
) -> Generator[ScanResult, None, None]:
    """Scan files one at a time, yielding results for progress tracking.

    Args:
        files: List of file paths to scan
        compute_hash: Whether to compute SHA-256 hash
        progress_callback: Optional callback(filepath, current, total) for progress
        use_context_analysis: Whether to run context analysis on findings
        use_external_validation: Whether to run external tool validation
        confidence_threshold: Minimum confidence to report as actionable
        entropy_threshold: Entropy threshold for compressed region detection

    Yields:
        ScanResult for each file
    """
    total = len(files)
    for i, filepath in enumerate(files):
        if progress_callback:
            progress_callback(filepath, i + 1, total)
        yield scan_file(
            filepath,
            compute_hash=compute_hash,
            use_context_analysis=use_context_analysis,
            use_external_validation=use_external_validation,
            confidence_threshold=confidence_threshold,
            entropy_threshold=entropy_threshold,
        )


def scan_directory(
    dirpath: Path,
    recursive: bool = True,
    extensions: set[str] | None = None,
    compute_hash: bool = True,
) -> list[ScanResult]:
    """Scan all model files in a directory.

    Args:
        dirpath: Directory to scan
        recursive: Whether to scan subdirectories
        extensions: File extensions to scan (default: all known formats)
        compute_hash: Whether to compute SHA-256 hash

    Returns:
        List of ScanResult for each file
    """
    dirpath = Path(dirpath)

    if not dirpath.exists():
        return [
            ScanResult(
                filepath=dirpath,
                format="unknown",
                findings=[
                    Finding(
                        severity=Severity.MEDIUM,
                        message=f"Directory not found: {dirpath}",
                        location=None,
                    )
                ],
            )
        ]

    if not dirpath.is_dir():
        return [
            ScanResult(
                filepath=dirpath,
                format="unknown",
                findings=[
                    Finding(
                        severity=Severity.MEDIUM,
                        message=f"Not a directory: {dirpath}",
                        location=None,
                    )
                ],
            )
        ]

    # Collect and scan files
    files = collect_files(dirpath, recursive=recursive, extensions=extensions)
    return list(scan_files_with_progress(files, compute_hash=compute_hash))


def _scan_by_format(
    filepath: Path,
    file_format: str,
    scan_options: dict[str, Any] | None = None,
) -> list[Finding]:
    """Run the appropriate scanner for a file format.

    Args:
        filepath: Path to file
        file_format: Detected format
        scan_options: Context analysis options

    Returns:
        List of findings
    """
    findings: list[Finding] = []
    options = scan_options or {}
    use_context = options.get("use_context_analysis", True)
    entropy_threshold = options.get("entropy_threshold", 7.0)

    if file_format == "pickle":
        findings.extend(scan_pickle_file(filepath))
    elif file_format == "safetensors":
        findings.extend(scan_safetensors(filepath))
    elif file_format == "gguf":
        findings.extend(scan_gguf(filepath))
    elif file_format == "onnx":
        findings.extend(scan_onnx_file(filepath))
    elif file_format == "keras":
        findings.extend(scan_keras_file(filepath))
    elif file_format == "yaml":
        findings.extend(scan_yaml_file(filepath))
    elif file_format == "json":
        # JSON files might be ComfyUI workflows
        findings.extend(scan_comfyui_workflow(filepath))
    elif file_format in ("image", "video", "svg"):
        # Media files - run polyglot scanner with context analysis
        if use_context:
            findings.extend(
                scan_polyglot_with_context(
                    filepath,
                    use_context_analysis=True,
                    entropy_threshold=entropy_threshold,
                )
            )
        else:
            findings.extend(scan_polyglot(filepath))
    elif file_format == "unknown":
        # Try to detect format from file contents
        findings.extend(_scan_unknown_format(filepath))
    else:
        findings.append(
            Finding(
                severity=Severity.INFO,
                message=f"Unknown format: {file_format}",
                location=None,
            )
        )

    # Run polyglot detection on ALL files (Defense-in-Depth)
    # This catches disguised files regardless of extension
    if file_format not in ("image", "video", "svg"):
        if use_context:
            polyglot_findings = scan_polyglot_with_context(
                filepath,
                use_context_analysis=True,
                entropy_threshold=entropy_threshold,
            )
        else:
            polyglot_findings = scan_polyglot(filepath)
        findings.extend(polyglot_findings)

    # Run obfuscation detection on high-risk formats
    if file_format in ("pickle", "onnx", "keras", "unknown"):
        try:
            with open(filepath, "rb") as f:
                data = f.read(1024 * 1024)  # Read first 1MB for obfuscation check
            obfuscation_findings = scan_for_obfuscation(data)
            findings.extend(obfuscation_findings)
        except OSError:
            pass

    # Add remediation recommendations to all findings
    add_recommendations(findings)

    return findings


def _scan_unknown_format(filepath: Path) -> list[Finding]:
    """Attempt to scan a file with unknown extension by checking magic bytes.

    This is critical for detecting CVE-2025-1889 where malicious pickle
    files are hidden behind non-standard extensions.

    Args:
        filepath: Path to file

    Returns:
        List of findings
    """
    findings = []

    # Use comprehensive magic byte detection
    try:
        magic_result = detect_by_magic(filepath)
    except Exception:
        magic_result = None

    if magic_result:
        detected_format = magic_result.format
        confidence = magic_result.confidence
        details = magic_result.details or {}

        # Check for 7z archive (nullifAI bypass - CVE-2025-1716)
        if detected_format == "7z_archive":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    message="7z archive detected - potential nullifAI bypass (CVE-2025-1716)",
                    location=0,
                    details={"format": "7z", "cve": "CVE-2025-1716"},
                )
            )
            return findings

        # Route to appropriate scanner based on magic detection
        if detected_format == "pickle" and confidence in ("high", "medium"):
            protocol = details.get("protocol", "unknown")
            msg = f"Pickle format detected by magic bytes (protocol {protocol})"
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message=f"{msg} - non-standard extension",
                    location=0,
                    details={"detected_by": "magic_bytes", "cve": "CVE-2025-1889"},
                )
            )
            findings.extend(scan_pickle_file(filepath))
            return findings

        elif detected_format in ("zip", "pytorch") and confidence in ("high", "medium"):
            # Could be PyTorch archive
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    message="ZIP archive detected - may contain pickle files",
                    location=0,
                )
            )
            findings.extend(scan_pickle_file(filepath))
            return findings

        elif detected_format == "gguf" and confidence in ("high", "medium"):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    message="GGUF format detected by magic bytes",
                    location=0,
                )
            )
            findings.extend(scan_gguf(filepath))
            return findings

        elif detected_format == "keras" and confidence in ("high", "medium"):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    message="HDF5/Keras format detected by magic bytes",
                    location=0,
                )
            )
            findings.extend(scan_keras_file(filepath))
            return findings

        elif detected_format == "onnx" and confidence in ("high", "medium"):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    message="ONNX format detected by magic bytes",
                    location=0,
                )
            )
            findings.extend(scan_onnx_file(filepath))
            return findings

    # Couldn't identify format
    findings.append(
        Finding(
            severity=Severity.INFO,
            message="Unknown file format - could not detect from extension or magic bytes",
            location=None,
        )
    )

    return findings


def _compute_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        filepath: Path to file

    Returns:
        Hex-encoded SHA-256 hash
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except OSError:
        return ""


def _apply_external_validation(
    filepath: Path,
    findings: list[Finding],
) -> list[Finding]:
    """Apply external tool validation to findings.

    Uses exiftool and binwalk (if available) to validate MEDIUM and HIGH
    confidence findings. May downgrade severity if tools don't confirm threat.

    Args:
        filepath: Path to file being scanned
        findings: List of findings to validate

    Returns:
        Updated findings with external_validation info in details
    """
    # Lazy import to avoid circular dependencies
    from tensortrap.scanner.external_validators import ExternalValidationRunner

    runner = ExternalValidationRunner(enabled=True)

    # Check tool availability
    tools = runner.get_available_tools()
    if not any(tools.values()):
        # No external tools available, return findings unchanged
        return findings

    validated_findings: list[Finding] = []

    for finding in findings:
        # Only validate findings that have context analysis
        if not finding.details or "context_analysis" not in finding.details:
            validated_findings.append(finding)
            continue

        ctx = finding.details.get("context_analysis", {})
        confidence_level = ctx.get("confidence_level", "LOW")

        # Only validate MEDIUM and HIGH confidence
        if confidence_level not in ("MEDIUM", "HIGH"):
            validated_findings.append(finding)
            continue

        # Get pattern name
        pattern_name = finding.details.get("technique", "")
        if not pattern_name:
            pattern_name = finding.message[:50]

        # Run external validation
        result = runner.validate_finding(
            filepath=filepath,
            pattern_name=pattern_name,
            confidence_level=confidence_level,
            offset=finding.location,
        )

        if result:
            # Add external validation to details
            updated_details = dict(finding.details)
            updated_details["external_validation"] = result.to_dict()

            # Downgrade if external tool doesn't confirm
            if result.status.value == "not_confirmed":
                if "adjusted_severity" in updated_details:
                    orig = updated_details["adjusted_severity"]
                    updated_details["adjusted_severity"] = orig.replace("-HIGH", "-LOW").replace(
                        "-MEDIUM", "-LOW"
                    )
                    updated_details["external_override"] = True

            validated_finding = Finding(
                severity=finding.severity,
                message=finding.message,
                location=finding.location,
                details=updated_details,
                recommendation=finding.recommendation,
            )
            validated_findings.append(validated_finding)
        else:
            validated_findings.append(finding)

    return validated_findings
