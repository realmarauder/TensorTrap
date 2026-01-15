"""Main scanning engine that orchestrates format-specific scanners.

Features:
- Streaming pickle parser (skips binary data, scans all control opcodes)
- Context analysis (entropy, AI metadata, structure validation)
- External validation (exiftool, binwalk - optional)
- Hash computation (disabled by default for performance)
"""

import hashlib
import time
from collections.abc import Callable, Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tensortrap.formats.magic import detect_format as detect_by_magic
from tensortrap.scanner.comfyui_scanner import scan_comfyui_workflow
from tensortrap.scanner.gguf_scanner import scan_gguf
from tensortrap.scanner.keras_scanner import scan_keras_file
from tensortrap.scanner.obfuscation import scan_for_obfuscation
from tensortrap.scanner.onnx_scanner import scan_onnx_file
from tensortrap.scanner.pickle_scanner import scan_pickle_file, scan_pickle
from tensortrap.scanner.polyglot_scanner import (
    scan_polyglot_from_bytes,
    scan_polyglot_with_context_from_bytes,
)
from tensortrap.scanner.recommendations import add_recommendations
from tensortrap.scanner.results import Finding, ScanResult, Severity
from tensortrap.scanner.safetensors_scanner import scan_safetensors
from tensortrap.scanner.yaml_scanner import scan_yaml_file
from tensortrap.signatures.patterns import FORMAT_EXTENSIONS, detect_format


# Chunk size for hash computation
CHUNK_SIZE = 64 * 1024  # 64KB chunks for hashing


@dataclass
class ScanOptions:
    """Configuration options for scanning."""
    compute_hash: bool = False  # Disabled by default for performance
    use_context_analysis: bool = True
    use_external_validation: bool = False
    confidence_threshold: float = 0.5
    entropy_threshold: float = 7.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "compute_hash": self.compute_hash,
            "use_context_analysis": self.use_context_analysis,
            "use_external_validation": self.use_external_validation,
            "confidence_threshold": self.confidence_threshold,
            "entropy_threshold": self.entropy_threshold,
        }


class FileDataCache:
    """Simple cache for file data to avoid multiple reads within a scan."""

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self._data: bytes | None = None

    def get_data(self) -> bytes:
        """Get file data, caching on first read."""
        if self._data is None:
            with open(self.filepath, "rb") as f:
                self._data = f.read()
        return self._data

    def get_chunk(self, start: int, size: int) -> bytes:
        """Get a chunk of file data."""
        data = self.get_data()
        return data[start:start + size]

    def close(self):
        """Release cached data."""
        self._data = None


def scan_file(
    filepath: Path,
    compute_hash: bool = False,
    use_context_analysis: bool = True,
    use_external_validation: bool = False,
    confidence_threshold: float = 0.5,
    entropy_threshold: float = 7.0,
) -> ScanResult:
    """Scan a single file for security issues.

    Args:
        filepath: Path to file to scan
        compute_hash: Whether to compute SHA-256 hash (default: False for performance)
        use_context_analysis: Whether to run context analysis on findings
        use_external_validation: Whether to run external tool validation
        confidence_threshold: Minimum confidence to report as actionable
        entropy_threshold: Entropy threshold for compressed region detection

    Returns:
        ScanResult with findings
    """
    filepath = Path(filepath)
    start_time = time.perf_counter()

    # Build scan options
    options = ScanOptions(
        compute_hash=compute_hash,
        use_context_analysis=use_context_analysis,
        use_external_validation=use_external_validation,
        confidence_threshold=confidence_threshold,
        entropy_threshold=entropy_threshold,
    )

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

    # Initialize file data cache
    cache = FileDataCache(filepath)

    try:
        # Compute hash if requested (using chunked reading)
        file_hash = ""
        if compute_hash:
            file_hash = _compute_sha256_chunked(filepath)

        # Run appropriate scanner with cached data
        findings = _scan_by_format_optimized(filepath, file_format, options, cache)

        # Run external validation if enabled
        if use_external_validation and findings:
            findings = _apply_external_validation(filepath, findings)

    finally:
        cache.close()

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


def _scan_by_format_optimized(
    filepath: Path,
    file_format: str,
    options: ScanOptions,
    cache: FileDataCache,
) -> list[Finding]:
    """Run the appropriate scanner for a file format.

    Args:
        filepath: Path to file
        file_format: Detected format
        options: Scan options
        cache: File data cache

    Returns:
        List of findings
    """
    findings: list[Finding] = []
    use_context = options.use_context_analysis
    entropy_threshold = options.entropy_threshold

    # Format-specific scanning
    if file_format == "pickle":
        findings.extend(scan_pickle_file(filepath, data=cache.get_data()))
    elif file_format == "archive":
        findings.extend(_scan_archive_format(filepath, cache=cache))
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
        findings.extend(scan_comfyui_workflow(filepath))
    elif file_format in ("image", "video", "svg"):
        # Media files - run polyglot scanner (can hide malicious content)
        file_data = cache.get_data()
        if use_context:
            findings.extend(
                scan_polyglot_with_context_from_bytes(
                    file_data,
                    filepath,
                    use_context_analysis=True,
                    entropy_threshold=entropy_threshold,
                )
            )
        else:
            findings.extend(scan_polyglot_from_bytes(file_data, filepath))
    elif file_format == "unknown":
        findings.extend(_scan_unknown_format(filepath, cache=cache))
    else:
        findings.append(
            Finding(
                severity=Severity.INFO,
                message=f"Unknown format: {file_format}",
                location=None,
            )
        )

    # Defense-in-depth: Run polyglot detection on ALL files
    # This catches disguised files regardless of extension
    if file_format not in ("image", "video", "svg"):
        file_data = cache.get_data()
        if use_context:
            polyglot_findings = scan_polyglot_with_context_from_bytes(
                file_data,
                filepath,
                use_context_analysis=True,
                entropy_threshold=entropy_threshold,
            )
        else:
            polyglot_findings = scan_polyglot_from_bytes(file_data, filepath)
        findings.extend(polyglot_findings)

    # Run obfuscation detection on high-risk formats
    if file_format in ("pickle", "onnx", "keras", "unknown"):
        file_data = cache.get_data()
        # Only scan first 1MB for obfuscation (performance)
        obfuscation_findings = scan_for_obfuscation(file_data[:1024 * 1024])
        findings.extend(obfuscation_findings)

    # Add remediation recommendations to all findings
    add_recommendations(findings)

    return findings


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
    compute_hash: bool = False,
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
    compute_hash: bool = False,
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


def _scan_unknown_format(filepath: Path, cache: FileDataCache | None = None) -> list[Finding]:
    """Attempt to scan a file with unknown extension by checking magic bytes.

    This is critical for detecting CVE-2025-1889 where malicious pickle
    files are hidden behind non-standard extensions.

    Args:
        filepath: Path to file
        cache: Optional file data cache

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

        # Get cached data if available
        file_data = cache.get_data() if cache else None

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
            findings.extend(scan_pickle_file(filepath, data=file_data))
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
            findings.extend(scan_pickle_file(filepath, data=file_data))
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


def _scan_archive_format(filepath: Path, cache: FileDataCache | None = None) -> list[Finding]:
    """Scan archive files (ZIP, 7z) for embedded pickle data.

    Handles CVE-2025-1889 style bypass attacks where pickle data
    is hidden inside or appended to archive files.

    Args:
        filepath: Path to archive file
        cache: Optional file data cache

    Returns:
        List of findings
    """
    from tensortrap.formats.pytorch_zip import (
        check_zip_trailing_data,
        scan_7z_for_pickle,
        scan_zip_raw_for_pickle,
    )

    findings: list[Finding] = []
    ext = filepath.suffix.lower()

    # Get file data once (from cache or read)
    if cache:
        file_data = cache.get_data()
    else:
        try:
            with open(filepath, "rb") as f:
                file_data = f.read()
        except OSError:
            return findings

    # Handle 7z archives (check magic bytes directly)
    if ext == ".7z" or file_data.startswith(b"7z\xbc\xaf\x27\x1c"):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message="7z archive detected - scanning for embedded pickle (CVE-2025-1716)",
                location=0,
                details={"format": "7z", "cve": "CVE-2025-1716"},
            )
        )

        # Scan 7z for embedded pickle data (pass data to avoid re-read)
        scan_result = scan_7z_for_pickle(filepath, data=file_data)
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

            # Scan the pickle content
            if offsets:
                pickle_data = file_data[offsets[0] :]
                pickle_findings = scan_pickle(pickle_data, filepath)
                for pf in pickle_findings:
                    if pf.details is None:
                        pf.details = {}
                    pf.details["source"] = "7z_embedded_pickle"
                    pf.details["base_offset"] = offsets[0]
                findings.extend(pickle_findings)

        return findings

    # Handle ZIP archives (check magic bytes directly)
    if ext == ".zip" or file_data.startswith(b"PK\x03\x04") or file_data.startswith(b"PK\x05\x06"):
        # CVE-2025-10156: Scan raw ZIP structure for zeroed CRCs (pass data)
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

        if raw_scan["contains_pickle"]:
            # Scan the pickle content from raw offsets
            for fname, offset in zip(
                raw_scan["pickle_files_found"], raw_scan["pickle_offsets"]
            ):
                pickle_data = file_data[offset:]
                pickle_findings = scan_pickle(pickle_data, filepath)

                # Add metadata to pickle findings
                for pf in pickle_findings:
                    if pf.details is None:
                        pf.details = {}
                    pf.details["source"] = "zip_raw_extraction"
                    pf.details["base_offset"] = offset
                    pf.details["filename"] = fname
                    if raw_scan["has_zeroed_crc"] and fname in raw_scan.get(
                        "zeroed_crc_files", []
                    ):
                        pf.details["zeroed_crc"] = True
                        pf.details["cve"] = "CVE-2025-10156"
                findings.extend(pickle_findings)

        # Check for trailing data (CVE-2025-1889 bypass) - pass data
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
                # Trailing data but not pickle
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

        # Also scan internal pickle files (via standard zipfile) - pass data
        internal_findings = scan_pickle_file(filepath, data=file_data)
        findings.extend(internal_findings)

        return findings

    # Unknown archive format
    findings.append(
        Finding(
            severity=Severity.INFO,
            message=f"Unknown archive format: {ext}",
            location=None,
            details={"extension": ext},
        )
    )

    return findings


def _compute_sha256_chunked(filepath: Path) -> str:
    """Compute SHA-256 hash of a file.

    Args:
        filepath: Path to file

    Returns:
        Hex-encoded SHA-256 hash
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
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
