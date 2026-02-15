"""Polyglot and disguised file detection.

Detects files that masquerade as one format while containing another,
a common technique for bypassing security scanners.

This module implements Defense-in-Depth (DiD) scanning for:
- Extension vs magic byte mismatches (CVE-2025-1889)
- Archive-in-image attacks (ZIP/7z appended to valid images)
- Archive-in-video attacks
- Pickle data embedded in media files
- SVG script injection (JavaScript, event handlers)
- Metadata payloads (code in EXIF/XMP)
- Double extension tricks (model.pkl.png)
- Trailing data after image end markers

Enhanced with multi-tier context analysis (v0.3.0):
- Entropy analysis for compressed region detection
- Archive structure validation
- AI metadata detection (ComfyUI, Stable Diffusion, Topaz)
- Confidence scoring: CRITICAL-HIGH/MEDIUM/LOW
"""

import re
from pathlib import Path
from typing import Any

from tensortrap.scanner.results import Finding, Severity

# Magic bytes for common image formats
IMAGE_SIGNATURES = {
    "png": b"\x89PNG\r\n\x1a\n",
    "jpeg": b"\xff\xd8\xff",
    "gif87": b"GIF87a",
    "gif89": b"GIF89a",
    "webp": b"RIFF",  # + "WEBP" at offset 8
    "bmp": b"BM",
    "tiff_le": b"II\x2a\x00",  # Little-endian
    "tiff_be": b"MM\x00\x2a",  # Big-endian
    "ico": b"\x00\x00\x01\x00",
}

# Video format signatures
VIDEO_SIGNATURES = {
    "mp4": b"ftyp",  # At offset 4
    "webm": b"\x1a\x45\xdf\xa3",  # EBML header
    "mkv": b"\x1a\x45\xdf\xa3",  # EBML header (same as webm)
    "avi": b"RIFF",  # + "AVI " at offset 8
    "flv": b"FLV\x01",
    "wmv": b"\x30\x26\xb2\x75",  # ASF header
}

# Archive signatures with sufficient length to avoid false positives
# NOTE: GZIP (0x1f8b) and BZIP2 (BZ) are excluded - only 2 bytes, too many
# false positives in compressed media data (video codecs, JPEG data, etc.)
ARCHIVE_SIGNATURES = {
    "zip": b"PK\x03\x04",
    "zip_empty": b"PK\x05\x06",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "rar": b"Rar!\x1a\x07",
    "rar5": b"Rar!\x1a\x07\x01\x00",
    "xz": b"\xfd7zXZ\x00",
}

# Pickle protocol markers - only 2 bytes, so we validate that they're
# followed by valid pickle opcodes to avoid false positives in random data
PICKLE_SIGNATURES = [
    b"\x80\x02",  # Protocol 2
    b"\x80\x03",  # Protocol 3
    b"\x80\x04",  # Protocol 4
    b"\x80\x05",  # Protocol 5
]

# Image extensions to scan for polyglot attacks
IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg",
    ".tiff", ".tif", ".ico", ".avif", ".heic", ".heif",
}

# Video extensions to scan for polyglot attacks
VIDEO_EXTENSIONS = {
    ".mp4", ".webm", ".avi", ".mov", ".mkv", ".m4v",
    ".flv", ".wmv", ".ogv", ".3gp", ".ts", ".mts", ".m2ts",
}

# Document extensions to scan for polyglot attacks
DOCUMENT_EXTENSIONS = {".pdf"}

# Combined media extensions
MEDIA_EXTENSIONS = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS | DOCUMENT_EXTENSIONS


def _is_valid_pickle(data: bytes, pos: int) -> bool:
    """Validate that a pickle signature is followed by valid opcodes."""
    if pos + 2 >= len(data):
        return False

    protocol = data[pos + 1]
    next_byte = data[pos + 2]

    # Protocol 4 and 5: Expect FRAME opcode (0x95) with valid structure
    if protocol >= 4:
        if next_byte != 0x95:
            return False
        if pos + 11 >= len(data):
            return False
        frame_len = int.from_bytes(data[pos + 3 : pos + 11], "little")
        if frame_len < 1 or frame_len > 100_000_000:
            return False
        if pos + 11 < len(data):
            opcode_after_frame = data[pos + 11]
            if opcode_after_frame not in {0x63, 0x7D, 0x5D, 0x29, 0x28, 0x8C, 0x89, 0x81}:
                return False
        return True

    # Protocol 2 and 3: Only accept GLOBAL opcode with proper structure
    if protocol in (2, 3):
        if next_byte != 0x63:
            return False
        if pos + 10 >= len(data):
            return False
        found_newline = False
        for i in range(pos + 3, min(pos + 258, len(data))):
            b = data[i]
            if b == 0x0A:
                found_newline = True
                break
            if not (0x2E <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x5F == b or 0x61 <= b <= 0x7A):
                return False
        return found_newline

    return False


# =============================================================================
# Core scanning functions (bytes-based)
# =============================================================================

def scan_polyglot_from_bytes(data: bytes, filepath: Path) -> list[Finding]:
    """Scan file data for polyglot/disguised threats.

    Args:
        data: File content as bytes
        filepath: Path to file (for extension detection and messages)

    Returns:
        List of findings
    """
    findings: list[Finding] = []
    filepath = Path(filepath)
    ext = filepath.suffix.lower()

    # Check for double extensions (no file read needed)
    findings.extend(_check_double_extension(filepath))

    # Check extension vs magic byte mismatch
    findings.extend(_check_extension_mismatch(data, filepath))

    # For image files, check for appended archives
    if ext in IMAGE_EXTENSIONS:
        findings.extend(_check_archive_in_image(data, filepath))
        findings.extend(_check_trailing_data(data, filepath))

    # For video files, check for appended archives and embedded data
    if ext in VIDEO_EXTENSIONS:
        findings.extend(_check_archive_in_video(data, filepath))
        findings.extend(_check_video_metadata(data, filepath))

    # For PDF files, check for appended data
    if ext in DOCUMENT_EXTENSIONS:
        findings.extend(_check_trailing_data(data, filepath))

    # For SVG files, check for embedded scripts
    if ext == ".svg":
        findings.extend(_check_svg_scripts(data))

    # Check EXIF/XMP metadata for payloads
    if ext in {".jpg", ".jpeg", ".tiff", ".tif", ".png", ".webp"}:
        findings.extend(_check_metadata_payloads(data))

    return findings


def scan_polyglot(filepath: Path) -> list[Finding]:
    """Scan a file for polyglot/disguised threats.

    Args:
        filepath: Path to file to scan

    Returns:
        List of findings
    """
    filepath = Path(filepath)
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError:
        return []

    return scan_polyglot_from_bytes(data, filepath)


# =============================================================================
# Helper functions (all work with bytes)
# =============================================================================

def _check_double_extension(filepath: Path) -> list[Finding]:
    """Detect double extension tricks like 'model.pkl.png'."""
    findings: list[Finding] = []
    name = filepath.name.lower()

    dangerous_extensions = {
        ".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt",
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh",
        ".py", ".js", ".vbs", ".hta", ".scr", ".pif",
    }

    parts = name.split(".")
    if len(parts) > 2:
        inner_ext = "." + parts[-2]
        if inner_ext in dangerous_extensions:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message=f"Double extension detected: {name} (inner: {inner_ext})",
                    location=None,
                    details={
                        "technique": "double_extension",
                        "inner_extension": inner_ext,
                        "outer_extension": filepath.suffix,
                    },
                )
            )

    return findings


def _check_extension_mismatch(data: bytes, filepath: Path) -> list[Finding]:
    """Detect when file extension doesn't match magic bytes."""
    findings: list[Finding] = []
    ext = filepath.suffix.lower()

    if len(data) < 8:
        return findings

    header = data[:32]
    actual_format = None

    # Check for pickle (high priority - main threat)
    if len(header) >= 2 and header[0] == 0x80 and header[1] <= 5:
        actual_format = "pickle"

    # Check for archives
    if actual_format is None:
        for fmt, sig in ARCHIVE_SIGNATURES.items():
            if header.startswith(sig):
                actual_format = fmt
                break

    # Check for images
    if actual_format is None:
        if header.startswith(b"\x89PNG"):
            actual_format = "png"
        elif header.startswith(b"\xff\xd8\xff"):
            actual_format = "jpeg"
        elif header.startswith(b"GIF8"):
            actual_format = "gif"
        elif header.startswith(b"RIFF") and len(header) >= 12 and header[8:12] == b"WEBP":
            actual_format = "webp"

    # Report mismatches
    if actual_format == "pickle" and ext in MEDIA_EXTENSIONS:
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                message=f"Disguised pickle file: extension is {ext} but file is pickle format",
                location=0,
                details={
                    "technique": "extension_mismatch",
                    "claimed_format": ext,
                    "actual_format": "pickle",
                    "cve": "CVE-2025-1889",
                },
            )
        )
    elif actual_format in ("zip", "zip_empty", "7z", "rar", "rar5") and ext in MEDIA_EXTENSIONS:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message=f"Disguised archive: extension is {ext} but file is {actual_format} format",
                location=0,
                details={
                    "technique": "extension_mismatch",
                    "claimed_format": ext,
                    "actual_format": actual_format,
                },
            )
        )
    elif actual_format == "7z" and ext in {".pkl", ".pt", ".pth", ".bin", ".ckpt"}:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                message="7z archive with model extension (potential nullifAI bypass)",
                location=0,
                details={
                    "technique": "extension_mismatch",
                    "claimed_format": ext,
                    "actual_format": "7z",
                    "cve": "CVE-2025-1716",
                },
            )
        )

    return findings


def _check_archive_in_image(data: bytes, filepath: Path) -> list[Finding]:
    """Detect ZIP/7z/RAR archives appended to valid images."""
    findings: list[Finding] = []

    if len(data) < 16:
        return findings

    for archive_type, signature in ARCHIVE_SIGNATURES.items():
        pos = data.find(signature, 8)
        if pos > 0:
            atype = archive_type.upper()
            if archive_type in ("zip", "zip_empty"):
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        message=f"Archive embedded in image: {atype} at offset {pos}",
                        location=pos,
                        details={
                            "technique": "archive_in_image",
                            "archive_type": archive_type,
                            "archive_offset": pos,
                            "warning": "May contain malicious pickle files",
                        },
                    )
                )
            elif archive_type == "7z":
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        message=f"7z archive embedded in image at offset {pos} (CVE-2025-1716)",
                        location=pos,
                        details={
                            "technique": "archive_in_image",
                            "archive_type": "7z",
                            "archive_offset": pos,
                            "cve": "CVE-2025-1716",
                        },
                    )
                )
            elif archive_type in ("rar", "rar5"):
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        message=f"RAR archive embedded in image at offset {pos}",
                        location=pos,
                        details={
                            "technique": "archive_in_image",
                            "archive_type": archive_type,
                            "archive_offset": pos,
                        },
                    )
                )
            break

    # Check for pickle signatures after image data
    for pickle_sig in PICKLE_SIGNATURES:
        pos = data.find(pickle_sig, 8)
        if pos > 0 and _is_valid_pickle(data, pos):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    message=f"Pickle data embedded in image at offset {pos}",
                    location=pos,
                    details={
                        "technique": "pickle_in_image",
                        "pickle_offset": pos,
                        "protocol": pickle_sig[1],
                    },
                )
            )
            break

    return findings


def _check_trailing_data(data: bytes, filepath: Path) -> list[Finding]:
    """Check for unexpected data after valid image/document end marker."""
    findings: list[Finding] = []
    ext = filepath.suffix.lower()

    if len(data) < 16:
        return findings

    trailing_data_start = None

    # PNG: ends with IEND chunk
    if ext == ".png" and data.startswith(b"\x89PNG"):
        iend_pos = data.find(b"IEND")
        if iend_pos > 0:
            png_end = iend_pos + 12
            if png_end < len(data):
                trailing_data_start = png_end

    # JPEG: ends with FFD9
    elif ext in (".jpg", ".jpeg") and data.startswith(b"\xff\xd8"):
        eoi_pos = data.rfind(b"\xff\xd9")
        if eoi_pos > 0:
            jpeg_end = eoi_pos + 2
            if jpeg_end < len(data):
                trailing_data_start = jpeg_end

    # GIF: ends with trailer byte 0x3B
    elif ext == ".gif" and data.startswith(b"GIF8"):
        trailer_pos = data.rfind(b"\x3b")
        if trailer_pos > 0:
            gif_end = trailer_pos + 1
            if gif_end < len(data):
                trailing_data_start = gif_end

    # PDF: ends with %%EOF marker
    elif ext == ".pdf" and data.startswith(b"%PDF"):
        eof_pos = data.rfind(b"%%EOF")
        if eof_pos > 0:
            pdf_end = eof_pos + 5
            while pdf_end < len(data) and data[pdf_end : pdf_end + 1] in (b"\r", b"\n", b" "):
                pdf_end += 1
            if pdf_end < len(data):
                trailing_data_start = pdf_end

    if trailing_data_start and (len(data) - trailing_data_start) > 16:
        trailing_size = len(data) - trailing_data_start
        trailing_preview = data[trailing_data_start : trailing_data_start + 16]

        severity = Severity.MEDIUM
        details: dict = {
            "technique": "trailing_data",
            "trailing_offset": trailing_data_start,
            "trailing_size": trailing_size,
        }

        # Escalate if trailing data is archive or validated pickle
        for sig in PICKLE_SIGNATURES:
            if trailing_preview.startswith(sig) and _is_valid_pickle(data, trailing_data_start):
                severity = Severity.CRITICAL
                details["contains"] = "pickle"
                details["protocol"] = sig[1]
                break

        for archive_type, sig in ARCHIVE_SIGNATURES.items():
            if trailing_preview.startswith(sig):
                severity = Severity.CRITICAL
                details["contains"] = archive_type
                break

        findings.append(
            Finding(
                severity=severity,
                message=f"Trailing data after image end: {trailing_size} bytes",
                location=trailing_data_start,
                details=details,
            )
        )

    return findings


def _check_svg_scripts(data: bytes) -> list[Finding]:
    """Detect JavaScript and event handlers in SVG files."""
    findings: list[Finding] = []

    content = data[:1024 * 1024]  # First 1MB
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    dangerous_patterns = [
        (r"<script[^>]*>", "script_tag", Severity.CRITICAL),
        (r"on\w+\s*=", "event_handler", Severity.HIGH),
        (r"javascript:", "javascript_uri", Severity.CRITICAL),
        (r"data:text/html", "data_uri_html", Severity.HIGH),
        (r"<foreignObject", "foreign_object", Severity.MEDIUM),
        (r"xlink:href\s*=\s*[\"']javascript:", "xlink_javascript", Severity.CRITICAL),
        (r"set\s+attributeName.*on", "svg_animation_handler", Severity.HIGH),
        (r"<use[^>]+href\s*=\s*[\"']data:", "use_data_uri", Severity.HIGH),
    ]

    for pattern, technique, severity in dangerous_patterns:
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        if matches:
            preview = text[matches[0].start() : matches[0].start() + 50]
            if "\n" in preview:
                preview = preview[: preview.index("\n")]

            findings.append(
                Finding(
                    severity=severity,
                    message=f"SVG contains {technique}: {len(matches)} occurrence(s)",
                    location=matches[0].start(),
                    details={
                        "technique": f"svg_{technique}",
                        "occurrences": len(matches),
                        "preview": preview,
                    },
                )
            )

    return findings


def _check_metadata_payloads(data: bytes) -> list[Finding]:
    """Check image metadata (EXIF, XMP) for embedded code."""
    findings: list[Finding] = []

    metadata_region = data[:65536]  # First 64KB

    suspicious_patterns = [
        (rb"<\?php", "php_code", Severity.CRITICAL),
        (rb"<%\s*=", "asp_output", Severity.CRITICAL),
        (rb"<%\s+[a-zA-Z]", "asp_code", Severity.CRITICAL),
        (rb"eval\s*\(\s*[a-zA-Z$'\"]", "eval_call", Severity.CRITICAL),
        (rb"exec\s*\(\s*[a-zA-Z$'\"]", "exec_call", Severity.CRITICAL),
        (rb"system\s*\(\s*[a-zA-Z$'\"]", "system_call", Severity.CRITICAL),
        (rb"import\s+os\b", "python_import_os", Severity.HIGH),
        (rb"import\s+subprocess", "python_import_subprocess", Severity.HIGH),
        (rb"__import__\s*\(", "dynamic_import", Severity.HIGH),
        (rb"<script[^>]*>", "script_tag", Severity.HIGH),
        (rb"javascript:", "javascript_uri", Severity.HIGH),
        (rb"cmd\.exe", "cmd_exe", Severity.HIGH),
        (rb"/bin/sh\b", "shell_path", Severity.HIGH),
        (rb"/bin/bash\b", "bash_path", Severity.HIGH),
    ]

    # Check for validated pickle signatures in metadata area
    for pickle_sig in PICKLE_SIGNATURES:
        pos = metadata_region.find(pickle_sig, 20)
        if pos > 0 and pos < 65536 and _is_valid_pickle(metadata_region, pos):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    message=f"Pickle signature in image metadata at offset {pos}",
                    location=pos,
                    details={
                        "technique": "metadata_pickle",
                        "offset": pos,
                        "protocol": pickle_sig[1],
                    },
                )
            )
            break

    for pattern, technique, severity in suspicious_patterns:
        match = re.search(pattern, metadata_region, re.IGNORECASE)
        if match:
            findings.append(
                Finding(
                    severity=severity,
                    message=f"Suspicious pattern in image metadata: {technique}",
                    location=match.start(),
                    details={
                        "technique": f"metadata_{technique}",
                        "offset": match.start(),
                    },
                )
            )

    return findings


def _check_archive_in_video(data: bytes, filepath: Path) -> list[Finding]:
    """Detect archives appended to video files."""
    findings: list[Finding] = []

    file_size = len(data)
    if file_size < 100:
        return findings

    # Check last 64KB for appended archive
    read_size = min(65536, file_size)
    tail = data[-read_size:]

    for archive_type, signature in ARCHIVE_SIGNATURES.items():
        pos = tail.find(signature)
        if pos >= 0:
            actual_pos = file_size - read_size + pos
            atype = archive_type.upper()
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    message=f"Archive appended to video: {atype} at offset {actual_pos}",
                    location=actual_pos,
                    details={
                        "technique": "archive_in_video",
                        "archive_type": archive_type,
                        "archive_offset": actual_pos,
                        "warning": "May contain malicious pickle files",
                    },
                )
            )
            break

    # Check for validated pickle in tail
    for pickle_sig in PICKLE_SIGNATURES:
        pos = tail.find(pickle_sig)
        if pos >= 0 and _is_valid_pickle(tail, pos):
            actual_pos = file_size - read_size + pos
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    message=f"Pickle data appended to video at offset {actual_pos}",
                    location=actual_pos,
                    details={
                        "technique": "pickle_in_video",
                        "pickle_offset": actual_pos,
                        "protocol": pickle_sig[1],
                    },
                )
            )
            break

    return findings


def _check_video_metadata(data: bytes, filepath: Path) -> list[Finding]:
    """Check video metadata for suspicious payloads."""
    findings: list[Finding] = []
    ext = filepath.suffix.lower()

    metadata_region = data[:1024 * 1024]  # First 1MB

    if ext in {".mp4", ".m4v", ".mov"}:
        suspicious_patterns = [
            (rb"<\?php", "php_code", Severity.CRITICAL),
            (rb"eval\s*\(", "eval_call", Severity.CRITICAL),
            (rb"exec\s*\(", "exec_call", Severity.CRITICAL),
            (rb"import\s+os\b", "python_import", Severity.HIGH),
            (rb"subprocess", "subprocess_ref", Severity.HIGH),
            (rb"__import__\s*\(", "dynamic_import", Severity.HIGH),
            (rb"<script[^>]*>", "script_tag", Severity.HIGH),
        ]

        for pattern, technique, severity in suspicious_patterns:
            match = re.search(pattern, metadata_region, re.IGNORECASE)
            if match:
                findings.append(
                    Finding(
                        severity=severity,
                        message=f"Suspicious pattern in video metadata: {technique}",
                        location=match.start(),
                        details={
                            "technique": f"video_metadata_{technique}",
                            "offset": match.start(),
                        },
                    )
                )

    # MKV: Check for attachments indicator
    if ext == ".mkv":
        attachment_id = b"\x19\x41\xa4\x69"
        if attachment_id in metadata_region:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    message="MKV file contains attachments - review manually",
                    location=metadata_region.find(attachment_id),
                    details={
                        "technique": "mkv_attachments",
                        "warning": "Attachments may contain malicious files",
                    },
                )
            )

    return findings


# =============================================================================
# Context analysis functions
# =============================================================================

def _detect_file_format(filepath: Path) -> str:
    """Detect file format from extension for context analysis."""
    ext = filepath.suffix.lower()
    if ext in IMAGE_EXTENSIONS:
        return "image"
    elif ext in VIDEO_EXTENSIONS:
        return "video"
    else:
        return "unknown"


def scan_polyglot_with_context_from_bytes(
    file_data: bytes,
    filepath: Path,
    use_context_analysis: bool = True,
    entropy_threshold: float = 7.0,
) -> list[Finding]:
    """Scan file data for polyglot/disguised threats with context analysis.

    Args:
        file_data: File content as bytes
        filepath: Path to file (for extension detection and messages)
        use_context_analysis: Whether to run context analysis (default: True)
        entropy_threshold: Entropy threshold for compressed region detection

    Returns:
        List of findings, enriched with context_analysis if enabled
    """
    # Stage 1: Run standard pattern detection
    findings = scan_polyglot_from_bytes(file_data, filepath)

    if not use_context_analysis or not findings:
        return findings

    # Lazy import to avoid circular dependencies
    from tensortrap.scanner.context_analyzer import ContextAnalyzer

    file_format = _detect_file_format(filepath)
    analyzer = ContextAnalyzer(entropy_threshold=entropy_threshold)

    # Stage 2: Apply context analysis to HIGH/CRITICAL findings
    enriched_findings: list[Finding] = []

    for finding in findings:
        if finding.severity not in (Severity.HIGH, Severity.CRITICAL):
            enriched_findings.append(finding)
            continue

        pattern_name = ""
        if finding.details:
            pattern_name = finding.details.get("technique", "")
        if not pattern_name:
            pattern_name = finding.message[:50]

        context_result = analyzer.analyze(
            file_data=file_data,
            match_offset=finding.location or 0,
            pattern_name=pattern_name,
            file_format=file_format,
            original_severity=finding.severity.value,
            filepath=filepath,
        )

        enriched_details = dict(finding.details or {})
        enriched_details["context_analysis"] = context_result.to_dict()
        enriched_details["adjusted_severity"] = context_result.adjusted_severity
        enriched_details["confidence"] = context_result.confidence_score
        enriched_details["recommended_action"] = context_result.recommended_action

        enriched_finding = Finding(
            severity=finding.severity,
            message=finding.message,
            location=finding.location,
            details=enriched_details,
            recommendation=context_result.recommended_action,
        )

        enriched_findings.append(enriched_finding)

    return enriched_findings


def scan_polyglot_with_context(
    filepath: Path,
    use_context_analysis: bool = True,
    entropy_threshold: float = 7.0,
) -> list[Finding]:
    """Scan a file for polyglot/disguised threats with context analysis.

    Args:
        filepath: Path to file to scan
        use_context_analysis: Whether to run context analysis (default: True)
        entropy_threshold: Entropy threshold for compressed region detection

    Returns:
        List of findings, enriched with context_analysis if enabled
    """
    filepath = Path(filepath)
    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
    except OSError:
        return []

    return scan_polyglot_with_context_from_bytes(
        file_data, filepath, use_context_analysis, entropy_threshold
    )


def enrich_findings_with_context(
    findings: list[Finding],
    file_data: bytes,
    filepath: Path,
    file_format: str | None = None,
    entropy_threshold: float = 7.0,
) -> list[Finding]:
    """Enrich existing findings with context analysis.

    Args:
        findings: List of findings to enrich
        file_data: Raw file bytes
        filepath: Path to file
        file_format: File format (auto-detected if None)
        entropy_threshold: Entropy threshold for compressed detection

    Returns:
        List of findings enriched with context_analysis
    """
    if not findings:
        return findings

    from tensortrap.scanner.context_analyzer import ContextAnalyzer

    if file_format is None:
        file_format = _detect_file_format(filepath)

    analyzer = ContextAnalyzer(entropy_threshold=entropy_threshold)
    enriched_findings: list[Finding] = []

    for finding in findings:
        if finding.severity not in (Severity.HIGH, Severity.CRITICAL):
            enriched_findings.append(finding)
            continue

        pattern_name = ""
        if finding.details:
            pattern_name = finding.details.get("technique", "")
        if not pattern_name:
            pattern_name = finding.message[:50]

        context_result = analyzer.analyze(
            file_data=file_data,
            match_offset=finding.location or 0,
            pattern_name=pattern_name,
            file_format=file_format,
            original_severity=finding.severity.value,
            filepath=filepath,
        )

        enriched_details = dict(finding.details or {})
        enriched_details["context_analysis"] = context_result.to_dict()
        enriched_details["adjusted_severity"] = context_result.adjusted_severity
        enriched_details["confidence"] = context_result.confidence_score
        enriched_details["recommended_action"] = context_result.recommended_action

        enriched_finding = Finding(
            severity=finding.severity,
            message=finding.message,
            location=finding.location,
            details=enriched_details,
            recommendation=context_result.recommended_action,
        )

        enriched_findings.append(enriched_finding)

    return enriched_findings


def get_context_analysis_summary(findings: list[Finding]) -> dict[str, Any]:
    """Generate summary statistics for context-analyzed findings."""
    summary: dict[str, Any] = {
        "total_findings": len(findings),
        "context_analyzed": 0,
        "by_confidence": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "by_adjusted_severity": {},
        "actionable_count": 0,
    }

    for finding in findings:
        if not finding.details:
            continue

        ctx = finding.details.get("context_analysis")
        if not ctx:
            continue

        summary["context_analyzed"] += 1
        level = ctx.get("confidence_level", "LOW")
        summary["by_confidence"][level] = summary["by_confidence"].get(level, 0) + 1

        adjusted = finding.details.get("adjusted_severity", finding.severity.value)
        summary["by_adjusted_severity"][adjusted] = (
            summary["by_adjusted_severity"].get(adjusted, 0) + 1
        )

        if level in ("HIGH", "MEDIUM"):
            summary["actionable_count"] += 1

    return summary
