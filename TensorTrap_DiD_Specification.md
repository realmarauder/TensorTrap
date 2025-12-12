# TensorTrap Defense-in-Depth (DiD) Specification

## Document Purpose

This specification extends TensorTrap with polyglot/disguised threat detection and documents a recommended security stack for comprehensive AI workflow protection.

---

## Motivation

### The Gap

TensorTrap currently scans AI model files (pickle, safetensors, GGUF, etc.) for malicious code. However, attackers have developed evasion techniques:

1. **Polyglot files** - Files valid as multiple formats (e.g., an image that's also a ZIP containing pickle)
2. **Disguised extensions** - Malicious pickle files renamed to `.png` or `.jpg`
3. **Payload hiding** - Malicious data embedded in media metadata (EXIF, XMP)
4. **SVG attacks** - Vector graphics with embedded JavaScript

### Complementary Tools

Users should deploy TensorTrap alongside other security tools for full coverage:

| Tool | Purpose | TensorTrap Overlap |
|------|---------|-------------------|
| **Stego** | Steganography detection in images | None - different threat |
| **YARA** | Pattern-based malware scanning | Minimal - TensorTrap is format-aware |
| **MediaVal** | Media file validation | None - different purpose |
| **RKHunter** | Rootkit detection | None - system-level |

TensorTrap fills the **AI model security gap** that these tools don't address.

---

## New Capabilities

### 1. Polyglot File Scanner

A new scanner module (`scanner/polyglot_scanner.py`) to detect multi-format files.

#### Detection Categories

| Detection | Description | Severity | CVE/Reference |
|-----------|-------------|----------|---------------|
| Extension mismatch | File magic doesn't match extension | HIGH | CVE-2025-1889 |
| Archive-in-image | ZIP/7z/RAR appended to valid image | CRITICAL | Common evasion |
| Double extension | `model.safetensors.png` | MEDIUM | Social engineering |
| SVG script content | JavaScript/event handlers in SVG | HIGH | XSS vector |
| Metadata payload | Code patterns in EXIF/XMP | HIGH | Metadata injection |
| Trailing data | Unexpected data after valid image | MEDIUM | Polyglot indicator |

#### Implementation

```python
# src/tensortrap/scanner/polyglot_scanner.py

"""Polyglot and disguised file detection.

Detects files that masquerade as one format while containing another,
a common technique for bypassing security scanners.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import struct
import re

from tensortrap.scanner.results import Finding, Severity


@dataclass
class ImageInfo:
    """Basic image format information."""
    format: str
    width: int
    height: int
    end_offset: int  # Where the valid image data ends


# Magic bytes for common image formats
IMAGE_SIGNATURES = {
    "png": (b"\x89PNG\r\n\x1a\n", 0),
    "jpeg": (b"\xff\xd8\xff", 0),
    "gif": (b"GIF87a", 0),
    "gif89": (b"GIF89a", 0),
    "webp": (b"RIFF", 0),  # + "WEBP" at offset 8
    "bmp": (b"BM", 0),
    "svg": (b"<?xml", 0),  # or b"<svg"
    "svg_direct": (b"<svg", 0),
}

# Dangerous archive signatures
ARCHIVE_SIGNATURES = {
    "zip": b"PK\x03\x04",
    "zip_empty": b"PK\x05\x06",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "rar": b"Rar!\x1a\x07",
    "rar5": b"Rar!\x1a\x07\x01\x00",
}

# Pickle signatures
PICKLE_SIGNATURES = [
    b"\x80\x00",  # Protocol 0
    b"\x80\x01",  # Protocol 1
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
    ".mp4", ".webm", ".avi", ".mov", ".mkv", ".m4v", ".flv",
    ".wmv", ".ogv", ".3gp", ".ts", ".mts", ".m2ts",
}

# Combined media extensions
MEDIA_EXTENSIONS = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS


def scan_polyglot(filepath: Path) -> list[Finding]:
    """Scan a file for polyglot/disguised threats.

    Args:
        filepath: Path to file to scan

    Returns:
        List of findings
    """
    findings = []
    filepath = Path(filepath)
    ext = filepath.suffix.lower()

    # Check for double extensions
    findings.extend(_check_double_extension(filepath))

    # Check extension vs magic byte mismatch
    findings.extend(_check_extension_mismatch(filepath))

    # For image files, check for appended archives
    if ext in IMAGE_EXTENSIONS:
        findings.extend(_check_archive_in_image(filepath))
        findings.extend(_check_trailing_data(filepath))

    # For video files, check for appended archives and embedded data
    if ext in VIDEO_EXTENSIONS:
        findings.extend(_check_archive_in_video(filepath))
        findings.extend(_check_video_metadata(filepath))

    # For SVG files, check for embedded scripts
    if ext == ".svg":
        findings.extend(_check_svg_scripts(filepath))

    # Check EXIF/XMP metadata for payloads
    if ext in {".jpg", ".jpeg", ".tiff", ".tif", ".png", ".webp"}:
        findings.extend(_check_metadata_payloads(filepath))

    return findings


def _check_double_extension(filepath: Path) -> list[Finding]:
    """Detect double extension tricks like 'model.pkl.png'."""
    findings = []
    name = filepath.name.lower()

    # Known dangerous inner extensions
    dangerous_extensions = {
        ".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt",
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh",
        ".py", ".js", ".vbs", ".hta",
    }

    # Check if filename has multiple extensions
    parts = name.split(".")
    if len(parts) > 2:
        inner_ext = "." + parts[-2]
        if inner_ext in dangerous_extensions:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                message=f"Double extension detected: {name} (inner: {inner_ext})",
                location=None,
                details={
                    "technique": "double_extension",
                    "inner_extension": inner_ext,
                    "outer_extension": filepath.suffix,
                },
            ))

    return findings


def _check_extension_mismatch(filepath: Path) -> list[Finding]:
    """Detect when file extension doesn't match magic bytes."""
    findings = []
    ext = filepath.suffix.lower()

    try:
        with open(filepath, "rb") as f:
            header = f.read(32)
    except IOError:
        return findings

    if len(header) < 8:
        return findings

    # Determine what the file actually is based on magic bytes
    actual_format = None

    # Check for pickle (high priority - this is the main threat)
    if header[:2] in [bytes([0x80, i]) for i in range(6)]:
        actual_format = "pickle"

    # Check for archives
    for fmt, sig in ARCHIVE_SIGNATURES.items():
        if header.startswith(sig):
            actual_format = fmt
            break

    # Check for images (if claiming to be something else)
    if actual_format is None:
        if header.startswith(b"\x89PNG"):
            actual_format = "png"
        elif header.startswith(b"\xff\xd8\xff"):
            actual_format = "jpeg"
        elif header.startswith(b"GIF8"):
            actual_format = "gif"

    # Report mismatches
    if actual_format == "pickle" and ext in IMAGE_EXTENSIONS:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            message=f"Disguised pickle file: extension is {ext} but file is pickle format",
            location=0,
            details={
                "technique": "extension_mismatch",
                "claimed_format": ext,
                "actual_format": "pickle",
                "cve": "CVE-2025-1889",
            },
        ))

    elif actual_format in ("zip", "7z", "rar", "rar5") and ext in IMAGE_EXTENSIONS:
        findings.append(Finding(
            severity=Severity.HIGH,
            message=f"Disguised archive: extension is {ext} but file is {actual_format} format",
            location=0,
            details={
                "technique": "extension_mismatch",
                "claimed_format": ext,
                "actual_format": actual_format,
            },
        ))

    return findings


def _check_archive_in_image(filepath: Path) -> list[Finding]:
    """Detect ZIP/7z/RAR archives appended to valid images."""
    findings = []

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except IOError:
        return findings

    # Find archive signatures anywhere in the file (not at start)
    for archive_type, signature in ARCHIVE_SIGNATURES.items():
        # Skip if archive is at the very beginning (not a polyglot)
        pos = data.find(signature, 8)  # Start searching after first 8 bytes

        if pos > 0:
            # Verify this isn't just random bytes matching
            # For ZIP, check for valid local file header structure
            if archive_type in ("zip", "zip_empty") and pos + 30 < len(data):
                # ZIP local file header has predictable structure
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    message=f"Archive embedded in image: {archive_type.upper()} found at offset {pos}",
                    location=pos,
                    details={
                        "technique": "archive_in_image",
                        "archive_type": archive_type,
                        "archive_offset": pos,
                        "warning": "May contain malicious pickle files",
                    },
                ))
                break

            elif archive_type == "7z":
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    message=f"7z archive embedded in image at offset {pos} (CVE-2025-1716 bypass)",
                    location=pos,
                    details={
                        "technique": "archive_in_image",
                        "archive_type": "7z",
                        "archive_offset": pos,
                        "cve": "CVE-2025-1716",
                    },
                ))
                break

    # Also check for pickle signatures after image data
    for pickle_sig in PICKLE_SIGNATURES:
        pos = data.find(pickle_sig, 8)
        if pos > 0:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                message=f"Pickle data embedded in image at offset {pos}",
                location=pos,
                details={
                    "technique": "pickle_in_image",
                    "pickle_offset": pos,
                    "protocol": pickle_sig[1],
                },
            ))
            break

    return findings


def _check_trailing_data(filepath: Path) -> list[Finding]:
    """Check for unexpected data after valid image end marker."""
    findings = []
    ext = filepath.suffix.lower()

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except IOError:
        return findings

    trailing_data_start = None

    # PNG: ends with IEND chunk
    if ext == ".png" and data.startswith(b"\x89PNG"):
        iend_pos = data.find(b"IEND")
        if iend_pos > 0:
            # IEND chunk is 12 bytes total (4 len + 4 type + 4 crc)
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

    if trailing_data_start and (len(data) - trailing_data_start) > 16:
        trailing_size = len(data) - trailing_data_start
        trailing_preview = data[trailing_data_start:trailing_data_start + 16]

        # Check if trailing data looks like known dangerous formats
        severity = Severity.MEDIUM
        details = {
            "technique": "trailing_data",
            "trailing_offset": trailing_data_start,
            "trailing_size": trailing_size,
        }

        # Escalate if trailing data is archive or pickle
        for sig in PICKLE_SIGNATURES:
            if trailing_preview.startswith(sig):
                severity = Severity.CRITICAL
                details["contains"] = "pickle"
                break

        for archive_type, sig in ARCHIVE_SIGNATURES.items():
            if trailing_preview.startswith(sig):
                severity = Severity.CRITICAL
                details["contains"] = archive_type
                break

        findings.append(Finding(
            severity=severity,
            message=f"Trailing data after image end: {trailing_size} bytes at offset {trailing_data_start}",
            location=trailing_data_start,
            details=details,
        ))

    return findings


def _check_svg_scripts(filepath: Path) -> list[Finding]:
    """Detect JavaScript and event handlers in SVG files."""
    findings = []

    try:
        with open(filepath, "rb") as f:
            content = f.read(1024 * 1024)  # Read up to 1MB
    except IOError:
        return findings

    # Convert to string for pattern matching
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return findings

    # Dangerous SVG patterns
    dangerous_patterns = [
        (r"<script[^>]*>", "script_tag", Severity.CRITICAL),
        (r"on\w+\s*=", "event_handler", Severity.HIGH),  # onclick=, onload=, etc.
        (r"javascript:", "javascript_uri", Severity.CRITICAL),
        (r"data:text/html", "data_uri_html", Severity.HIGH),
        (r"<foreignObject", "foreign_object", Severity.MEDIUM),
        (r"xlink:href\s*=\s*[\"']javascript:", "xlink_javascript", Severity.CRITICAL),
        (r"set\s+attributeName.*on", "svg_animation_handler", Severity.HIGH),
    ]

    for pattern, technique, severity in dangerous_patterns:
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        if matches:
            findings.append(Finding(
                severity=severity,
                message=f"SVG contains {technique}: {len(matches)} occurrence(s)",
                location=matches[0].start(),
                details={
                    "technique": f"svg_{technique}",
                    "occurrences": len(matches),
                    "preview": text[matches[0].start():matches[0].start() + 50],
                },
            ))

    return findings


def _check_metadata_payloads(filepath: Path) -> list[Finding]:
    """Check image metadata (EXIF, XMP) for embedded code."""
    findings = []

    try:
        with open(filepath, "rb") as f:
            data = f.read(65536)  # First 64KB should contain metadata
    except IOError:
        return findings

    # Patterns that shouldn't appear in legitimate metadata
    suspicious_patterns = [
        (rb"<\?php", "php_code", Severity.CRITICAL),
        (rb"<%.*%>", "asp_code", Severity.CRITICAL),
        (rb"eval\s*\(", "eval_call", Severity.CRITICAL),
        (rb"exec\s*\(", "exec_call", Severity.CRITICAL),
        (rb"system\s*\(", "system_call", Severity.CRITICAL),
        (rb"import\s+os", "python_import", Severity.HIGH),
        (rb"subprocess", "subprocess_ref", Severity.HIGH),
        (rb"__import__", "dynamic_import", Severity.HIGH),
        (rb"\x80[\x00-\x05]", "pickle_signature", Severity.CRITICAL),
        (rb"<script", "script_tag", Severity.HIGH),
        (rb"javascript:", "javascript_uri", Severity.HIGH),
    ]

    for pattern, technique, severity in suspicious_patterns:
        match = re.search(pattern, data, re.IGNORECASE)
        if match:
            # Verify it's in a metadata section, not image data
            # EXIF is in APP1 segment (FFE1), XMP can be in various segments
            findings.append(Finding(
                severity=severity,
                message=f"Suspicious pattern in image metadata: {technique}",
                location=match.start(),
                details={
                    "technique": f"metadata_{technique}",
                    "offset": match.start(),
                },
            ))

    return findings


def _check_archive_in_video(filepath: Path) -> list[Finding]:
    """Detect archives appended to video files."""
    findings = []

    try:
        with open(filepath, "rb") as f:
            # Read first chunk for header validation
            header = f.read(32)

            # Seek to end and read last portion for appended data
            f.seek(0, 2)  # End of file
            file_size = f.tell()

            # Read last 64KB for appended archive detection
            read_size = min(65536, file_size)
            f.seek(-read_size, 2)
            tail = f.read()
    except IOError:
        return findings

    # Check for archives in tail of video file
    for archive_type, signature in ARCHIVE_SIGNATURES.items():
        pos = tail.find(signature)
        if pos >= 0:
            actual_pos = file_size - read_size + pos
            findings.append(Finding(
                severity=Severity.CRITICAL,
                message=f"Archive appended to video: {archive_type.upper()} at offset {actual_pos}",
                location=actual_pos,
                details={
                    "technique": "archive_in_video",
                    "archive_type": archive_type,
                    "archive_offset": actual_pos,
                    "warning": "May contain malicious pickle files",
                },
            ))
            break

    # Check for pickle in tail
    for pickle_sig in PICKLE_SIGNATURES:
        pos = tail.find(pickle_sig)
        if pos >= 0:
            actual_pos = file_size - read_size + pos
            findings.append(Finding(
                severity=Severity.CRITICAL,
                message=f"Pickle data appended to video at offset {actual_pos}",
                location=actual_pos,
                details={
                    "technique": "pickle_in_video",
                    "pickle_offset": actual_pos,
                    "protocol": pickle_sig[1],
                },
            ))
            break

    return findings


def _check_video_metadata(filepath: Path) -> list[Finding]:
    """Check video metadata for suspicious payloads."""
    findings = []

    try:
        with open(filepath, "rb") as f:
            # Read first 1MB which should contain most metadata
            data = f.read(1024 * 1024)
    except IOError:
        return findings

    ext = filepath.suffix.lower()

    # Video format-specific checks
    # MP4/M4V: Check for suspicious atoms
    if ext in {".mp4", ".m4v", ".mov"}:
        # Look for suspicious strings in metadata atoms
        suspicious_atoms = [
            (rb"<\?php", "php_code", Severity.CRITICAL),
            (rb"eval\s*\(", "eval_call", Severity.CRITICAL),
            (rb"exec\s*\(", "exec_call", Severity.CRITICAL),
            (rb"import\s+os", "python_import", Severity.HIGH),
            (rb"subprocess", "subprocess_ref", Severity.HIGH),
            (rb"__import__", "dynamic_import", Severity.HIGH),
            (rb"<script", "script_tag", Severity.HIGH),
        ]

        for pattern, technique, severity in suspicious_atoms:
            match = re.search(pattern, data, re.IGNORECASE)
            if match:
                findings.append(Finding(
                    severity=severity,
                    message=f"Suspicious pattern in video metadata: {technique}",
                    location=match.start(),
                    details={
                        "technique": f"video_metadata_{technique}",
                        "offset": match.start(),
                    },
                ))

    # MKV: Check for suspicious attachments indicator
    if ext == ".mkv":
        # MKV uses EBML format - look for attachment element
        if b"\x19\x41\xa4\x69" in data:  # Attachments element ID
            findings.append(Finding(
                severity=Severity.MEDIUM,
                message="MKV file contains attachments - review manually",
                location=data.find(b"\x19\x41\xa4\x69"),
                details={
                    "technique": "mkv_attachments",
                    "warning": "Attachments may contain malicious files",
                },
            ))

    return findings


# Exported extensions for engine integration
MEDIA_EXTENSIONS = IMAGE_EXTENSIONS | VIDEO_EXTENSIONS
```

### 2. Engine Integration

Update `scanner/engine.py` to include polyglot scanning **by default on all files**:

```python
# Add to imports
from tensortrap.scanner.polyglot_scanner import scan_polyglot, MEDIA_EXTENSIONS

# Update FORMAT_EXTENSIONS in patterns.py to include all media extensions
FORMAT_EXTENSIONS: dict[str, str] = {
    # ... existing model formats ...

    # Image formats (polyglot scanning)
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".webp": "image",
    ".bmp": "image",
    ".svg": "svg",
    ".tiff": "image",
    ".tif": "image",
    ".ico": "image",
    ".avif": "image",
    ".heic": "image",
    ".heif": "image",

    # Video formats (polyglot scanning)
    ".mp4": "video",
    ".webm": "video",
    ".avi": "video",
    ".mov": "video",
    ".mkv": "video",
    ".m4v": "video",
    ".flv": "video",
    ".wmv": "video",
    ".ogv": "video",
    ".3gp": "video",
    ".ts": "video",
    ".mts": "video",
    ".m2ts": "video",
}

# Update _scan_by_format to handle media files
def _scan_by_format(filepath: Path, file_format: str) -> list[Finding]:
    """Run the appropriate scanner for a file format."""
    findings = []

    # Existing model format scanning...
    if file_format == "pickle":
        findings.extend(scan_pickle_file(filepath))
    # ... other formats ...

    # Always run polyglot scanner on media files
    elif file_format in ("image", "video", "svg"):
        findings.extend(scan_polyglot(filepath))

    # Run polyglot checks on ALL files (catches disguised files)
    # This is always-on, no flag needed
    polyglot_findings = scan_polyglot(filepath)
    findings.extend(polyglot_findings)

    return findings
```

**Key change**: Polyglot scanning is **always enabled** - no opt-in flag required. This ensures disguised threats are caught regardless of file extension.

---

## New File Extensions (Always Scanned)

### Image Files

| Extension | Format | Threat Type |
|-----------|--------|-------------|
| .png | PNG image | Polyglot, trailing data, metadata |
| .jpg/.jpeg | JPEG image | Polyglot, EXIF payload, trailing data |
| .gif | GIF image | Polyglot, trailing data |
| .webp | WebP image | Polyglot, metadata |
| .svg | SVG vector | JavaScript injection, XSS |
| .bmp | Bitmap | Polyglot |
| .tiff/.tif | TIFF image | EXIF payload |
| .ico | Icon | Polyglot |
| .avif | AVIF image | Polyglot, metadata |
| .heic/.heif | HEIF image | Polyglot, metadata |

### Video Files

| Extension | Format | Threat Type |
|-----------|--------|-------------|
| .mp4 | MPEG-4 | Appended archives, metadata payloads |
| .m4v | MPEG-4 Video | Appended archives, metadata payloads |
| .mov | QuickTime | Appended archives, metadata payloads |
| .webm | WebM | Appended archives, metadata |
| .mkv | Matroska | Attachments, appended archives |
| .avi | AVI | Appended archives |
| .flv | Flash Video | Appended archives |
| .wmv | Windows Media | Appended archives |
| .ogv | Ogg Video | Appended archives |
| .3gp | 3GPP | Appended archives |
| .ts/.mts/.m2ts | MPEG Transport | Appended archives |

---

## CLI Structure (No Changes Needed)

Polyglot scanning is always-on, so no new flags are required:

```
tensortrap
├── scan <path>
│   ├── --recursive
│   ├── --json
│   ├── --verbose
│   ├── --no-hash
│   ├── --report
│   ├── --report-dir
│   └── --report-formats
```

All media files in scanned directories will automatically be checked for polyglot threats.

---

## README Security Stack Section

Add to README.md:

```markdown
## Defense in Depth

TensorTrap focuses on AI model file security. For comprehensive protection of your AI workflow, we recommend combining TensorTrap with these complementary tools:

### Recommended Security Stack

| Tool | Purpose | Install |
|------|---------|---------|
| **TensorTrap** | AI model file scanning | `pip install tensortrap` |
| **Stego** | Steganography detection | See [stego-toolkit](https://github.com/DominicBreuker/stego-toolkit) |
| **YARA** | Pattern-based malware detection | `apt install yara` / [yara.readthedocs.io](https://yara.readthedocs.io/) |
| **MediaVal** | Media file validation | Platform-specific |
| **RKHunter** | Rootkit detection | `apt install rkhunter` |
| **ClamAV** | General antivirus | `apt install clamav` |

### What Each Tool Catches

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI Workflow Security                          │
├─────────────────────────────────────────────────────────────────┤
│  Downloaded Models    │  Generated Output    │  System Level    │
│  ─────────────────    │  ────────────────    │  ────────────    │
│  TensorTrap ✓         │  Stego ✓             │  RKHunter ✓      │
│  • Pickle exploits    │  • Hidden data       │  • Rootkits      │
│  • Format attacks     │  • Steganography     │  • Backdoors     │
│  • Polyglot files     │                      │                  │
│                       │  MediaVal ✓          │  ClamAV ✓        │
│  YARA ✓               │  • Corrupted files   │  • Known malware │
│  • Known signatures   │  • Format exploits   │  • Viruses       │
└─────────────────────────────────────────────────────────────────┘
```

### Quick Setup (Linux)

```bash
# Install TensorTrap
pip install tensortrap

# Install system tools
sudo apt update
sudo apt install yara rkhunter clamav clamav-daemon

# Initialize ClamAV database
sudo freshclam

# Run comprehensive scan
tensortrap scan ~/Models ~/Downloads    # AI models + media polyglot detection (always-on)
yara -r /path/to/rules ~/Downloads      # Pattern matching
rkhunter --check                        # System integrity
clamscan -r ~/Downloads                 # General malware
```

### Automated Scanning

For continuous protection, see [Daemon Mode](docs/daemon.md) to run TensorTrap as a background service alongside your other security tools.
```

---

## Testing Requirements

### Polyglot Scanner Tests

```python
# tests/test_polyglot_scanner.py

def test_clean_png_no_findings(tmp_path):
    """Valid PNG file produces no findings."""
    # Create minimal valid PNG
    png_file = tmp_path / "clean.png"
    # Write valid PNG bytes...

    findings = scan_polyglot(png_file)
    assert len(findings) == 0

def test_pickle_disguised_as_png(tmp_path):
    """Pickle file with .png extension is detected."""
    fake_png = tmp_path / "model.png"
    fake_png.write_bytes(b"\x80\x04\x95...")  # Pickle protocol 4

    findings = scan_polyglot(fake_png)
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("disguised pickle" in f.message.lower() for f in findings)

def test_zip_appended_to_png(tmp_path):
    """ZIP archive appended to valid PNG is detected."""
    # Create PNG + ZIP polyglot
    polyglot = tmp_path / "image.png"
    polyglot.write_bytes(VALID_PNG_BYTES + b"PK\x03\x04...")

    findings = scan_polyglot(polyglot)
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("archive embedded" in f.message.lower() for f in findings)

def test_svg_with_script_tag(tmp_path):
    """SVG with script tag is flagged."""
    svg_file = tmp_path / "image.svg"
    svg_file.write_text('<svg><script>alert(1)</script></svg>')

    findings = scan_polyglot(svg_file)
    assert any(f.severity == Severity.CRITICAL for f in findings)

def test_svg_with_event_handler(tmp_path):
    """SVG with onclick handler is flagged."""
    svg_file = tmp_path / "image.svg"
    svg_file.write_text('<svg><rect onclick="alert(1)"/></svg>')

    findings = scan_polyglot(svg_file)
    assert any(f.severity == Severity.HIGH for f in findings)

def test_double_extension_detection(tmp_path):
    """Double extension like .pkl.png is detected."""
    suspicious = tmp_path / "model.pkl.png"
    suspicious.write_bytes(b"\x89PNG...")  # Even if valid PNG

    findings = scan_polyglot(suspicious)
    assert any("double extension" in f.message.lower() for f in findings)

def test_trailing_data_after_jpeg(tmp_path):
    """Data after JPEG EOI marker is detected."""
    jpeg_polyglot = tmp_path / "image.jpg"
    jpeg_polyglot.write_bytes(VALID_JPEG_BYTES + b"\x80\x04pickle_data")

    findings = scan_polyglot(jpeg_polyglot)
    assert any(f.severity == Severity.CRITICAL for f in findings)

def test_exif_payload(tmp_path):
    """Suspicious code in EXIF metadata is detected."""
    # Create JPEG with malicious EXIF
    jpeg_file = tmp_path / "photo.jpg"
    # Write JPEG with "eval(" in EXIF comment

    findings = scan_polyglot(jpeg_file)
    assert any("metadata" in f.message.lower() for f in findings)

def test_video_with_appended_archive(tmp_path):
    """ZIP archive appended to video file is detected."""
    video_file = tmp_path / "video.mp4"
    video_file.write_bytes(VALID_MP4_BYTES + b"PK\x03\x04...")

    findings = scan_polyglot(video_file)
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("archive appended" in f.message.lower() for f in findings)

def test_video_with_appended_pickle(tmp_path):
    """Pickle data appended to video file is detected."""
    video_file = tmp_path / "video.mp4"
    video_file.write_bytes(VALID_MP4_BYTES + b"\x80\x04\x95...")

    findings = scan_polyglot(video_file)
    assert any(f.severity == Severity.CRITICAL for f in findings)
    assert any("pickle" in f.message.lower() for f in findings)

def test_mkv_with_attachments(tmp_path):
    """MKV with attachments is flagged for review."""
    mkv_file = tmp_path / "video.mkv"
    # Write MKV with attachment element

    findings = scan_polyglot(mkv_file)
    assert any(f.severity == Severity.MEDIUM for f in findings)
    assert any("attachment" in f.message.lower() for f in findings)

def test_clean_video_no_findings(tmp_path):
    """Valid video file produces no findings."""
    video_file = tmp_path / "clean.mp4"
    video_file.write_bytes(VALID_MP4_BYTES)

    findings = scan_polyglot(video_file)
    assert len(findings) == 0
```

---

## Implementation Priority

1. **Core polyglot scanner** (`scanner/polyglot_scanner.py`)
   - Extension mismatch detection (highest priority)
   - Archive-in-image detection
   - Archive-in-video detection
   - SVG script detection
   - Metadata payload detection

2. **Engine integration**
   - Add media extensions to FORMAT_EXTENSIONS
   - Integrate polyglot scanner into scan flow (always-on)
   - No new CLI flags needed

3. **README updates**
   - Add Defense in Depth section
   - Document security stack recommendations
   - Update "What We Detect" section with media/polyglot info

4. **Testing**
   - Create test fixtures (polyglot files, malicious SVGs, video with appended data)
   - Unit tests for each detection type
   - False positive testing with legitimate media files

5. **Documentation**
   - Update README with new capabilities
   - Add examples of polyglot detection output

---

## Dependencies

No new dependencies required. The polyglot scanner uses only standard library modules:
- `struct` - Binary parsing
- `re` - Pattern matching
- `pathlib` - File handling

---

## Success Criteria

1. **Detection rate**: Catches all documented polyglot techniques
2. **False positive rate**: < 1% on legitimate media files
3. **Performance**: Adds < 100ms overhead per media file scanned
4. **Usability**: Clear, actionable findings with severity levels
5. **Documentation**: README includes security stack recommendations

---

## Notes for Implementation

1. Start with `_check_extension_mismatch()` - this is the highest-value detection
2. SVG scanning is straightforward regex - implement second
3. Archive-in-image requires careful offset detection to avoid false positives
4. Video scanning reads only header + tail, not entire file (performance)
5. Trailing data detection needs format-specific end markers
6. Metadata payload detection should focus on obvious code patterns, not be overly aggressive
7. MKV attachment detection is informational (MEDIUM) since attachments have legitimate uses
8. Polyglot scanning is always-on by default for comprehensive protection
