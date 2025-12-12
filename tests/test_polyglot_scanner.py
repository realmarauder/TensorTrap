"""Tests for the polyglot scanner module."""

import pytest
from pathlib import Path

from tensortrap.scanner.polyglot_scanner import (
    scan_polyglot,
    _check_double_extension,
    _check_extension_mismatch,
    _check_archive_in_image,
    _check_trailing_data,
    _check_svg_scripts,
    _check_metadata_payloads,
    _check_archive_in_video,
    _check_video_metadata,
)
from tensortrap.scanner.results import Severity


# Minimal valid PNG (1x1 transparent pixel)
VALID_PNG_BYTES = (
    b'\x89PNG\r\n\x1a\n'  # PNG signature
    b'\x00\x00\x00\rIHDR'  # IHDR chunk
    b'\x00\x00\x00\x01'  # Width: 1
    b'\x00\x00\x00\x01'  # Height: 1
    b'\x08\x06'  # Bit depth: 8, Color type: RGBA
    b'\x00\x00\x00'  # Compression, Filter, Interlace
    b'\x1f\x15\xc4\x89'  # CRC
    b'\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01'  # IDAT chunk
    b'\r\n-\xb4'  # CRC
    b'\x00\x00\x00\x00IEND'  # IEND chunk
    b'\xaeB`\x82'  # CRC
)

# Minimal valid JPEG (1x1 red pixel)
VALID_JPEG_BYTES = (
    b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
    b'\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t'
    b'\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a'
    b'\x1f\x1e\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),01444\x1f\'9telelit\x14\x00'
    b'\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00'
    b'\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b'
    b'\xff\xda\x00\x08\x01\x01\x00\x00?\x00}\xff\xd9'
)

# Minimal valid GIF (1x1 pixel)
VALID_GIF_BYTES = (
    b'GIF89a'  # Header
    b'\x01\x00\x01\x00'  # Width: 1, Height: 1
    b'\x00\x00\x00'  # Flags, bgcolor, aspect
    b',\x00\x00\x00\x00\x01\x00\x01\x00\x00'  # Image descriptor
    b'\x02\x02D\x01\x00'  # Image data
    b'\x3b'  # Trailer
)

# Pickle protocol signatures
PICKLE_PROTO_4 = b'\x80\x04'
PICKLE_PROTO_5 = b'\x80\x05'

# ZIP signature
ZIP_SIGNATURE = b'PK\x03\x04'

# 7z signature
SEVENZ_SIGNATURE = b'7z\xbc\xaf\x27\x1c'


class TestDoubleExtension:
    """Tests for double extension detection."""

    def test_double_extension_pkl_png(self, tmp_path):
        """Detect model.pkl.png double extension."""
        filepath = tmp_path / "model.pkl.png"
        filepath.write_bytes(VALID_PNG_BYTES)

        findings = _check_double_extension(filepath)

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "double extension" in findings[0].message.lower()
        assert ".pkl" in findings[0].details["inner_extension"]

    def test_double_extension_pt_jpg(self, tmp_path):
        """Detect model.pt.jpg double extension."""
        filepath = tmp_path / "model.pt.jpg"
        filepath.write_bytes(VALID_JPEG_BYTES)

        findings = _check_double_extension(filepath)

        assert len(findings) == 1
        assert ".pt" in findings[0].details["inner_extension"]

    def test_no_double_extension(self, tmp_path):
        """Clean file with single extension produces no findings."""
        filepath = tmp_path / "image.png"
        filepath.write_bytes(VALID_PNG_BYTES)

        findings = _check_double_extension(filepath)

        assert len(findings) == 0

    def test_safe_double_extension(self, tmp_path):
        """Non-dangerous double extension (e.g., file.backup.png)."""
        filepath = tmp_path / "file.backup.png"
        filepath.write_bytes(VALID_PNG_BYTES)

        findings = _check_double_extension(filepath)

        assert len(findings) == 0


class TestExtensionMismatch:
    """Tests for extension vs magic byte mismatch detection."""

    def test_pickle_disguised_as_png(self, tmp_path):
        """Pickle file with .png extension is detected."""
        filepath = tmp_path / "image.png"
        # Write pickle bytes with PNG extension
        filepath.write_bytes(PICKLE_PROTO_4 + b'\x95\x00\x00\x00\x00\x00\x00\x00\x00.')

        findings = _check_extension_mismatch(filepath)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "disguised pickle" in findings[0].message.lower()
        assert findings[0].details["cve"] == "CVE-2025-1889"

    def test_pickle_disguised_as_jpg(self, tmp_path):
        """Pickle file with .jpg extension is detected."""
        filepath = tmp_path / "photo.jpg"
        filepath.write_bytes(PICKLE_PROTO_5 + b'\x95\x00\x00\x00\x00\x00\x00\x00\x00.')

        findings = _check_extension_mismatch(filepath)

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_zip_disguised_as_image(self, tmp_path):
        """ZIP file with image extension is detected."""
        filepath = tmp_path / "image.png"
        filepath.write_bytes(ZIP_SIGNATURE + b'\x00' * 26)

        findings = _check_extension_mismatch(filepath)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "disguised archive" in findings[0].message.lower()

    def test_valid_png_no_mismatch(self, tmp_path):
        """Valid PNG file produces no mismatch findings."""
        filepath = tmp_path / "image.png"
        filepath.write_bytes(VALID_PNG_BYTES)

        findings = _check_extension_mismatch(filepath)

        assert len(findings) == 0

    def test_valid_jpeg_no_mismatch(self, tmp_path):
        """Valid JPEG file produces no mismatch findings."""
        filepath = tmp_path / "photo.jpg"
        filepath.write_bytes(VALID_JPEG_BYTES)

        findings = _check_extension_mismatch(filepath)

        assert len(findings) == 0


class TestArchiveInImage:
    """Tests for archive-in-image detection."""

    def test_zip_appended_to_png(self, tmp_path):
        """ZIP archive appended to PNG is detected."""
        filepath = tmp_path / "image.png"
        filepath.write_bytes(VALID_PNG_BYTES + ZIP_SIGNATURE + b'\x00' * 26)

        findings = _check_archive_in_image(filepath)

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("archive embedded" in f.message.lower() or "zip" in f.message.lower() for f in findings)

    def test_7z_appended_to_png(self, tmp_path):
        """7z archive appended to PNG is detected (CVE-2025-1716)."""
        filepath = tmp_path / "image.png"
        filepath.write_bytes(VALID_PNG_BYTES + SEVENZ_SIGNATURE + b'\x00' * 20)

        findings = _check_archive_in_image(filepath)

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("CVE-2025-1716" in str(f.details) for f in findings)

    def test_pickle_embedded_in_image(self, tmp_path):
        """Pickle data embedded in image is detected."""
        filepath = tmp_path / "image.png"
        # Protocol 4 pickle with proper FRAME structure and valid opcode after frame
        # FRAME (0x95) + 8-byte length (20) + EMPTY_DICT (0x7D) as first opcode
        valid_pickle = PICKLE_PROTO_4 + b'\x95\x14\x00\x00\x00\x00\x00\x00\x00}.'
        filepath.write_bytes(VALID_PNG_BYTES + valid_pickle)

        findings = _check_archive_in_image(filepath)

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("pickle" in f.message.lower() for f in findings)

    def test_clean_png_no_archive(self, tmp_path):
        """Valid PNG without appended data produces no findings."""
        filepath = tmp_path / "clean.png"
        filepath.write_bytes(VALID_PNG_BYTES)

        findings = _check_archive_in_image(filepath)

        assert len(findings) == 0


class TestTrailingData:
    """Tests for trailing data detection."""

    def test_trailing_data_after_png(self, tmp_path):
        """Data after PNG IEND chunk is detected."""
        filepath = tmp_path / "image.png"
        # Add significant trailing data
        filepath.write_bytes(VALID_PNG_BYTES + b'SUSPICIOUS_TRAILING_DATA_HERE_12345')

        findings = _check_trailing_data(filepath)

        assert len(findings) >= 1
        assert any("trailing data" in f.message.lower() for f in findings)

    def test_trailing_pickle_after_png(self, tmp_path):
        """Pickle data after PNG end is flagged as critical."""
        filepath = tmp_path / "image.png"
        filepath.write_bytes(VALID_PNG_BYTES + PICKLE_PROTO_4 + b'\x95' + b'\x00' * 20)

        findings = _check_trailing_data(filepath)

        # Should detect trailing data with pickle
        assert len(findings) >= 1

    def test_trailing_data_after_jpeg(self, tmp_path):
        """Data after JPEG EOI marker is detected."""
        filepath = tmp_path / "photo.jpg"
        filepath.write_bytes(VALID_JPEG_BYTES + b'SUSPICIOUS_DATA_AFTER_EOI_1234567890')

        findings = _check_trailing_data(filepath)

        assert len(findings) >= 1
        assert any("trailing data" in f.message.lower() for f in findings)

    def test_clean_jpeg_no_trailing(self, tmp_path):
        """Valid JPEG without trailing data produces no findings."""
        filepath = tmp_path / "clean.jpg"
        filepath.write_bytes(VALID_JPEG_BYTES)

        findings = _check_trailing_data(filepath)

        assert len(findings) == 0


class TestSVGScripts:
    """Tests for SVG script detection."""

    def test_svg_with_script_tag(self, tmp_path):
        """SVG with <script> tag is flagged."""
        filepath = tmp_path / "image.svg"
        filepath.write_text('<svg><script>alert(1)</script></svg>')

        findings = _check_svg_scripts(filepath)

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("script_tag" in str(f.details) for f in findings)

    def test_svg_with_onclick(self, tmp_path):
        """SVG with onclick handler is flagged."""
        filepath = tmp_path / "image.svg"
        filepath.write_text('<svg><rect onclick="alert(1)"/></svg>')

        findings = _check_svg_scripts(filepath)

        assert len(findings) >= 1
        assert any(f.severity == Severity.HIGH for f in findings)
        assert any("event_handler" in str(f.details) for f in findings)

    def test_svg_with_javascript_uri(self, tmp_path):
        """SVG with javascript: URI is flagged."""
        filepath = tmp_path / "image.svg"
        filepath.write_text('<svg><a xlink:href="javascript:alert(1)">click</a></svg>')

        findings = _check_svg_scripts(filepath)

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_svg_with_onload(self, tmp_path):
        """SVG with onload handler is flagged."""
        filepath = tmp_path / "image.svg"
        filepath.write_text('<svg onload="malicious()"></svg>')

        findings = _check_svg_scripts(filepath)

        assert len(findings) >= 1
        assert any("event_handler" in str(f.details) for f in findings)

    def test_clean_svg_no_scripts(self, tmp_path):
        """Clean SVG without scripts produces no findings."""
        filepath = tmp_path / "clean.svg"
        filepath.write_text('<svg><rect x="0" y="0" width="100" height="100" fill="blue"/></svg>')

        findings = _check_svg_scripts(filepath)

        assert len(findings) == 0


class TestMetadataPayloads:
    """Tests for metadata payload detection."""

    def test_php_in_metadata(self, tmp_path):
        """PHP code in image metadata is detected."""
        filepath = tmp_path / "image.jpg"
        # Create a file with PHP code that would appear in metadata area
        filepath.write_bytes(VALID_JPEG_BYTES[:20] + b'<?php system($_GET["cmd"]); ?>' + VALID_JPEG_BYTES[20:])

        findings = _check_metadata_payloads(filepath)

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_eval_in_metadata(self, tmp_path):
        """eval() call in image metadata is detected."""
        filepath = tmp_path / "image.jpg"
        filepath.write_bytes(VALID_JPEG_BYTES[:20] + b'eval(base64_decode($payload))' + VALID_JPEG_BYTES[20:])

        findings = _check_metadata_payloads(filepath)

        assert len(findings) >= 1

    def test_python_import_in_metadata(self, tmp_path):
        """Python import in image metadata is detected."""
        filepath = tmp_path / "image.jpg"
        filepath.write_bytes(VALID_JPEG_BYTES[:20] + b'import os\nos.system("whoami")' + VALID_JPEG_BYTES[20:])

        findings = _check_metadata_payloads(filepath)

        assert len(findings) >= 1

    def test_clean_jpeg_metadata(self, tmp_path):
        """Clean JPEG without payload produces no findings."""
        filepath = tmp_path / "clean.jpg"
        filepath.write_bytes(VALID_JPEG_BYTES)

        findings = _check_metadata_payloads(filepath)

        assert len(findings) == 0


class TestArchiveInVideo:
    """Tests for archive-in-video detection."""

    def test_zip_appended_to_mp4(self, tmp_path):
        """ZIP archive appended to video is detected."""
        filepath = tmp_path / "video.mp4"
        # Minimal MP4-like header + ZIP at end
        mp4_header = b'\x00\x00\x00\x1cftypisom' + b'\x00' * 100
        filepath.write_bytes(mp4_header + ZIP_SIGNATURE + b'\x00' * 26)

        findings = _check_archive_in_video(filepath)

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_pickle_appended_to_video(self, tmp_path):
        """Pickle data appended to video is detected."""
        filepath = tmp_path / "video.mp4"
        mp4_header = b'\x00\x00\x00\x1cftypisom' + b'\x00' * 100
        # Protocol 4 pickle with proper FRAME structure and valid opcode after frame
        # FRAME (0x95) + 8-byte length (20) + EMPTY_DICT (0x7D) as first opcode
        valid_pickle = PICKLE_PROTO_4 + b'\x95\x14\x00\x00\x00\x00\x00\x00\x00}.'
        filepath.write_bytes(mp4_header + valid_pickle)

        findings = _check_archive_in_video(filepath)

        assert len(findings) >= 1
        assert any("pickle" in f.message.lower() for f in findings)


class TestVideoMetadata:
    """Tests for video metadata detection."""

    def test_mkv_with_attachments(self, tmp_path):
        """MKV with attachments element is flagged."""
        filepath = tmp_path / "video.mkv"
        # EBML header + attachments element ID
        mkv_data = b'\x1a\x45\xdf\xa3' + b'\x00' * 50 + b'\x19\x41\xa4\x69' + b'\x00' * 50
        filepath.write_bytes(mkv_data)

        findings = _check_video_metadata(filepath)

        assert len(findings) >= 1
        assert any(f.severity == Severity.MEDIUM for f in findings)
        assert any("attachment" in f.message.lower() for f in findings)


class TestFullScan:
    """Integration tests for the full scan_polyglot function."""

    def test_clean_png(self, tmp_path):
        """Valid PNG file produces no findings."""
        filepath = tmp_path / "clean.png"
        filepath.write_bytes(VALID_PNG_BYTES)

        findings = scan_polyglot(filepath)

        assert len(findings) == 0

    def test_clean_jpeg(self, tmp_path):
        """Valid JPEG file produces no findings."""
        filepath = tmp_path / "clean.jpg"
        filepath.write_bytes(VALID_JPEG_BYTES)

        findings = scan_polyglot(filepath)

        assert len(findings) == 0

    def test_malicious_polyglot(self, tmp_path):
        """Polyglot file with multiple issues is fully detected."""
        filepath = tmp_path / "model.pkl.png"
        # This file has: double extension + pickle bytes + trailing data
        filepath.write_bytes(PICKLE_PROTO_4 + b'\x95\x00\x00\x00\x00\x00\x00\x00\x00.')

        findings = scan_polyglot(filepath)

        # Should have multiple findings
        assert len(findings) >= 2
        # Should have critical severity
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_svg_with_multiple_issues(self, tmp_path):
        """SVG with multiple dangerous patterns."""
        filepath = tmp_path / "malicious.svg"
        filepath.write_text('''
            <svg>
                <script>alert(1)</script>
                <rect onclick="evil()"/>
                <a xlink:href="javascript:steal()">link</a>
            </svg>
        ''')

        findings = scan_polyglot(filepath)

        # Should detect multiple issues
        assert len(findings) >= 3
