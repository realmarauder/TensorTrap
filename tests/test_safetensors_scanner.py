"""Tests for safetensors scanner."""

import json
import struct

import pytest

from tensortrap.scanner.results import Severity
from tensortrap.scanner.safetensors_scanner import scan_safetensors


class TestSafetensorsScanner:
    """Test safetensors scanning functionality."""

    def test_valid_safetensors(self, valid_safetensors_file):
        """Test that valid safetensors files pass."""
        findings = scan_safetensors(valid_safetensors_file)

        # Valid file should have no critical/high findings
        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0, (
            f"Valid safetensors had critical/high findings: {critical_high}"
        )

    def test_suspicious_metadata(self, suspicious_safetensors_file):
        """Test detection of suspicious metadata."""
        findings = scan_safetensors(suspicious_safetensors_file)

        # Should detect suspicious patterns
        suspicious_findings = [
            f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]
        assert len(suspicious_findings) > 0, "Should detect suspicious metadata"

    def test_oversized_header(self, fixtures_dir):
        """Test detection of oversized header."""
        filepath = fixtures_dir / "oversized.safetensors"

        # Claim a huge header size
        with open(filepath, "wb") as f:
            f.write(struct.pack("<Q", 500_000_000))  # 500MB header
            f.write(b"{}")  # Minimal actual data

        findings = scan_safetensors(filepath)

        # Should detect oversized header
        size_findings = [
            f for f in findings if "size" in f.message.lower() or "large" in f.message.lower()
        ]
        assert len(size_findings) > 0, "Should detect oversized header"

    def test_invalid_json_header(self, fixtures_dir):
        """Test handling of invalid JSON header."""
        filepath = fixtures_dir / "invalid_json.safetensors"

        invalid_json = b"{not valid json"
        with open(filepath, "wb") as f:
            f.write(struct.pack("<Q", len(invalid_json)))
            f.write(invalid_json)

        findings = scan_safetensors(filepath)

        # Should report JSON error
        json_findings = [f for f in findings if "json" in f.message.lower()]
        assert len(json_findings) > 0, "Should detect invalid JSON"

    def test_truncated_file(self, fixtures_dir):
        """Test handling of truncated file."""
        filepath = fixtures_dir / "truncated.safetensors"

        with open(filepath, "wb") as f:
            f.write(struct.pack("<Q", 1000))  # Claim 1000 byte header
            f.write(b"{}")  # Only write 2 bytes

        findings = scan_safetensors(filepath)

        # Should report truncation
        assert len(findings) > 0, "Should detect truncated file"

    def test_embedded_pickle_detection(self, fixtures_dir):
        """Test detection of embedded pickle in metadata."""
        filepath = fixtures_dir / "embedded_pickle.safetensors"

        # Create header with pickle-like bytes in metadata
        header = {
            "weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]},
            "__metadata__": {
                "payload": "\\x80\\x04\\x95"  # Looks like pickle protocol 4
            },
        }
        header_json = json.dumps(header).encode("utf-8")

        with open(filepath, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(struct.pack("<2f", 1.0, 2.0))

        findings = scan_safetensors(filepath)

        # Should detect potential pickle
        pickle_findings = [f for f in findings if "pickle" in f.message.lower()]
        assert len(pickle_findings) > 0, "Should detect embedded pickle pattern"

    def test_invalid_tensor_offsets(self, fixtures_dir):
        """Test detection of invalid tensor offsets."""
        filepath = fixtures_dir / "bad_offsets.safetensors"

        header = {
            "weight": {
                "dtype": "F32",
                "shape": [1000000],  # Large tensor
                "data_offsets": [0, 4000000],  # Offsets beyond file
            }
        }
        header_json = json.dumps(header).encode("utf-8")

        with open(filepath, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(b"\x00" * 16)  # Only 16 bytes of data

        findings = scan_safetensors(filepath)

        # Should detect invalid offsets
        offset_findings = [f for f in findings if "offset" in f.message.lower()]
        assert len(offset_findings) > 0, "Should detect invalid tensor offsets"


class TestMetadataPatterns:
    """Test detection of suspicious patterns in metadata."""

    @pytest.mark.parametrize(
        "pattern,description",
        [
            ("eval(", "eval function"),
            ("exec(", "exec function"),
            ("import os", "os import"),
            ("__import__", "dynamic import"),
            ("os.system", "system call"),
        ],
    )
    def test_code_pattern_detection(self, fixtures_dir, pattern, description):
        """Test detection of code patterns in metadata."""
        filepath = fixtures_dir / f"pattern_{pattern[:4]}.safetensors"

        header = {
            "tensor": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
            "__metadata__": {"suspicious": f"This contains {pattern} code"},
        }
        header_json = json.dumps(header).encode("utf-8")

        with open(filepath, "wb") as f:
            f.write(struct.pack("<Q", len(header_json)))
            f.write(header_json)
            f.write(struct.pack("<f", 1.0))

        findings = scan_safetensors(filepath)

        # Should detect the pattern
        pattern_findings = [
            f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]
        assert len(pattern_findings) > 0, f"Should detect {description} pattern"
