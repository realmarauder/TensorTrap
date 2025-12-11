"""Tests for GGUF scanner."""

import struct
import pytest

from tensortrap.scanner.gguf_scanner import scan_gguf
from tensortrap.scanner.results import Severity


class TestGGUFScanner:
    """Test GGUF scanning functionality."""

    def test_valid_gguf(self, valid_gguf_file):
        """Test that valid GGUF files pass."""
        findings = scan_gguf(valid_gguf_file)

        # Valid file should have no critical/high findings
        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0, f"Valid GGUF had critical/high findings: {critical_high}"

    def test_invalid_magic(self, invalid_gguf_file):
        """Test detection of invalid magic number."""
        findings = scan_gguf(invalid_gguf_file)

        # Should detect invalid magic
        magic_findings = [f for f in findings if "magic" in f.message.lower()]
        assert len(magic_findings) > 0, "Should detect invalid magic"
        assert any(f.severity == Severity.CRITICAL for f in magic_findings), \
            "Invalid magic should be critical"

    def test_unknown_version(self, fixtures_dir):
        """Test handling of unknown GGUF version."""
        filepath = fixtures_dir / "unknown_version.gguf"

        with open(filepath, "wb") as f:
            f.write(struct.pack("<I", 0x46554747))  # Valid magic
            f.write(struct.pack("<I", 99))  # Unknown version
            f.write(struct.pack("<Q", 0))
            f.write(struct.pack("<Q", 0))

        findings = scan_gguf(filepath)

        # Should note unknown version
        version_findings = [f for f in findings if "version" in f.message.lower()]
        assert len(version_findings) > 0, "Should detect unknown version"

    def test_excessive_tensor_count(self, fixtures_dir):
        """Test detection of excessive tensor count."""
        filepath = fixtures_dir / "many_tensors.gguf"

        with open(filepath, "wb") as f:
            f.write(struct.pack("<I", 0x46554747))
            f.write(struct.pack("<I", 3))
            f.write(struct.pack("<Q", 1000000))  # 1 million tensors
            f.write(struct.pack("<Q", 0))

        findings = scan_gguf(filepath)

        # Should flag excessive tensors
        tensor_findings = [f for f in findings if "tensor" in f.message.lower()]
        assert len(tensor_findings) > 0, "Should detect excessive tensor count"

    def test_excessive_metadata_count(self, fixtures_dir):
        """Test detection of excessive metadata count."""
        filepath = fixtures_dir / "many_metadata.gguf"

        with open(filepath, "wb") as f:
            f.write(struct.pack("<I", 0x46554747))
            f.write(struct.pack("<I", 3))
            f.write(struct.pack("<Q", 0))
            f.write(struct.pack("<Q", 100000))  # 100k metadata entries

        findings = scan_gguf(filepath)

        # Should flag excessive metadata
        metadata_findings = [f for f in findings if "metadata" in f.message.lower()]
        assert len(metadata_findings) > 0, "Should detect excessive metadata count"

    def test_truncated_file(self, fixtures_dir):
        """Test handling of truncated file."""
        filepath = fixtures_dir / "truncated.gguf"

        with open(filepath, "wb") as f:
            f.write(struct.pack("<I", 0x46554747))  # Only magic

        findings = scan_gguf(filepath)

        # Should report error
        assert len(findings) > 0, "Should detect truncated file"

    def test_empty_file(self, fixtures_dir):
        """Test handling of empty file."""
        filepath = fixtures_dir / "empty.gguf"
        filepath.touch()

        findings = scan_gguf(filepath)

        # Should report error
        assert len(findings) > 0, "Should detect empty file"


class TestChatTemplate:
    """Test chat template (CVE-2024-34359) detection."""

    def test_safe_chat_template(self, fixtures_dir):
        """Test that safe chat templates don't trigger alerts."""
        filepath = fixtures_dir / "safe_template.gguf"

        # Create GGUF with a simple chat template
        template = "{{ message }}"

        with open(filepath, "wb") as f:
            # Header
            f.write(struct.pack("<I", 0x46554747))
            f.write(struct.pack("<I", 3))
            f.write(struct.pack("<Q", 0))  # No tensors
            f.write(struct.pack("<Q", 1))  # 1 metadata entry

            # Metadata: tokenizer.chat_template
            key = "tokenizer.chat_template"
            f.write(struct.pack("<Q", len(key)))
            f.write(key.encode())
            f.write(struct.pack("<I", 8))  # STRING type
            f.write(struct.pack("<Q", len(template)))
            f.write(template.encode())

        findings = scan_gguf(filepath)

        # Should note template presence (INFO) but no critical findings
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0, "Safe template should not trigger critical alert"

    def test_malicious_chat_template(self, fixtures_dir):
        """Test detection of malicious Jinja template."""
        filepath = fixtures_dir / "malicious_template.gguf"

        # Template with Jinja injection attempt
        template = "{{ self.__class__.__mro__[2].__subclasses__() }}"

        with open(filepath, "wb") as f:
            f.write(struct.pack("<I", 0x46554747))
            f.write(struct.pack("<I", 3))
            f.write(struct.pack("<Q", 0))
            f.write(struct.pack("<Q", 1))

            key = "tokenizer.chat_template"
            f.write(struct.pack("<Q", len(key)))
            f.write(key.encode())
            f.write(struct.pack("<I", 8))
            f.write(struct.pack("<Q", len(template)))
            f.write(template.encode())

        findings = scan_gguf(filepath)

        # Should detect injection attempt
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) > 0, "Should detect Jinja injection attempt"

        # Should mention CVE
        cve_findings = [f for f in findings if f.details and f.details.get("cve") == "CVE-2024-34359"]
        assert len(cve_findings) > 0, "Should reference CVE-2024-34359"
