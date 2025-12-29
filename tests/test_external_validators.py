"""Tests for the external validators module."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tensortrap.scanner.external_validators import (
    BaseExternalValidator,
    BinwalkValidator,
    ExiftoolValidator,
    ExternalValidationResult,
    ExternalValidationRunner,
    ExternalValidationStatus,
)


class TestExternalValidationStatus:
    """Tests for validation status enum."""

    def test_status_values(self):
        """Verify status enum values."""
        assert ExternalValidationStatus.CONFIRMED.value == "confirmed"
        assert ExternalValidationStatus.NOT_CONFIRMED.value == "not_confirmed"
        assert ExternalValidationStatus.TOOL_UNAVAILABLE.value == "tool_unavailable"
        assert ExternalValidationStatus.VALIDATION_ERROR.value == "validation_error"
        assert ExternalValidationStatus.SKIPPED.value == "skipped"


class TestExternalValidationResult:
    """Tests for validation result dataclass."""

    def test_to_dict(self):
        """Result serializes to dictionary correctly."""
        result = ExternalValidationResult(
            status=ExternalValidationStatus.CONFIRMED,
            tool_name="exiftool",
            tool_available=True,
            details="Found threat in metadata",
            evidence={"field": "value"},
        )

        d = result.to_dict()

        assert d["status"] == "confirmed"
        assert d["tool_name"] == "exiftool"
        assert d["tool_available"] is True
        assert d["details"] == "Found threat in metadata"
        assert d["evidence"] == {"field": "value"}


class TestExiftoolValidator:
    """Tests for the exiftool validator."""

    def test_supported_patterns(self):
        """Validator supports expected patterns."""
        validator = ExiftoolValidator()

        assert validator.can_validate("asp_code")
        assert validator.can_validate("metadata_payload")
        assert validator.can_validate("script_injection")
        assert not validator.can_validate("zip_archive")
        assert not validator.can_validate("embedded_archive")

    def test_unavailable_tool(self):
        """Returns correct status when tool not installed."""
        validator = ExiftoolValidator()
        validator._tool_available = False

        result = validator.validate(Path("/test/file.jpg"), "asp")

        assert result.status == ExternalValidationStatus.TOOL_UNAVAILABLE
        assert result.tool_available is False
        assert "exiftool" in result.details.lower()

    def test_file_not_found(self, tmp_path):
        """Returns error when file doesn't exist."""
        validator = ExiftoolValidator()
        validator._tool_available = True

        nonexistent = tmp_path / "nonexistent.jpg"
        result = validator.validate(nonexistent, "asp")

        assert result.status == ExternalValidationStatus.VALIDATION_ERROR
        assert "not found" in result.details.lower()

    @patch("subprocess.run")
    def test_successful_validation_no_threats(self, mock_run, tmp_path):
        """Returns NOT_CONFIRMED when no threats in metadata."""
        validator = ExiftoolValidator()
        validator._tool_available = True

        # Create test file
        test_file = tmp_path / "clean.jpg"
        test_file.write_bytes(b"\xff\xd8\xff" + b"\x00" * 100)

        # Mock exiftool output
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[{"FileName": "clean.jpg", "ImageWidth": 100}]',
        )

        result = validator.validate(test_file, "asp")

        assert result.status == ExternalValidationStatus.NOT_CONFIRMED
        assert result.tool_available is True

    @patch("subprocess.run")
    def test_successful_validation_with_threats(self, mock_run, tmp_path):
        """Returns CONFIRMED when threats found in metadata."""
        validator = ExiftoolValidator()
        validator._tool_available = True

        test_file = tmp_path / "malicious.jpg"
        test_file.write_bytes(b"\xff\xd8\xff" + b"\x00" * 100)

        # Mock exiftool output with malicious content
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[{"FileName": "malicious.jpg", "Comment": "<?php system($_GET[cmd]); ?>"}]',
        )

        result = validator.validate(test_file, "asp")

        assert result.status == ExternalValidationStatus.CONFIRMED
        assert "Comment" in str(result.evidence.get("fields_with_threats", {}))


class TestBinwalkValidator:
    """Tests for the binwalk validator."""

    def test_supported_patterns(self):
        """Validator supports expected patterns."""
        validator = BinwalkValidator()

        assert validator.can_validate("archive_in_image")
        assert validator.can_validate("zip_embedded")
        assert validator.can_validate("polyglot_attack")
        assert not validator.can_validate("asp_code")
        assert not validator.can_validate("script_tag")

    def test_unavailable_tool(self):
        """Returns correct status when tool not installed."""
        validator = BinwalkValidator()
        validator._tool_available = False

        result = validator.validate(Path("/test/file.png"), "archive")

        assert result.status == ExternalValidationStatus.TOOL_UNAVAILABLE
        assert result.tool_available is False

    @patch("subprocess.run")
    def test_no_archives_found(self, mock_run, tmp_path):
        """Returns NOT_CONFIRMED when no archives found."""
        validator = BinwalkValidator()
        validator._tool_available = True

        test_file = tmp_path / "clean.png"
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        # Mock binwalk output with no archives
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="DECIMAL       HEXADECIMAL     DESCRIPTION\n"
            "--------------------------------------------------------------------------------\n",
        )

        result = validator.validate(test_file, "archive")

        assert result.status == ExternalValidationStatus.NOT_CONFIRMED


class TestExternalValidationRunner:
    """Tests for the validation runner orchestrator."""

    def test_disabled_runner(self):
        """Disabled runner returns None."""
        runner = ExternalValidationRunner(enabled=False)

        result = runner.validate_finding(
            filepath=Path("/test/file.jpg"),
            pattern_name="asp",
            confidence_level="HIGH",
        )

        assert result is None

    def test_low_confidence_skipped(self):
        """LOW confidence findings are not validated."""
        runner = ExternalValidationRunner(enabled=True)

        result = runner.validate_finding(
            filepath=Path("/test/file.jpg"),
            pattern_name="asp",
            confidence_level="LOW",
        )

        assert result is None

    def test_get_available_tools(self):
        """Returns tool availability status."""
        runner = ExternalValidationRunner(enabled=True)

        tools = runner.get_available_tools()

        assert "exiftool" in tools
        assert "binwalk" in tools
        assert isinstance(tools["exiftool"], bool)
        assert isinstance(tools["binwalk"], bool)

    def test_validate_findings_batch(self):
        """Batch validation processes multiple findings."""
        runner = ExternalValidationRunner(enabled=False)

        findings = [
            {
                "pattern": "asp",
                "filepath": "/test/file.jpg",
                "context_analysis": {"confidence_level": "HIGH"},
            },
            {
                "pattern": "zip",
                "filepath": "/test/file.png",
                "context_analysis": {"confidence_level": "MEDIUM"},
            },
        ]

        results = runner.validate_findings(findings)

        # When disabled, findings are returned unchanged
        assert len(results) == 2

    def test_finds_appropriate_validator(self):
        """Runner selects correct validator for pattern."""
        runner = ExternalValidationRunner(enabled=True)

        # Both validators should be present
        assert len(runner._validators) == 2

        # Check that patterns are matched correctly
        for validator in runner._validators:
            if validator.name == "exiftool":
                assert validator.can_validate("asp_injection")
            elif validator.name == "binwalk":
                assert validator.can_validate("archive_embedded")
