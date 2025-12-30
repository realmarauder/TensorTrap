"""
External Validators for TensorTrap

Optional Stage 3 validation using external tools (exiftool, binwalk).
These validators provide additional confirmation for findings that passed
context analysis with MEDIUM or HIGH confidence.

Usage:
    - Runs AFTER context_analyzer.py
    - Only processes CRITICAL-MEDIUM and CRITICAL-HIGH findings
    - Gracefully degrades if tools are not installed
    - Can be disabled via CLI flag (--no-external-validation)
"""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ExternalValidationStatus(Enum):
    """Status from external tool validation."""

    CONFIRMED = "confirmed"  # Tool confirmed the threat
    NOT_CONFIRMED = "not_confirmed"  # Tool found no threat
    TOOL_UNAVAILABLE = "tool_unavailable"  # Required tool not installed
    VALIDATION_ERROR = "validation_error"  # Tool failed to run
    SKIPPED = "skipped"  # Validation not applicable


@dataclass
class ExternalValidationResult:
    """Result from external tool validation."""

    status: ExternalValidationStatus
    tool_name: str
    tool_available: bool
    details: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "tool_name": self.tool_name,
            "tool_available": self.tool_available,
            "details": self.details,
            "evidence": self.evidence,
        }


class BaseExternalValidator(ABC):
    """Base class for external tool validators."""

    name: str = "base"
    required_tool: str | None = None
    supported_patterns: list[str] = []

    def __init__(self) -> None:
        self._tool_available: bool | None = None

    @property
    def tool_available(self) -> bool:
        """Check if required tool is installed."""
        if self.required_tool is None:
            return True
        if self._tool_available is None:
            self._tool_available = shutil.which(self.required_tool) is not None
        return self._tool_available

    def can_validate(self, pattern_name: str) -> bool:
        """Check if this validator handles the given pattern."""
        pattern_lower = pattern_name.lower()
        return any(p in pattern_lower for p in self.supported_patterns)

    @abstractmethod
    def validate(
        self,
        filepath: Path,
        pattern_name: str,
        offset: int | None = None,
    ) -> ExternalValidationResult:
        """Run external validation on file."""
        pass

    def _unavailable_result(self) -> ExternalValidationResult:
        """Return result for unavailable tool."""
        install_hints = {
            "exiftool": "sudo apt install libimage-exiftool-perl",
            "binwalk": "sudo apt install binwalk",
            "7z": "sudo apt install p7zip-full",
        }
        hint = install_hints.get(self.required_tool or "", f"install {self.required_tool}")

        return ExternalValidationResult(
            status=ExternalValidationStatus.TOOL_UNAVAILABLE,
            tool_name=self.name,
            tool_available=False,
            details=f"Required tool '{self.required_tool}' not installed. Install with: {hint}",
        )


class ExiftoolValidator(BaseExternalValidator):
    """
    Validates metadata-based findings using exiftool.

    Extracts actual EXIF/XMP/IPTC fields and checks if suspicious
    patterns exist in real metadata vs binary coincidence.
    """

    name = "exiftool"
    required_tool = "exiftool"
    supported_patterns = ["asp", "script", "metadata", "payload", "injection"]

    # Patterns indicating actual executable code
    THREAT_PATTERNS = [
        re.compile(r"<%.*%>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
        re.compile(r"on(?:load|click|error|mouseover)\s*=", re.IGNORECASE),
        re.compile(r"<\?php", re.IGNORECASE),
        re.compile(r"eval\s*\(", re.IGNORECASE),
        re.compile(r"exec\s*\(", re.IGNORECASE),
        re.compile(r"document\.(?:write|cookie)", re.IGNORECASE),
        re.compile(r"window\.location", re.IGNORECASE),
    ]

    # Fields that can contain text
    TEXT_FIELDS = [
        "Comment",
        "UserComment",
        "ImageDescription",
        "Description",
        "Caption-Abstract",
        "Copyright",
        "Artist",
        "Author",
        "Creator",
        "Software",
        "XPComment",
        "XPTitle",
        "Title",
        "Subject",
        "Keywords",
        "Instructions",
        "SpecialInstructions",
        "DocumentNotes",
    ]

    def validate(
        self,
        filepath: Path,
        pattern_name: str,
        offset: int | None = None,
    ) -> ExternalValidationResult:
        """Validate using exiftool metadata extraction."""
        if not self.tool_available:
            return self._unavailable_result()

        if not filepath.exists():
            return ExternalValidationResult(
                status=ExternalValidationStatus.VALIDATION_ERROR,
                tool_name=self.name,
                tool_available=True,
                details=f"File not found: {filepath}",
            )

        try:
            result = subprocess.run(
                ["exiftool", "-json", "-all", "-unknown", str(filepath)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return ExternalValidationResult(
                    status=ExternalValidationStatus.VALIDATION_ERROR,
                    tool_name=self.name,
                    tool_available=True,
                    details=f"exiftool error: {result.stderr[:200]}",
                )

            metadata_list = json.loads(result.stdout)
            if not metadata_list:
                return ExternalValidationResult(
                    status=ExternalValidationStatus.NOT_CONFIRMED,
                    tool_name=self.name,
                    tool_available=True,
                    details="No metadata extracted",
                )

            metadata = metadata_list[0]

        except subprocess.TimeoutExpired:
            return ExternalValidationResult(
                status=ExternalValidationStatus.VALIDATION_ERROR,
                tool_name=self.name,
                tool_available=True,
                details="exiftool timeout",
            )
        except json.JSONDecodeError as e:
            return ExternalValidationResult(
                status=ExternalValidationStatus.VALIDATION_ERROR,
                tool_name=self.name,
                tool_available=True,
                details=f"JSON parse error: {e}",
            )
        except Exception as e:
            return ExternalValidationResult(
                status=ExternalValidationStatus.VALIDATION_ERROR,
                tool_name=self.name,
                tool_available=True,
                details=f"Unexpected error: {e}",
            )

        # Scan text fields for threats
        threats_found: dict[str, list[str]] = {}
        fields_checked = 0

        for field_name, value in metadata.items():
            if not isinstance(value, str):
                continue

            # Check relevant fields
            is_text_field = any(tf.lower() in field_name.lower() for tf in self.TEXT_FIELDS)
            if not is_text_field and len(value) < 100:
                continue

            fields_checked += 1

            for pattern in self.THREAT_PATTERNS:
                if pattern.search(value):
                    if field_name not in threats_found:
                        threats_found[field_name] = []
                    threats_found[field_name].append(pattern.pattern[:40])

        if threats_found:
            return ExternalValidationResult(
                status=ExternalValidationStatus.CONFIRMED,
                tool_name=self.name,
                tool_available=True,
                details=f"Executable patterns in metadata: {', '.join(threats_found.keys())}",
                evidence={
                    "fields_with_threats": threats_found,
                    "fields_checked": fields_checked,
                },
            )
        else:
            return ExternalValidationResult(
                status=ExternalValidationStatus.NOT_CONFIRMED,
                tool_name=self.name,
                tool_available=True,
                details="No executable patterns found in metadata fields",
                evidence={
                    "fields_checked": fields_checked,
                    "metadata_count": len(metadata),
                },
            )


class BinwalkValidator(BaseExternalValidator):
    """
    Validates embedded archive findings using binwalk.

    Confirms if detected archive signatures are actual extractable
    archives or false positives from compressed data.
    """

    name = "binwalk"
    required_tool = "binwalk"
    supported_patterns = ["archive", "zip", "rar", "7z", "embedded", "polyglot"]

    # Real archive signatures
    ARCHIVE_SIGNATURES = [
        "zip archive",
        "rar archive",
        "7-zip archive",
        "gzip compressed",
        "bzip2 compressed",
        "xz compressed",
        "tar archive",
        "cab archive",
    ]

    # False positive signatures
    FALSE_POSITIVES = [
        "stuffit",
        "bix header",
        "qualcomm",
        "intel x86",
        "device tree",
        "copyright",
        "boot sector",
    ]

    def validate(
        self,
        filepath: Path,
        pattern_name: str,
        offset: int | None = None,
    ) -> ExternalValidationResult:
        """Validate using binwalk analysis."""
        if not self.tool_available:
            return self._unavailable_result()

        if not filepath.exists():
            return ExternalValidationResult(
                status=ExternalValidationStatus.VALIDATION_ERROR,
                tool_name=self.name,
                tool_available=True,
                details=f"File not found: {filepath}",
            )

        try:
            # Run binwalk analysis
            result = subprocess.run(
                ["binwalk", "-B", str(filepath)],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Parse output
            entries: list[dict[str, str | int]] = []
            for line in result.stdout.split("\n"):
                if line.startswith("DECIMAL") or line.startswith("-") or not line.strip():
                    continue
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    try:
                        entries.append(
                            {
                                "offset": int(parts[0]),
                                "description": parts[2],
                            }
                        )
                    except ValueError:
                        continue

        except subprocess.TimeoutExpired:
            return ExternalValidationResult(
                status=ExternalValidationStatus.VALIDATION_ERROR,
                tool_name=self.name,
                tool_available=True,
                details="binwalk timeout",
            )
        except Exception as e:
            return ExternalValidationResult(
                status=ExternalValidationStatus.VALIDATION_ERROR,
                tool_name=self.name,
                tool_available=True,
                details=f"binwalk error: {e}",
            )

        # Filter for real archives
        archives = []
        for entry in entries:
            desc = str(entry["description"])
            desc_lower = desc.lower()

            # Skip known false positives
            if any(fp in desc_lower for fp in self.FALSE_POSITIVES):
                continue

            # Check for real signatures
            for sig in self.ARCHIVE_SIGNATURES:
                if sig in desc_lower:
                    archives.append(
                        {
                            "type": sig,
                            "offset": entry["offset"],
                            "description": desc[:100],
                        }
                    )
                    break

        if not archives:
            return ExternalValidationResult(
                status=ExternalValidationStatus.NOT_CONFIRMED,
                tool_name=self.name,
                tool_available=True,
                details="No extractable archives found",
                evidence={
                    "total_signatures": len(entries),
                    "filtered_as_false_positive": len(entries),
                },
            )

        # Attempt extraction to confirm
        extraction = self._attempt_extraction(filepath)

        if extraction["success"]:
            return ExternalValidationResult(
                status=ExternalValidationStatus.CONFIRMED,
                tool_name=self.name,
                tool_available=True,
                details=f"Extractable archive confirmed: {archives[0]['type']}",
                evidence={
                    "archives": archives,
                    "extracted_files": extraction.get("files", []),
                    "total_extracted": extraction.get("count", 0),
                },
            )
        else:
            return ExternalValidationResult(
                status=ExternalValidationStatus.NOT_CONFIRMED,
                tool_name=self.name,
                tool_available=True,
                details=(
                    f"Archive signature found but extraction failed: "
                    f"{extraction.get('error', 'unknown')}"
                ),
                evidence={"archives": archives},
            )

    def _attempt_extraction(self, filepath: Path) -> dict[str, Any]:
        """Attempt to extract archives from file."""
        temp_dir = None
        try:
            temp_dir = tempfile.mkdtemp(prefix="tensortrap_")

            subprocess.run(
                ["binwalk", "-e", "-C", temp_dir, str(filepath)],
                capture_output=True,
                timeout=120,
            )

            # Check what was extracted
            files = []
            count = 0
            for root, dirs, filenames in os.walk(temp_dir):
                for f in filenames:
                    count += 1
                    if count <= 10:
                        files.append(f)

            return {
                "success": count > 0,
                "files": files,
                "count": count,
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "extraction timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


class ExternalValidationRunner:
    """
    Orchestrates external validation on findings.

    Runs appropriate external validators on CRITICAL-MEDIUM and
    CRITICAL-HIGH findings to provide additional confirmation.
    """

    def __init__(self, enabled: bool = True):
        """
        Initialize the validation runner.

        Args:
            enabled: Whether external validation is enabled
        """
        self.enabled = enabled
        self._validators: list[BaseExternalValidator] = [
            ExiftoolValidator(),
            BinwalkValidator(),
        ]

    def get_available_tools(self) -> dict[str, bool]:
        """Get availability status of external tools."""
        return {v.name: v.tool_available for v in self._validators}

    def validate_finding(
        self,
        filepath: Path,
        pattern_name: str,
        confidence_level: str,
        offset: int | None = None,
    ) -> ExternalValidationResult | None:
        """
        Validate a single finding with appropriate external tool.

        Args:
            filepath: Path to file
            pattern_name: Pattern that was matched
            confidence_level: Confidence level from context analyzer
            offset: Optional byte offset

        Returns:
            ExternalValidationResult or None if no validator available
        """
        if not self.enabled:
            return None

        # Only validate MEDIUM and HIGH confidence
        if confidence_level.upper() not in ["MEDIUM", "HIGH"]:
            return None

        # Find appropriate validator
        for validator in self._validators:
            if validator.can_validate(pattern_name):
                return validator.validate(filepath, pattern_name, offset)

        return None

    def validate_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Validate multiple findings and update with results.

        Args:
            findings: List of finding dictionaries

        Returns:
            Updated findings with external_validation field
        """
        if not self.enabled:
            return findings

        updated = []
        for finding in findings:
            filepath = Path(finding.get("filepath", ""))
            pattern = finding.get("pattern", finding.get("pattern_name", ""))
            confidence = finding.get("context_analysis", {}).get("confidence_level", "LOW")
            offset = finding.get("offset")

            result = self.validate_finding(filepath, pattern, confidence, offset)

            finding_copy = dict(finding)
            if result:
                finding_copy["external_validation"] = result.to_dict()

                # Update severity if external validation disagrees
                if result.status == ExternalValidationStatus.NOT_CONFIRMED:
                    # Downgrade to LOW if external tool found nothing
                    if "adjusted_severity" in finding_copy:
                        orig = finding_copy["adjusted_severity"]
                        finding_copy["adjusted_severity"] = orig.replace("-HIGH", "-LOW").replace(
                            "-MEDIUM", "-LOW"
                        )
                        finding_copy["external_override"] = True

            updated.append(finding_copy)

        return updated
