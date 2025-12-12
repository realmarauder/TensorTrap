"""Result data structures for scan findings."""

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A single security finding from a scan."""

    severity: Severity
    message: str
    location: int | None = None  # Byte offset in file
    details: dict | None = None
    recommendation: str | None = None  # Remediation advice

    def to_dict(self) -> dict:
        """Convert finding to dictionary."""
        return {
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location,
            "details": self.details,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanResult:
    """Complete result of scanning a single file."""

    filepath: Path
    format: str  # "pickle", "safetensors", "gguf", "unknown"
    findings: list[Finding] = field(default_factory=list)
    scan_time_ms: float = 0.0
    file_size: int = 0
    file_hash: str = ""  # SHA-256

    @property
    def is_safe(self) -> bool:
        """Check if the file is considered safe (no critical/high findings)."""
        return not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    @property
    def max_severity(self) -> Severity | None:
        """Get the highest severity finding."""
        if not self.findings:
            return None
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for sev in severity_order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    def to_dict(self) -> dict:
        """Convert scan result to dictionary."""
        return {
            "filepath": str(self.filepath),
            "format": self.format,
            "is_safe": self.is_safe,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [f.to_dict() for f in self.findings],
            "scan_time_ms": self.scan_time_ms,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
        }

    def to_json(self) -> str:
        """Convert scan result to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
