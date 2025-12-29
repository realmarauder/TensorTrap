"""Scanner modules for different model file formats.

Enhanced with multi-tier context analysis for reduced false positives.

Architecture:
    Tier 1: Pattern Detection (existing scanners)
        - Flags ALL potential threats
        - Maintains high sensitivity

    Tier 2: Context Analysis (context_analyzer.py)
        - Entropy analysis (compressed regions)
        - Archive structure validation
        - AI metadata detection
        - Executable context checking
        - Outputs: CRITICAL-HIGH/MEDIUM/LOW

    Tier 3: External Validation (external_validators.py)
        - exiftool for metadata confirmation
        - binwalk for archive confirmation
        - Optional, graceful degradation
"""

# Context Analysis (Tier 2)
from tensortrap.scanner.context_analyzer import (
    ConfidenceLevel,
    ContextAnalysisResult,
    ContextAnalyzer,
    analyze_finding_context,
)
from tensortrap.scanner.engine import scan_directory, scan_file

# External Validation (Tier 3)
from tensortrap.scanner.external_validators import (
    BinwalkValidator,
    ExiftoolValidator,
    ExternalValidationResult,
    ExternalValidationRunner,
    ExternalValidationStatus,
)
from tensortrap.scanner.results import Finding, ScanResult, Severity

__all__ = [
    # Core scanning
    "scan_file",
    "scan_directory",
    "Finding",
    "ScanResult",
    "Severity",
    # Context Analysis
    "ContextAnalyzer",
    "ContextAnalysisResult",
    "ConfidenceLevel",
    "analyze_finding_context",
    # External Validation
    "ExternalValidationRunner",
    "ExternalValidationResult",
    "ExternalValidationStatus",
    "ExiftoolValidator",
    "BinwalkValidator",
]
