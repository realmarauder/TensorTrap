"""
TensorTrap Scanner Module

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

from .context_analyzer import (
    ContextAnalyzer,
    ContextAnalysisResult,
    ConfidenceLevel,
    analyze_finding_context,
)

from .external_validators import (
    ExternalValidationRunner,
    ExternalValidationResult,
    ExternalValidationStatus,
    ExiftoolValidator,
    BinwalkValidator,
)

__all__ = [
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
