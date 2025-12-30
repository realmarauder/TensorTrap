"""
Context Analyzer for TensorTrap

Multi-tier context analysis system that reduces false positive noise while
maintaining threat detection capability. Runs during scanning to provide
confidence scoring for pattern matches.

Architecture:
    Tier 1: Pattern Detection (existing scanners) - flags ALL potential threats
    Tier 2: Context Analysis (this module) - analyzes context around matches
    Tier 3: Confidence Scoring - outputs CRITICAL-HIGH/MEDIUM/LOW ratings

This module does NOT reduce detection sensitivity. It adds intelligence
to classify findings by confidence level.
"""

import logging
import math
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    """Confidence level for threat classification."""

    HIGH = "HIGH"  # 90%+ confidence - likely real threat
    MEDIUM = "MEDIUM"  # 50-90% confidence - needs investigation
    LOW = "LOW"  # <50% confidence - probable false positive


@dataclass
class ContextAnalysisResult:
    """
    Result of context analysis for a single finding.

    Attributes:
        confidence_score: Float 0.0-1.0 (0=definitely FP, 1=definitely threat)
        confidence_level: Categorical HIGH/MEDIUM/LOW
        reasons: List of reasons affecting the score
        adjusted_severity: Original severity with confidence suffix
        recommended_action: What the user should do
        context_data: Additional context information
    """

    confidence_score: float
    confidence_level: ConfidenceLevel
    reasons: list[str]
    adjusted_severity: str
    recommended_action: str
    context_data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_score(
        cls,
        score: float,
        original_severity: str,
        reasons: list[str],
        context_data: dict[str, Any] | None = None,
    ) -> "ContextAnalysisResult":
        """Create result from confidence score."""
        if score >= 0.9:
            level = ConfidenceLevel.HIGH
            action = "QUARANTINE - Isolate this file immediately"
        elif score >= 0.5:
            level = ConfidenceLevel.MEDIUM
            action = "INVESTIGATE - Manual review recommended"
        else:
            level = ConfidenceLevel.LOW
            action = "REVIEW - Likely false positive, verify if concerned"

        adjusted = f"{original_severity}-{level.value}"

        return cls(
            confidence_score=score,
            confidence_level=level,
            reasons=reasons,
            adjusted_severity=adjusted,
            recommended_action=action,
            context_data=context_data or {},
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "confidence_score": round(self.confidence_score, 3),
            "confidence_level": self.confidence_level.value,
            "confidence_percent": f"{int(self.confidence_score * 100)}%",
            "reasons": self.reasons,
            "adjusted_severity": self.adjusted_severity,
            "recommended_action": self.recommended_action,
            "context_data": self.context_data,
        }


class ContextAnalyzer:
    """
    Analyzes context around pattern matches to score confidence.

    This class provides the core context analysis without external tool
    dependencies. It uses entropy analysis, structure validation, and
    metadata pattern detection to classify findings.
    """

    # Entropy threshold - above this is likely compressed/encrypted data
    DEFAULT_ENTROPY_THRESHOLD = 7.0

    # Context window size for entropy calculation
    DEFAULT_CONTEXT_WINDOW = 1024

    # AI generation tool signatures
    AI_METADATA_SIGNATURES = [
        # ComfyUI
        b"ComfyUI",
        b"class_type",
        b"KSampler",
        b"CLIPTextEncode",
        b"VAEDecode",
        b"CheckpointLoaderSimple",
        b"LoraLoader",
        b"ControlNetApply",
        # Stable Diffusion / Automatic1111
        b"Stable Diffusion",
        b"sd-webui",
        b"AUTOMATIC1111",
        b"txt2img",
        b"img2img",
        b"hires fix",
        # InvokeAI
        b"InvokeAI",
        b"invokeai",
        # Topaz
        b"Topaz",
        b"Topaz Photo AI",
        b"Topaz Video AI",
        b"Topaz Gigapixel",
        # Midjourney (in metadata)
        b"Midjourney",
        b"mj::",
        # DALL-E
        b"DALL-E",
        b"dalle",
        # Generic
        b"diffusion",
        b"sampler",
        b"CFG Scale",
        b"cfg_scale",
        b"negative_prompt",
    ]

    # EXIF field patterns that indicate AI generation
    AI_EXIF_PATTERNS = [
        re.compile(rb"(?:prompt|workflow|parameters)\s*[:=]", re.IGNORECASE),
        re.compile(rb"Steps:\s*\d+", re.IGNORECASE),
        re.compile(rb"Sampler:\s*\w+", re.IGNORECASE),
        re.compile(rb"CFG\s*(?:scale)?:\s*[\d.]+", re.IGNORECASE),
        re.compile(rb"Seed:\s*\d+", re.IGNORECASE),
        re.compile(rb"Model:\s*\w+", re.IGNORECASE),
    ]

    # Executable code patterns that increase confidence
    EXECUTABLE_PATTERNS = [
        # ASP/VBScript with actual code
        re.compile(rb"<%\s*(?:response|request|server|session)\.", re.IGNORECASE),
        re.compile(rb"<%\s*(?:dim|set|if|for|while|function|sub)\s", re.IGNORECASE),
        re.compile(rb"CreateObject\s*\(", re.IGNORECASE),
        re.compile(rb"WScript\.Shell", re.IGNORECASE),
        # PHP
        re.compile(rb"<\?php\s", re.IGNORECASE),
        re.compile(rb"\$_(?:GET|POST|REQUEST|SERVER|FILES)\[", re.IGNORECASE),
        re.compile(rb"(?:eval|exec|system|passthru|shell_exec)\s*\(", re.IGNORECASE),
        # JavaScript in non-JS context
        re.compile(rb"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
        re.compile(rb"javascript\s*:", re.IGNORECASE),
        # Shell
        re.compile(rb"(?:^|[;&|`])\s*(?:bash|sh|cmd|powershell)\s", re.IGNORECASE),
        re.compile(rb"/bin/(?:ba)?sh", re.IGNORECASE),
        # Python
        re.compile(rb"import\s+(?:os|subprocess|socket|sys)\b", re.IGNORECASE),
        re.compile(rb"__import__\s*\(", re.IGNORECASE),
    ]

    def __init__(
        self,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
        context_window: int = DEFAULT_CONTEXT_WINDOW,
    ):
        """
        Initialize the context analyzer.

        Args:
            entropy_threshold: Entropy above this = compressed data (default 7.0)
            context_window: Bytes to analyze around match (default 1024)
        """
        self.entropy_threshold = entropy_threshold
        self.context_window = context_window
        self._ai_metadata_cache: dict[str, bool] = {}

    def analyze(
        self,
        file_data: bytes,
        match_offset: int,
        pattern_name: str,
        file_format: str,
        original_severity: str,
        filepath: Path | None = None,
    ) -> ContextAnalysisResult:
        """
        Analyze context of a pattern match and return confidence scoring.

        Args:
            file_data: Full file content as bytes
            match_offset: Byte offset where pattern was found
            pattern_name: Name of the pattern that matched
            file_format: File format (image, video, etc.)
            original_severity: Original severity from scanner
            filepath: Optional path for caching

        Returns:
            ContextAnalysisResult with confidence scoring
        """
        confidence = 0.5  # Start at medium confidence
        reasons: list[str] = []
        context_data: dict[str, Any] = {
            "pattern": pattern_name,
            "offset": match_offset,
            "file_format": file_format,
        }

        # === ANALYSIS 1: Entropy Check ===
        entropy_result = self._analyze_entropy(file_data, match_offset)
        context_data["entropy"] = entropy_result

        if entropy_result["is_compressed"]:
            confidence *= 0.2
            reasons.append(
                f"pattern in high-entropy region ({entropy_result['entropy']:.2f} bits/byte)"
            )

        # === ANALYSIS 2: Archive Structure Validation ===
        if self._is_archive_pattern(pattern_name):
            archive_result = self._validate_archive_structure(file_data, match_offset)
            context_data["archive_validation"] = archive_result

            if archive_result["is_valid"]:
                confidence = max(confidence, 0.9)
                reasons.append(f"valid {archive_result['type']} archive structure confirmed")
            else:
                confidence *= 0.1
                reasons.append(f"invalid archive structure - {archive_result['reason']}")

        # === ANALYSIS 3: Executable Context ===
        exec_result = self._check_executable_context(file_data, match_offset)
        context_data["executable_context"] = exec_result

        if exec_result["has_executable"]:
            confidence = max(confidence, 0.9)
            reasons.append(f"executable code patterns nearby: {', '.join(exec_result['patterns'])}")

        # === ANALYSIS 4: AI Generation Metadata ===
        if file_format in ["image", "video"]:
            cache_key = str(filepath) if filepath else str(id(file_data))

            if cache_key in self._ai_metadata_cache:
                has_ai = self._ai_metadata_cache[cache_key]
            else:
                has_ai = self._detect_ai_metadata(file_data)
                self._ai_metadata_cache[cache_key] = has_ai

            context_data["ai_metadata_detected"] = has_ai

            if has_ai:
                confidence *= 0.15
                reasons.append("AI generation metadata detected (ComfyUI/SD/Topaz)")

        # === ANALYSIS 5: Pattern-Specific Checks ===
        pattern_result = self._pattern_specific_analysis(file_data, match_offset, pattern_name)
        if pattern_result:
            context_data["pattern_analysis"] = pattern_result
            if pattern_result.get("confidence_modifier"):
                confidence *= pattern_result["confidence_modifier"]
            if pattern_result.get("reason"):
                reasons.append(pattern_result["reason"])

        # Clamp confidence to valid range
        confidence = max(0.0, min(1.0, confidence))

        # Generate result
        if not reasons:
            reasons.append("default scoring applied")

        return ContextAnalysisResult.from_score(
            score=confidence,
            original_severity=original_severity,
            reasons=reasons,
            context_data=context_data,
        )

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of byte sequence.

        Args:
            data: Byte sequence to analyze

        Returns:
            Entropy in bits per byte (0.0 to 8.0)
        """
        if not data:
            return 0.0

        # Count byte frequencies
        frequencies = [0] * 256
        for byte in data:
            frequencies[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for freq in frequencies:
            if freq > 0:
                probability = freq / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    def _analyze_entropy(
        self,
        data: bytes,
        offset: int,
    ) -> dict[str, Any]:
        """
        Analyze entropy around the match offset.

        Args:
            data: Full file data
            offset: Match offset

        Returns:
            Dictionary with entropy analysis results
        """
        half_window = self.context_window // 2
        start = max(0, offset - half_window)
        end = min(len(data), offset + half_window)
        chunk = data[start:end]

        entropy = self._calculate_entropy(chunk)
        is_compressed = entropy > self.entropy_threshold

        return {
            "entropy": entropy,
            "threshold": self.entropy_threshold,
            "is_compressed": is_compressed,
            "window_start": start,
            "window_end": end,
            "window_size": len(chunk),
        }

    def _is_archive_pattern(self, pattern_name: str) -> bool:
        """Check if pattern relates to embedded archives."""
        archive_keywords = [
            "archive",
            "zip",
            "rar",
            "7z",
            "tar",
            "gz",
            "cab",
            "embedded",
            "polyglot",
        ]
        pattern_lower = pattern_name.lower()
        return any(kw in pattern_lower for kw in archive_keywords)

    def _validate_archive_structure(
        self,
        data: bytes,
        offset: int,
    ) -> dict[str, Any]:
        """
        Validate if archive signature is part of valid structure.

        Args:
            data: Full file data
            offset: Offset of suspected archive

        Returns:
            Dictionary with validation results
        """
        result: dict[str, Any] = {
            "is_valid": False,
            "type": None,
            "reason": "unknown format",
        }

        if offset >= len(data):
            result["reason"] = "offset beyond file end"
            return result

        remaining = data[offset:]

        # Check ZIP
        if remaining[:4] == b"PK\x03\x04":
            result["type"] = "ZIP"
            zip_valid = self._validate_zip_structure(remaining)
            result["is_valid"] = zip_valid["is_valid"]
            result["reason"] = zip_valid["reason"]
            result.update(zip_valid.get("details", {}))
            return result

        # Check RAR
        if remaining[:7] == b"Rar!\x1a\x07\x00" or remaining[:8] == b"Rar!\x1a\x07\x01\x00":
            result["type"] = "RAR"
            result["is_valid"] = True
            result["reason"] = "valid RAR signature"
            return result

        # Check 7z
        if remaining[:6] == b"7z\xbc\xaf\x27\x1c":
            result["type"] = "7z"
            result["is_valid"] = True
            result["reason"] = "valid 7z signature"
            return result

        # Check GZIP
        if remaining[:2] == b"\x1f\x8b":
            result["type"] = "GZIP"
            if len(remaining) >= 10:
                result["is_valid"] = True
                result["reason"] = "valid GZIP header"
            else:
                result["reason"] = "incomplete GZIP header"
            return result

        result["reason"] = "no recognized archive signature at offset"
        return result

    def _validate_zip_structure(self, data: bytes) -> dict[str, Any]:
        """
        Validate ZIP local file header structure.

        Args:
            data: Data starting at ZIP signature

        Returns:
            Dictionary with validation result
        """
        result: dict[str, Any] = {"is_valid": False, "reason": "", "details": {}}

        # ZIP local file header minimum: 30 bytes
        if len(data) < 30:
            result["reason"] = "insufficient data for ZIP header"
            return result

        try:
            # Parse local file header
            signature = data[0:4]
            if signature != b"PK\x03\x04":
                result["reason"] = "invalid ZIP signature"
                return result

            version = struct.unpack("<H", data[4:6])[0]
            compression = struct.unpack("<H", data[8:10])[0]
            filename_len = struct.unpack("<H", data[26:28])[0]
            extra_len = struct.unpack("<H", data[28:30])[0]
            compressed_size = struct.unpack("<I", data[18:22])[0]

            result["details"] = {
                "version": version,
                "compression": compression,
                "filename_len": filename_len,
                "compressed_size": compressed_size,
            }

            # Sanity checks
            if version > 100:
                result["reason"] = f"implausible version: {version}"
                return result

            if compression > 99:
                result["reason"] = f"invalid compression method: {compression}"
                return result

            if filename_len > 1024:
                result["reason"] = f"implausible filename length: {filename_len}"
                return result

            if extra_len > 65535:
                result["reason"] = f"implausible extra field length: {extra_len}"
                return result

            # Check if filename is present and readable
            header_end = 30 + filename_len + extra_len
            if len(data) < header_end:
                result["reason"] = "incomplete header"
                return result

            filename = data[30 : 30 + filename_len]
            try:
                filename_str = filename.decode("utf-8", errors="strict")
                result["details"]["filename"] = filename_str
            except UnicodeDecodeError:
                try:
                    filename_str = filename.decode("cp437", errors="strict")
                    result["details"]["filename"] = filename_str
                except UnicodeDecodeError:
                    result["reason"] = "filename not valid UTF-8 or CP437"
                    return result

            # Look for end of central directory
            eocd_sig = b"PK\x05\x06"
            if eocd_sig in data:
                result["details"]["has_eocd"] = True
                result["is_valid"] = True
                result["reason"] = "complete ZIP structure with EOCD"
            else:
                # Partial ZIP might still be valid
                result["is_valid"] = True
                result["reason"] = "valid local file header (EOCD not found in visible data)"

            return result

        except struct.error as e:
            result["reason"] = f"struct parse error: {e}"
            return result

    def _check_executable_context(
        self,
        data: bytes,
        offset: int,
        window: int = 2048,
    ) -> dict[str, Any]:
        """
        Check for executable code patterns near the match.

        Args:
            data: Full file data
            offset: Match offset
            window: Bytes to check around offset

        Returns:
            Dictionary with executable context analysis
        """
        half_window = window // 2
        start = max(0, offset - half_window)
        end = min(len(data), offset + half_window)
        chunk = data[start:end]

        matched_patterns = []
        for pattern in self.EXECUTABLE_PATTERNS:
            if pattern.search(chunk):
                # Extract pattern name from regex
                pattern_str = (
                    pattern.pattern.decode()
                    if isinstance(pattern.pattern, bytes)
                    else pattern.pattern
                )
                matched_patterns.append(pattern_str[:50])

        return {
            "has_executable": len(matched_patterns) > 0,
            "patterns": matched_patterns[:5],  # Limit to first 5
            "window_size": len(chunk),
        }

    def _detect_ai_metadata(self, data: bytes) -> bool:
        """
        Detect AI generation tool metadata in file.

        Args:
            data: Full file data

        Returns:
            True if AI generation metadata detected
        """
        # Check first 64KB for signatures (metadata is usually near start)
        check_region = data[:65536]

        # Check for known signatures
        for sig in self.AI_METADATA_SIGNATURES:
            if sig in check_region:
                return True

        # Check for EXIF patterns
        for pattern in self.AI_EXIF_PATTERNS:
            if pattern.search(check_region):
                return True

        return False

    def _pattern_specific_analysis(
        self,
        data: bytes,
        offset: int,
        pattern_name: str,
    ) -> dict[str, Any] | None:
        """
        Perform pattern-specific additional analysis.

        Args:
            data: Full file data
            offset: Match offset
            pattern_name: Name of matched pattern

        Returns:
            Optional dictionary with analysis results
        """
        pattern_lower = pattern_name.lower()

        # ASP patterns - check if it looks like actual ASP code
        if "asp" in pattern_lower:
            # Get context around match
            start = max(0, offset - 50)
            end = min(len(data), offset + 200)
            context = data[start:end]

            # Look for ASP code structure
            asp_code_indicators = [
                b"response.write",
                b"request(",
                b"request.form",
                b"request.querystring",
                b"server.execute",
                b"server.transfer",
                b"session(",
                b"application(",
                b"%>",  # Closing tag
            ]

            found_indicators = sum(1 for ind in asp_code_indicators if ind in context.lower())

            if found_indicators >= 2:
                return {
                    "confidence_modifier": 2.0,  # Increase confidence
                    "reason": f"ASP code structure detected ({found_indicators} indicators)",
                }
            elif found_indicators == 0:
                return {
                    "confidence_modifier": 0.3,
                    "reason": "ASP pattern without code structure",
                }

        return None

    def clear_cache(self) -> None:
        """Clear the AI metadata detection cache."""
        self._ai_metadata_cache.clear()


# Convenience function for scanner integration
def analyze_finding_context(
    file_data: bytes,
    match_offset: int,
    pattern_name: str,
    file_format: str,
    original_severity: str,
    filepath: Path | None = None,
    analyzer: ContextAnalyzer | None = None,
) -> ContextAnalysisResult:
    """
    Convenience function to analyze a finding's context.

    Args:
        file_data: Full file content
        match_offset: Offset where pattern was found
        pattern_name: Name of matched pattern
        file_format: File format type
        original_severity: Original severity from scanner
        filepath: Optional file path
        analyzer: Optional ContextAnalyzer instance (creates new if None)

    Returns:
        ContextAnalysisResult with confidence scoring
    """
    if analyzer is None:
        analyzer = ContextAnalyzer()

    return analyzer.analyze(
        file_data=file_data,
        match_offset=match_offset,
        pattern_name=pattern_name,
        file_format=file_format,
        original_severity=original_severity,
        filepath=filepath,
    )
