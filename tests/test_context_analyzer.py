"""Tests for the context analyzer module."""

from pathlib import Path

from tensortrap.scanner.context_analyzer import (
    ConfidenceLevel,
    ContextAnalysisResult,
    ContextAnalyzer,
    analyze_finding_context,
)


class TestConfidenceLevel:
    """Tests for confidence level classification."""

    def test_confidence_levels(self):
        """Verify confidence level enum values."""
        assert ConfidenceLevel.HIGH.value == "HIGH"
        assert ConfidenceLevel.MEDIUM.value == "MEDIUM"
        assert ConfidenceLevel.LOW.value == "LOW"


class TestContextAnalysisResult:
    """Tests for context analysis result creation."""

    def test_from_score_high(self):
        """High confidence score creates HIGH level result."""
        result = ContextAnalysisResult.from_score(
            score=0.95,
            original_severity="CRITICAL",
            reasons=["test reason"],
        )

        assert result.confidence_level == ConfidenceLevel.HIGH
        assert result.adjusted_severity == "CRITICAL-HIGH"
        assert "QUARANTINE" in result.recommended_action
        assert result.confidence_score == 0.95

    def test_from_score_medium(self):
        """Medium confidence score creates MEDIUM level result."""
        result = ContextAnalysisResult.from_score(
            score=0.7,
            original_severity="CRITICAL",
            reasons=["test reason"],
        )

        assert result.confidence_level == ConfidenceLevel.MEDIUM
        assert result.adjusted_severity == "CRITICAL-MEDIUM"
        assert "INVESTIGATE" in result.recommended_action

    def test_from_score_low(self):
        """Low confidence score creates LOW level result."""
        result = ContextAnalysisResult.from_score(
            score=0.2,
            original_severity="CRITICAL",
            reasons=["test reason"],
        )

        assert result.confidence_level == ConfidenceLevel.LOW
        assert result.adjusted_severity == "CRITICAL-LOW"
        assert "REVIEW" in result.recommended_action

    def test_to_dict(self):
        """Result serializes to dictionary correctly."""
        result = ContextAnalysisResult.from_score(
            score=0.85,
            original_severity="HIGH",
            reasons=["reason1", "reason2"],
            context_data={"key": "value"},
        )

        d = result.to_dict()

        assert d["confidence_score"] == 0.85
        assert d["confidence_level"] == "MEDIUM"
        assert d["confidence_percent"] == "85%"
        assert d["reasons"] == ["reason1", "reason2"]
        assert d["adjusted_severity"] == "HIGH-MEDIUM"
        assert d["context_data"] == {"key": "value"}


class TestContextAnalyzer:
    """Tests for the context analyzer."""

    def test_entropy_calculation(self):
        """Entropy calculation works correctly."""
        analyzer = ContextAnalyzer()

        # Uniform data has low entropy
        uniform = bytes([0] * 1024)
        entropy = analyzer._calculate_entropy(uniform)
        assert entropy == 0.0

        # Random-ish data has higher entropy
        varied = bytes(range(256)) * 4
        entropy = analyzer._calculate_entropy(varied)
        assert entropy == 8.0  # Maximum entropy

    def test_high_entropy_reduces_confidence(self, tmp_path):
        """High entropy region reduces confidence score."""
        analyzer = ContextAnalyzer(entropy_threshold=7.0)

        # Create high-entropy data (compressed-like)
        high_entropy_data = bytes(range(256)) * 100

        result = analyzer.analyze(
            file_data=high_entropy_data,
            match_offset=500,
            pattern_name="test_pattern",
            file_format="image",
            original_severity="CRITICAL",
        )

        # High entropy should reduce confidence
        assert result.confidence_score < 0.5
        assert any("entropy" in r.lower() for r in result.reasons)

    def test_ai_metadata_detection(self):
        """AI generation metadata is detected."""
        analyzer = ContextAnalyzer()

        # Create data with ComfyUI signature
        data_with_ai = b"\x00" * 100 + b"ComfyUI" + b"\x00" * 100

        result = analyzer._detect_ai_metadata(data_with_ai)
        assert result is True

        # Data without AI signatures
        plain_data = b"Hello world, this is just text" * 100
        result = analyzer._detect_ai_metadata(plain_data)
        assert result is False

    def test_ai_metadata_reduces_confidence(self):
        """AI metadata detection reduces confidence."""
        analyzer = ContextAnalyzer()

        # Image with ComfyUI metadata
        ai_image_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100 + b"ComfyUI workflow" + b"\x00" * 1000

        result = analyzer.analyze(
            file_data=ai_image_data,
            match_offset=150,
            pattern_name="asp_code",
            file_format="image",
            original_severity="CRITICAL",
        )

        # Should have low confidence due to AI metadata
        assert result.confidence_level == ConfidenceLevel.LOW
        assert any("AI" in r for r in result.reasons)

    def test_archive_validation_valid_zip(self):
        """Valid ZIP structure is recognized."""
        analyzer = ContextAnalyzer()

        # Minimal valid ZIP structure
        zip_data = (
            b"PK\x03\x04"  # Local file header signature
            b"\x14\x00"  # Version needed
            b"\x00\x00"  # Flags
            b"\x08\x00"  # Compression method (deflate)
            b"\x00\x00\x00\x00"  # Mod time/date
            b"\x00\x00\x00\x00"  # CRC-32
            b"\x00\x00\x00\x00"  # Compressed size
            b"\x00\x00\x00\x00"  # Uncompressed size
            b"\x08\x00"  # Filename length = 8
            b"\x00\x00"  # Extra field length
            b"test.txt"  # Filename
            + b"\x00" * 100  # Some data
            + b"PK\x05\x06"  # End of central directory
            + b"\x00" * 18
        )

        result = analyzer._validate_archive_structure(zip_data, 0)

        assert result["is_valid"] is True
        assert result["type"] == "ZIP"

    def test_archive_validation_invalid_zip(self):
        """Invalid ZIP structure is rejected."""
        analyzer = ContextAnalyzer()

        # ZIP signature but invalid header
        invalid_zip = (
            b"PK\x03\x04"
            b"\xff\xff" + b"\x00" * 24  # Invalid version (>100)
        )

        result = analyzer._validate_archive_structure(invalid_zip, 0)

        assert result["is_valid"] is False
        assert "implausible" in result["reason"]

    def test_executable_patterns_detected(self):
        """Executable code patterns are detected."""
        analyzer = ContextAnalyzer()

        # Data with PHP code
        data = b"\x00" * 100 + b"<?php system($_GET['cmd']); ?>" + b"\x00" * 100

        result = analyzer._check_code_structure_context(
            data, 120, pattern_name="php_code", is_high_entropy=False
        )

        assert result["has_code_structure"] is True
        assert len(result["patterns_found"]) > 0

    def test_executable_patterns_increase_confidence(self):
        """Executable patterns increase confidence score."""
        analyzer = ContextAnalyzer()

        # Data with executable code near match
        data = b"<%\x00response.write('evil')\x00%>" + b"\x00" * 500

        result = analyzer.analyze(
            file_data=data,
            match_offset=0,
            pattern_name="asp_code",
            file_format="unknown",
            original_severity="CRITICAL",
        )

        assert result.confidence_score >= 0.5  # Should be elevated

    def test_caching(self):
        """AI metadata detection is cached."""
        analyzer = ContextAnalyzer()

        data = b"ComfyUI workflow data" + b"\x00" * 1000
        filepath = Path("/test/file.png")

        # First call
        _result1 = analyzer.analyze(
            file_data=data,
            match_offset=50,
            pattern_name="test",
            file_format="image",
            original_severity="CRITICAL",
            filepath=filepath,
        )

        # Second call should use cache
        _result2 = analyzer.analyze(
            file_data=data,
            match_offset=100,
            pattern_name="test",
            file_format="image",
            original_severity="CRITICAL",
            filepath=filepath,
        )

        # Cache should exist
        assert str(filepath) in analyzer._ai_metadata_cache

        # Clear cache
        analyzer.clear_cache()
        assert len(analyzer._ai_metadata_cache) == 0


class TestConvenienceFunction:
    """Tests for the analyze_finding_context convenience function."""

    def test_analyze_finding_context(self):
        """Convenience function works correctly."""
        data = b"\x00" * 1000

        result = analyze_finding_context(
            file_data=data,
            match_offset=500,
            pattern_name="test_pattern",
            file_format="image",
            original_severity="HIGH",
        )

        assert isinstance(result, ContextAnalysisResult)
        assert result.adjusted_severity.startswith("HIGH-")

    def test_with_custom_analyzer(self):
        """Custom analyzer can be passed."""
        data = b"\x00" * 1000
        custom_analyzer = ContextAnalyzer(entropy_threshold=5.0)

        result = analyze_finding_context(
            file_data=data,
            match_offset=500,
            pattern_name="test",
            file_format="unknown",
            original_severity="CRITICAL",
            analyzer=custom_analyzer,
        )

        assert isinstance(result, ContextAnalysisResult)
