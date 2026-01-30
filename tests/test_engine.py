"""Tests for scanning engine."""

from tensortrap.scanner.engine import scan_directory, scan_file
from tensortrap.scanner.results import Severity


class TestScanFile:
    """Test single file scanning."""

    def test_scan_pickle_file(self, safe_pickle_file):
        """Test scanning a pickle file."""
        result = scan_file(safe_pickle_file, compute_hash=True)

        assert result.filepath == safe_pickle_file
        assert result.format == "pickle"
        assert result.file_size > 0
        assert result.file_hash != ""
        assert result.scan_time_ms > 0

    def test_scan_safetensors_file(self, valid_safetensors_file):
        """Test scanning a safetensors file."""
        result = scan_file(valid_safetensors_file)

        assert result.filepath == valid_safetensors_file
        assert result.format == "safetensors"
        assert result.is_safe

    def test_scan_gguf_file(self, valid_gguf_file):
        """Test scanning a GGUF file."""
        result = scan_file(valid_gguf_file)

        assert result.filepath == valid_gguf_file
        assert result.format == "gguf"
        assert result.is_safe

    def test_scan_nonexistent_file(self, fixtures_dir):
        """Test scanning a file that doesn't exist."""
        result = scan_file(fixtures_dir / "nonexistent.pkl")

        assert result.format == "unknown"
        assert len(result.findings) > 0
        assert "not found" in result.findings[0].message.lower()

    def test_scan_without_hash(self, safe_pickle_file):
        """Test scanning without computing hash."""
        result = scan_file(safe_pickle_file, compute_hash=False)

        assert result.file_hash == ""

    def test_is_safe_property(self, safe_pickle_file, simple_malicious_pickle_file):
        """Test is_safe property."""
        safe_result = scan_file(safe_pickle_file)
        assert safe_result.is_safe

        malicious_result = scan_file(simple_malicious_pickle_file)
        assert not malicious_result.is_safe

    def test_max_severity_property(self, simple_malicious_pickle_file):
        """Test max_severity property."""
        result = scan_file(simple_malicious_pickle_file)

        assert result.max_severity is not None
        assert result.max_severity in (Severity.CRITICAL, Severity.HIGH)


class TestScanDirectory:
    """Test directory scanning."""

    def test_scan_empty_directory(self, fixtures_dir):
        """Test scanning an empty directory."""
        results = scan_directory(fixtures_dir)

        assert len(results) == 0

    def test_scan_directory_with_files(
        self, fixtures_dir, safe_pickle_file, valid_safetensors_file
    ):
        """Test scanning directory with multiple files."""
        results = scan_directory(fixtures_dir)

        assert len(results) == 2
        formats = {r.format for r in results}
        assert "pickle" in formats
        assert "safetensors" in formats

    def test_scan_directory_nonrecursive(self, fixtures_dir, safe_pickle_file):
        """Test non-recursive directory scanning."""
        # Create subdirectory with file
        subdir = fixtures_dir / "subdir"
        subdir.mkdir()
        subfile = subdir / "nested.pkl"
        subfile.write_bytes(safe_pickle_file.read_bytes())

        # Non-recursive should only find root file
        results = scan_directory(fixtures_dir, recursive=False)
        assert len(results) == 1

        # Recursive should find both
        results = scan_directory(fixtures_dir, recursive=True)
        assert len(results) == 2

    def test_scan_nonexistent_directory(self, fixtures_dir):
        """Test scanning a directory that doesn't exist."""
        results = scan_directory(fixtures_dir / "nonexistent")

        assert len(results) == 1
        assert "not found" in results[0].findings[0].message.lower()

    def test_scan_specific_extensions(self, fixtures_dir, safe_pickle_file, valid_safetensors_file):
        """Test scanning only specific extensions."""
        results = scan_directory(fixtures_dir, extensions={".pkl"})

        assert len(results) == 1
        assert results[0].format == "pickle"


class TestFormatDetection:
    """Test automatic format detection."""

    def test_detect_pickle_by_extension(self, fixtures_dir):
        """Test pickle detection by various extensions."""
        extensions = [".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"]

        for ext in extensions:
            filepath = fixtures_dir / f"test{ext}"
            filepath.write_bytes(b"\x80\x04N.")  # Minimal pickle

            result = scan_file(filepath)
            assert result.format == "pickle", f"Extension {ext} should be detected as pickle"

    def test_detect_safetensors_by_extension(self, valid_safetensors_file):
        """Test safetensors detection by extension."""
        result = scan_file(valid_safetensors_file)
        assert result.format == "safetensors"

    def test_detect_gguf_by_extension(self, valid_gguf_file):
        """Test GGUF detection by extension."""
        result = scan_file(valid_gguf_file)
        assert result.format == "gguf"

    def test_unknown_extension(self, fixtures_dir):
        """Test handling of unknown file extension."""
        filepath = fixtures_dir / "test.unknown"
        filepath.write_bytes(b"some data")

        result = scan_file(filepath)
        assert result.format == "unknown"
