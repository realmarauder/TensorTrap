"""Tests for pickle scanner."""

import pytest

from tensortrap.scanner.pickle_scanner import scan_pickle, scan_pickle_file
from tensortrap.scanner.results import Severity


class TestPickleScanner:
    """Test pickle scanning functionality."""

    def test_safe_pickle(self, safe_pickle_file):
        """Test that safe pickle files pass."""
        findings = scan_pickle_file(safe_pickle_file)

        # Safe pickles may have some findings but shouldn't be critical/high
        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0, f"Safe pickle had critical/high findings: {critical_high}"

    def test_malicious_pickle_global(self, simple_malicious_pickle_file):
        """Test detection of malicious GLOBAL opcode."""
        findings = scan_pickle_file(simple_malicious_pickle_file)

        # Should detect dangerous os.system call
        dangerous_findings = [f for f in findings if "os" in f.message.lower()]
        assert len(dangerous_findings) > 0, "Should detect dangerous os import or call"

        # Should have critical or high severity findings
        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) > 0, "Should have critical/high findings for malicious pickle"

    def test_malicious_pickle_bytes(self, malicious_pickle_bytes):
        """Test detection of malicious pickle bytecode."""
        findings = scan_pickle(malicious_pickle_bytes)

        # Should detect REDUCE opcode or stack_global
        has_dangerous = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM) for f in findings
        )
        assert has_dangerous, "Should detect dangerous patterns in malicious pickle"

    def test_empty_file(self, empty_file):
        """Test handling of empty file."""
        findings = scan_pickle_file(empty_file)

        # Should report invalid/empty pickle
        assert len(findings) > 0, "Should report issue with empty file"

    def test_corrupted_pickle(self, fixtures_dir):
        """Test handling of corrupted pickle."""
        filepath = fixtures_dir / "corrupted.pkl"
        with open(filepath, "wb") as f:
            f.write(b"\x80\x04\xff\xff\xff")  # Invalid pickle bytes

        findings = scan_pickle_file(filepath)

        # Should handle gracefully and report issue
        assert len(findings) > 0, "Should report issue with corrupted pickle"

    def test_nested_pickle_detection(self, fixtures_dir):
        """Test detection of nested pickle imports."""
        # Create pickle that imports pickle module
        filepath = fixtures_dir / "nested.pkl"
        # Protocol 0 style GLOBAL that imports pickle.loads
        data = b"cpickle\nloads\np0\n."
        with open(filepath, "wb") as f:
            f.write(data)

        findings = scan_pickle_file(filepath)

        # Should detect pickle import
        pickle_findings = [f for f in findings if "pickle" in f.message.lower()]
        assert len(pickle_findings) > 0, "Should detect nested pickle import"


class TestDangerousImports:
    """Test detection of various dangerous imports."""

    @pytest.mark.parametrize(
        "module,expected_severity",
        [
            ("os", Severity.CRITICAL),
            ("subprocess", Severity.CRITICAL),
            ("socket", Severity.CRITICAL),
            ("builtins", Severity.CRITICAL),
            ("sys", Severity.HIGH),
            ("importlib", Severity.HIGH),
        ],
    )
    def test_dangerous_module_detection(self, fixtures_dir, module, expected_severity):
        """Test detection of various dangerous modules."""
        filepath = fixtures_dir / f"test_{module}.pkl"
        # Create pickle with GLOBAL opcode importing the module
        data = f"c{module}\nfunc\np0\n.".encode()
        with open(filepath, "wb") as f:
            f.write(data)

        findings = scan_pickle_file(filepath)

        # Should detect the dangerous module
        module_findings = [f for f in findings if module in f.message.lower()]
        assert len(module_findings) > 0, f"Should detect {module} import"

        # Check severity is appropriate
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        max_sev = max((f.severity for f in module_findings), key=lambda s: severity_order.index(s))
        assert severity_order.index(max_sev) <= severity_order.index(expected_severity), (
            f"Expected {expected_severity} or higher for {module}, got {max_sev}"
        )
