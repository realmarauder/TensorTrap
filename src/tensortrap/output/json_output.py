"""JSON output for scan results."""

import json
import sys
from typing import TextIO

from tensortrap.scanner.results import ScanResult


def output_json(
    results: list[ScanResult],
    file: TextIO = sys.stdout,
    indent: int = 2,
) -> None:
    """Output scan results as JSON.

    Args:
        results: List of scan results
        file: Output file (default: stdout)
        indent: JSON indentation level
    """
    output = {
        "results": [r.to_dict() for r in results],
        "summary": _generate_summary(results),
    }
    json.dump(output, file, indent=indent)
    file.write("\n")


def _generate_summary(results: list[ScanResult]) -> dict:
    """Generate summary statistics for results.

    Args:
        results: List of scan results

    Returns:
        Summary dictionary
    """
    total = len(results)
    safe = sum(1 for r in results if r.is_safe)

    # Count findings by severity
    severity_counts: dict[str, int] = {}
    for result in results:
        for finding in result.findings:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Count by format
    format_counts: dict[str, int] = {}
    for result in results:
        fmt = result.format
        format_counts[fmt] = format_counts.get(fmt, 0) + 1

    return {
        "total_files": total,
        "safe_files": safe,
        "unsafe_files": total - safe,
        "findings_by_severity": severity_counts,
        "files_by_format": format_counts,
    }


def results_to_json(results: list[ScanResult], indent: int = 2) -> str:
    """Convert scan results to JSON string.

    Args:
        results: List of scan results
        indent: JSON indentation level

    Returns:
        JSON string
    """
    output = {
        "results": [r.to_dict() for r in results],
        "summary": _generate_summary(results),
    }
    return json.dumps(output, indent=indent)
