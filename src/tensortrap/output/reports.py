"""Report generators for scan results.

Generates reports in multiple formats: TXT, JSON, HTML, CSV.
"""

import csv
import json
from datetime import datetime
from io import StringIO
from pathlib import Path

from tensortrap.scanner.results import ScanResult, Severity


def generate_report_filename(base_dir: Path, format: str) -> Path:
    """Generate a timestamped report filename.

    Args:
        base_dir: Directory to save report in
        format: File format extension (txt, json, html, csv)

    Returns:
        Path to report file
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return base_dir / f"tensortrap_report_{timestamp}.{format}"


def generate_txt_report(results: list[ScanResult], scan_path: str) -> str:
    """Generate a plain text report.

    Args:
        results: List of scan results
        scan_path: Path that was scanned

    Returns:
        Report as string
    """
    lines = []
    lines.append("=" * 80)
    lines.append("TENSORTRAP SECURITY SCAN REPORT")
    lines.append("=" * 80)
    lines.append(f"Scan Target: {scan_path}")
    lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Total Files: {len(results)}")

    # Summary counts
    safe_count = sum(1 for r in results if r.is_safe)
    unsafe_count = len(results) - safe_count
    severity_counts = {sev: 0 for sev in Severity}
    for result in results:
        for finding in result.findings:
            severity_counts[finding.severity] += 1

    lines.append(f"Safe Files: {safe_count}")
    lines.append(f"Files with Issues: {unsafe_count}")
    lines.append("")
    lines.append("Findings Summary:")
    for sev in [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]:
        if severity_counts[sev] > 0:
            lines.append(f"  {sev.value.upper()}: {severity_counts[sev]}")
    lines.append("")
    lines.append("=" * 80)
    lines.append("DETAILED RESULTS")
    lines.append("=" * 80)
    lines.append("")

    # Sort results: unsafe first, then by path
    sorted_results = sorted(results, key=lambda r: (r.is_safe, str(r.filepath)))

    for result in sorted_results:
        status = "SAFE" if result.is_safe else "THREATS DETECTED"
        lines.append(f"File: {result.filepath}")
        lines.append(f"Format: {result.format}")
        lines.append(f"Status: {status}")
        lines.append(f"Size: {_format_size(result.file_size)}")
        if result.file_hash:
            lines.append(f"SHA-256: {result.file_hash}")
        lines.append(f"Scan Time: {result.scan_time_ms:.1f}ms")

        if result.findings:
            lines.append("Findings:")
            for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
                icon = _severity_icon(finding.severity)
                # Use adjusted severity if available from context analysis
                severity_str = finding.severity.value.upper()
                if finding.details and "adjusted_severity" in finding.details:
                    severity_str = finding.details["adjusted_severity"]
                    # Update icon based on confidence
                    if "-HIGH" in severity_str:
                        icon = "!!"
                    elif "-MEDIUM" in severity_str:
                        icon = "* "
                    elif "-LOW" in severity_str:
                        icon = "  "

                lines.append(f"  {icon} [{severity_str}] {finding.message}")

                # Add confidence info if available
                if finding.details and "context_analysis" in finding.details:
                    ctx = finding.details["context_analysis"]
                    conf_pct = ctx.get("confidence_percent", "")
                    reasons = ctx.get("reasons", [])
                    if conf_pct:
                        reason_str = "; ".join(reasons[:2]) if reasons else ""
                        lines.append(f"      Confidence: {conf_pct} ({reason_str})")

                if finding.recommendation:
                    lines.append(f"      Action: {finding.recommendation}")

                # Add external validation if present
                if finding.details and "external_validation" in finding.details:
                    ext = finding.details["external_validation"]
                    tool = ext.get("tool_name", "unknown")
                    status = ext.get("status", "unknown")
                    lines.append(f"      External ({tool}): {status.upper()}")
        else:
            lines.append("Findings: None")

        lines.append("-" * 80)
        lines.append("")

    return "\n".join(lines)


def generate_json_report(results: list[ScanResult], scan_path: str) -> str:
    """Generate a JSON report.

    Args:
        results: List of scan results
        scan_path: Path that was scanned

    Returns:
        Report as JSON string
    """
    # Summary counts
    safe_count = sum(1 for r in results if r.is_safe)
    severity_counts = {sev.value: 0 for sev in Severity}
    for result in results:
        for finding in result.findings:
            severity_counts[finding.severity.value] += 1

    report = {
        "report_type": "tensortrap_security_scan",
        "version": "1.0",
        "scan_target": scan_path,
        "scan_date": datetime.now().isoformat(),
        "summary": {
            "total_files": len(results),
            "safe_files": safe_count,
            "files_with_issues": len(results) - safe_count,
            "findings_by_severity": severity_counts,
        },
        "results": [r.to_dict() for r in results],
    }

    return json.dumps(report, indent=2, default=str)


def generate_html_report(results: list[ScanResult], scan_path: str) -> str:
    """Generate a styled HTML report.

    Args:
        results: List of scan results
        scan_path: Path that was scanned

    Returns:
        Report as HTML string
    """
    # Summary counts
    safe_count = sum(1 for r in results if r.is_safe)
    unsafe_count = len(results) - safe_count
    severity_counts = {sev: 0 for sev in Severity}
    for result in results:
        for finding in result.findings:
            severity_counts[finding.severity] += 1

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TensorTrap Security Scan Report</title>
    <style>
        :root {{
            --bg-dark: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #0f3460;
            --critical: #ff4757;
            --high: #ff6b6b;
            --medium: #ffa502;
            --low: #3498db;
            --info: #747d8c;
            --safe: #2ed573;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        header {{
            text-align: center;
            margin-bottom: 2rem;
            padding: 2rem;
            background: linear-gradient(135deg, var(--bg-card), var(--accent));
            border-radius: 12px;
        }}

        h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            background: linear-gradient(90deg, #fff, #0f3460);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}

        .scan-info {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .stat-card {{
            background: var(--bg-card);
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-card h3 {{
            font-size: 2rem;
            margin-bottom: 0.25rem;
        }}

        .stat-card p {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .stat-card.critical h3 {{ color: var(--critical); }}
        .stat-card.high h3 {{ color: var(--high); }}
        .stat-card.medium h3 {{ color: var(--medium); }}
        .stat-card.safe h3 {{ color: var(--safe); }}

        .results {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}

        .result-card {{
            background: var(--bg-card);
            border-radius: 8px;
            overflow: hidden;
        }}

        .result-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem 1.5rem;
            background: var(--accent);
            cursor: pointer;
        }}

        .result-header:hover {{
            background: #1a4a7a;
        }}

        .file-path {{
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
            word-break: break-all;
        }}

        .status {{
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .status.safe {{
            background: var(--safe);
            color: #000;
        }}

        .status.threat {{
            background: var(--critical);
            color: #fff;
        }}

        .result-body {{
            padding: 1.5rem;
        }}

        .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem;
            margin-bottom: 1rem;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}

        .findings {{
            margin-top: 1rem;
        }}

        .finding {{
            padding: 0.75rem 1rem;
            margin-bottom: 0.5rem;
            border-radius: 4px;
            border-left: 4px solid;
        }}

        .finding.critical {{
            background: rgba(255, 71, 87, 0.1);
            border-color: var(--critical);
        }}

        .finding.high {{
            background: rgba(255, 107, 107, 0.1);
            border-color: var(--high);
        }}

        .finding.medium {{
            background: rgba(255, 165, 2, 0.1);
            border-color: var(--medium);
        }}

        .finding.low {{
            background: rgba(52, 152, 219, 0.1);
            border-color: var(--low);
        }}

        .finding.info {{
            background: rgba(116, 125, 140, 0.1);
            border-color: var(--info);
        }}

        .finding-severity {{
            font-weight: bold;
            font-size: 0.75rem;
            text-transform: uppercase;
            margin-bottom: 0.25rem;
        }}

        .finding.critical .finding-severity {{ color: var(--critical); }}
        .finding.high .finding-severity {{ color: var(--high); }}
        .finding.medium .finding-severity {{ color: var(--medium); }}
        .finding.low .finding-severity {{ color: var(--low); }}
        .finding.info .finding-severity {{ color: var(--info); }}

        .finding-message {{
            margin-bottom: 0.25rem;
        }}

        .finding-action {{
            font-size: 0.85rem;
            color: #5dade2;
            font-style: italic;
        }}

        footer {{
            text-align: center;
            margin-top: 2rem;
            padding: 1rem;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}

        .no-findings {{
            color: var(--safe);
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>TensorTrap Security Scan Report</h1>
            <p class="scan-info">
                Scan Target: <strong>{_escape_html(scan_path)}</strong><br>
                Scan Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </p>
        </header>

        <div class="summary">
            <div class="stat-card safe">
                <h3>{safe_count}</h3>
                <p>Safe Files</p>
            </div>
            <div class="stat-card critical">
                <h3>{unsafe_count}</h3>
                <p>Files with Issues</p>
            </div>
            <div class="stat-card critical">
                <h3>{severity_counts[Severity.CRITICAL]}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card high">
                <h3>{severity_counts[Severity.HIGH]}</h3>
                <p>High</p>
            </div>
            <div class="stat-card medium">
                <h3>{severity_counts[Severity.MEDIUM]}</h3>
                <p>Medium</p>
            </div>
        </div>

        <h2 style="margin-bottom: 1rem;">Scan Results ({len(results)} files)</h2>
        <div class="results">
"""

    # Sort results: unsafe first, then by path
    sorted_results = sorted(results, key=lambda r: (r.is_safe, str(r.filepath)))

    for result in sorted_results:
        status_class = "safe" if result.is_safe else "threat"
        status_text = "SAFE" if result.is_safe else "THREATS"

        html += f"""
            <div class="result-card">
                <div class="result-header">
                    <span class="file-path">{_escape_html(str(result.filepath))}</span>
                    <span class="status {status_class}">{status_text}</span>
                </div>
                <div class="result-body">
                    <div class="meta">
                        <span>Format: <strong>{result.format}</strong></span>
                        <span>Size: <strong>{_format_size(result.file_size)}</strong></span>
                        <span>Scan Time: <strong>{result.scan_time_ms:.1f}ms</strong></span>
                    </div>
"""

        if result.findings:
            html += '                    <div class="findings">\n'
            for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
                sev_class = finding.severity.value
                severity_str = finding.severity.value.upper()

                # Get adjusted severity and confidence if available
                confidence_html = ""
                if finding.details and "adjusted_severity" in finding.details:
                    severity_str = finding.details["adjusted_severity"]
                    if "-HIGH" in severity_str:
                        sev_class = "critical"
                    elif "-MEDIUM" in severity_str:
                        sev_class = "medium"
                    elif "-LOW" in severity_str:
                        sev_class = "low"

                if finding.details and "context_analysis" in finding.details:
                    ctx = finding.details["context_analysis"]
                    conf_pct = ctx.get("confidence_percent", "")
                    if conf_pct:
                        reasons = ctx.get("reasons", [])
                        reason_str = "; ".join(reasons[:2]) if reasons else ""
                        confidence_html = (
                            f'<div class="finding-confidence" '
                            f'style="font-size:0.8rem;color:#888;margin-top:0.25rem;">'
                            f"Confidence: {conf_pct} ({_escape_html(reason_str)})</div>"
                        )

                html += f"""                        <div class="finding {sev_class}">
                            <div class="finding-severity">{severity_str}</div>
                            <div class="finding-message">{_escape_html(finding.message)}</div>
{confidence_html}
"""
                if finding.recommendation:
                    rec = _escape_html(finding.recommendation)
                    html += f'                            <div class="finding-action">{rec}</div>\n'

                # Add external validation if present
                if finding.details and "external_validation" in finding.details:
                    ext = finding.details["external_validation"]
                    tool = ext.get("tool_name", "unknown")
                    status = ext.get("status", "unknown")
                    if status == "confirmed":
                        ext_color = "#2ed573"
                    elif status == "not_confirmed":
                        ext_color = "#ff6b6b"
                    else:
                        ext_color = "#888"
                    html += (
                        f'<div style="font-size:0.8rem;color:{ext_color};'
                        f'margin-top:0.25rem;">External ({tool}): '
                        f"{status.upper()}</div>\n"
                    )

                html += "                        </div>\n"
            html += "                    </div>\n"
        else:
            html += '                    <p class="no-findings">No security findings</p>\n'

        html += """                </div>
            </div>
"""

    html += """        </div>

        <footer>
            Generated by TensorTrap - AI/ML Model Security Scanner
        </footer>
    </div>
</body>
</html>
"""

    return html


def generate_csv_report(results: list[ScanResult], scan_path: str) -> str:
    """Generate a CSV report.

    Args:
        results: List of scan results
        scan_path: Path that was scanned

    Returns:
        Report as CSV string
    """
    output = StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(
        [
            "File Path",
            "Format",
            "Status",
            "File Size",
            "SHA-256",
            "Scan Time (ms)",
            "Finding Severity",
            "Adjusted Severity",
            "Confidence",
            "Finding Message",
            "Recommended Action",
        ]
    )

    for result in results:
        status = "SAFE" if result.is_safe else "THREATS DETECTED"

        if result.findings:
            for finding in result.findings:
                # Get adjusted severity and confidence from context analysis
                adjusted_sev = ""
                confidence = ""
                if finding.details:
                    adjusted_sev = finding.details.get("adjusted_severity", "")
                    if "context_analysis" in finding.details:
                        ctx = finding.details["context_analysis"]
                        confidence = ctx.get("confidence_percent", "")

                writer.writerow(
                    [
                        str(result.filepath),
                        result.format,
                        status,
                        result.file_size,
                        result.file_hash,
                        f"{result.scan_time_ms:.1f}",
                        finding.severity.value.upper(),
                        adjusted_sev,
                        confidence,
                        finding.message,
                        finding.recommendation or "",
                    ]
                )
        else:
            writer.writerow(
                [
                    str(result.filepath),
                    result.format,
                    status,
                    result.file_size,
                    result.file_hash,
                    f"{result.scan_time_ms:.1f}",
                    "",
                    "",
                    "",
                    "",
                    "",
                ]
            )

    return output.getvalue()


def save_reports(
    results: list[ScanResult],
    scan_path: str,
    output_dir: Path,
    formats: list[str] | None = None,
) -> dict[str, Path]:
    """Save reports in multiple formats.

    Args:
        results: List of scan results
        scan_path: Path that was scanned
        output_dir: Directory to save reports in
        formats: List of formats to generate (default: all)

    Returns:
        Dictionary mapping format to saved file path
    """
    if formats is None:
        formats = ["txt", "json", "html", "csv"]

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    saved_files = {}
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    generators = {
        "txt": generate_txt_report,
        "json": generate_json_report,
        "html": generate_html_report,
        "csv": generate_csv_report,
    }

    for fmt in formats:
        if fmt in generators:
            content = generators[fmt](results, scan_path)
            filepath = output_dir / f"tensortrap_report_{timestamp}.{fmt}"
            filepath.write_text(content, encoding="utf-8")
            saved_files[fmt] = filepath

    return saved_files


def _format_size(size_bytes: int) -> str:
    """Format file size in human-readable form."""
    size: float = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _severity_icon(severity: Severity) -> str:
    """Get text icon for severity level."""
    icons = {
        Severity.CRITICAL: "!!",
        Severity.HIGH: "!",
        Severity.MEDIUM: "*",
        Severity.LOW: "-",
        Severity.INFO: "i",
    }
    return icons.get(severity, "?")


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
