"""Report generators for scan results.

Generates reports in multiple formats: TXT, JSON, HTML, CSV.

v0.3.3 - Enhanced HTML report:
- Confidence summary in header
- Results sorted by severity AND confidence (HIGH confidence first)
- Functional action buttons (copy file path)
- Verification instructions for each finding type
- Collapsible safe files section
- Collapsible threat cards for easier navigation
"""

import csv
import json
from datetime import datetime
from io import StringIO
from pathlib import Path

from tensortrap.scanner.results import ScanResult, Severity

# Verification instructions by pattern type
VERIFICATION_INSTRUCTIONS = {
    "eval": """<strong>How to verify:</strong>
<ol>
    <li>Run: <code>strings "{filepath}" | grep -iE 'eval\\s*\\(' | head -20</code></li>
    <li>Check if results show actual code like <code>eval($_POST[...])</code>
        or random binary fragments</li>
    <li>Run: <code>xxd -s {offset} -l 200 "{filepath}"</code> to inspect the region</li>
    <li>If only random bytes with no code structure → False positive</li>
</ol>""",
    "exec": """<strong>How to verify:</strong>
<ol>
    <li>Run: <code>strings "{filepath}" | grep -iE 'exec\\s*\\(' | head -20</code></li>
    <li>Check if results show actual code like <code>exec($cmd)</code> or random binary</li>
    <li>Run: <code>xxd -s {offset} -l 200 "{filepath}"</code> to inspect the region</li>
    <li>If only random bytes with no code structure → False positive</li>
</ol>""",
    "asp": """<strong>How to verify:</strong>
<ol>
    <li>Run: <code>strings "{filepath}" | grep -iE '&lt;%|response\\.' | head -20</code></li>
    <li>Look for actual ASP code: <code>&lt;% Response.Write(...) %&gt;</code></li>
    <li>Run: <code>xxd -s {offset} -l 200 "{filepath}"</code> to inspect the region</li>
    <li>Random <code>&lt;%</code> in compressed data without closing
        <code>%&gt;</code> → False positive</li>
</ol>""",
    "php": """<strong>How to verify:</strong>
<ol>
    <li>Run: <code>strings "{filepath}" | grep -iE '&lt;\\?php|\\$_' | head -20</code></li>
    <li>Look for actual PHP: <code>&lt;?php $x = $_GET[...];</code></li>
    <li>Run: <code>xxd -s {offset} -l 200 "{filepath}"</code> to inspect the region</li>
    <li>If no PHP structure visible → False positive</li>
</ol>""",
    "archive": """<strong>How to verify:</strong>
<ol>
    <li>Run: <code>binwalk "{filepath}"</code> to detect embedded files</li>
    <li>If binwalk shows valid archive with extractable files → Real threat</li>
    <li>Run: <code>xxd -s {offset} -l 100 "{filepath}"</code> to check archive header</li>
    <li>Invalid version numbers or impossible sizes → False positive
        (random bytes matching signature)</li>
</ol>""",
    "pickle": """<strong>How to verify:</strong>
<ol>
    <li>This is a high-risk format - pickle can execute code on load</li>
    <li>Run: <code>python -m pickletools "{filepath}" 2>&1 | grep -E 'GLOBAL|REDUCE'</code></li>
    <li>Check for dangerous imports: os, subprocess, socket, sys</li>
    <li>Convert to safetensors format if possible</li>
</ol>""",
    "default": """<strong>How to verify:</strong>
<ol>
    <li>Run: <code>strings "{filepath}" | head -50</code> to check for readable code</li>
    <li>Run: <code>file "{filepath}"</code> to confirm file type</li>
    <li>Run: <code>xxd -s {offset} -l 200 "{filepath}"</code> to inspect the flagged region</li>
    <li>Use <code>exiftool "{filepath}"</code> to check metadata</li>
</ol>""",
}


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


def _get_confidence_counts(results: list[ScanResult]) -> dict[str, int]:
    """Count findings by confidence level."""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNANALYZED": 0}
    for result in results:
        for finding in result.findings:
            if finding.details and "context_analysis" in finding.details:
                level = finding.details["context_analysis"].get("confidence_level", "LOW")
                counts[level] = counts.get(level, 0) + 1
            else:
                counts["UNANALYZED"] += 1
    return counts


def _get_result_sort_key(result: ScanResult) -> tuple:
    """Generate sort key for results: unsafe first, then by max confidence."""
    if result.is_safe:
        return (1, 0, str(result.filepath))  # Safe files last

    # Find highest confidence among findings
    max_confidence = 0.0
    max_severity_idx = 5
    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]

    for finding in result.findings:
        # Get severity index
        try:
            sev_idx = severity_order.index(finding.severity)
            max_severity_idx = min(max_severity_idx, sev_idx)
        except ValueError:
            pass

        # Get confidence
        if finding.details and "context_analysis" in finding.details:
            conf = finding.details["context_analysis"].get("confidence_score", 0.0)
            max_confidence = max(max_confidence, conf)

    # Sort: unsafe first (0), then by severity (lower=worse), then by confidence (higher=worse)
    return (0, max_severity_idx, -max_confidence, str(result.filepath))


def _get_verification_instructions(finding_message: str, filepath: str, offset: int | None) -> str:
    """Get verification instructions based on finding type."""
    message_lower = finding_message.lower()
    offset_str = str(offset) if offset else "0"

    template = VERIFICATION_INSTRUCTIONS["default"]

    if "eval" in message_lower:
        template = VERIFICATION_INSTRUCTIONS["eval"]
    elif "exec" in message_lower or "system" in message_lower or "passthru" in message_lower:
        template = VERIFICATION_INSTRUCTIONS["exec"]
    elif "asp" in message_lower:
        template = VERIFICATION_INSTRUCTIONS["asp"]
    elif "php" in message_lower:
        template = VERIFICATION_INSTRUCTIONS["php"]
    elif "archive" in message_lower or "zip" in message_lower or "rar" in message_lower:
        template = VERIFICATION_INSTRUCTIONS["archive"]
    elif "pickle" in message_lower or "dangerous import" in message_lower:
        template = VERIFICATION_INSTRUCTIONS["pickle"]

    return template.format(filepath=filepath, offset=offset_str)


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

    # Confidence counts
    confidence_counts = _get_confidence_counts(results)

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
    lines.append("Confidence Analysis:")
    if confidence_counts["HIGH"] > 0:
        lines.append(f"  HIGH confidence (likely real): {confidence_counts['HIGH']}")
    if confidence_counts["MEDIUM"] > 0:
        lines.append(f"  MEDIUM confidence (investigate): {confidence_counts['MEDIUM']}")
    if confidence_counts["LOW"] > 0:
        lines.append(f"  LOW confidence (likely false positive): {confidence_counts['LOW']}")

    lines.append("")
    lines.append("=" * 80)
    lines.append("DETAILED RESULTS (sorted by threat level)")
    lines.append("=" * 80)
    lines.append("")

    # Sort results: unsafe first, then by confidence
    sorted_results = sorted(results, key=_get_result_sort_key)

    # First show unsafe files
    unsafe_results = [r for r in sorted_results if not r.is_safe]
    safe_results = [r for r in sorted_results if r.is_safe]

    for result in unsafe_results:
        status = "THREATS DETECTED"
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
                severity_str = finding.severity.value.upper()
                if finding.details and "adjusted_severity" in finding.details:
                    severity_str = finding.details["adjusted_severity"]
                    if "-HIGH" in severity_str:
                        icon = "!!"
                    elif "-MEDIUM" in severity_str:
                        icon = "* "
                    elif "-LOW" in severity_str:
                        icon = "  "

                lines.append(f"  {icon} [{severity_str}] {finding.message}")

                if finding.details and "context_analysis" in finding.details:
                    ctx = finding.details["context_analysis"]
                    conf_pct = ctx.get("confidence_percent", "")
                    reasons = ctx.get("reasons", [])
                    if conf_pct:
                        reason_str = "; ".join(reasons[:2]) if reasons else ""
                        lines.append(f"      Confidence: {conf_pct} ({reason_str})")

                if finding.recommendation:
                    lines.append(f"      Action: {finding.recommendation}")

                if finding.details and "external_validation" in finding.details:
                    ext = finding.details["external_validation"]
                    tool = ext.get("tool_name", "unknown")
                    status = ext.get("status", "unknown")
                    lines.append(f"      External ({tool}): {status.upper()}")

        lines.append("-" * 80)
        lines.append("")

    # Summary of safe files (not individual entries)
    if safe_results:
        lines.append("=" * 80)
        lines.append(f"SAFE FILES ({len(safe_results)} files)")
        lines.append("=" * 80)
        for result in safe_results:
            lines.append(f"  {result.filepath}")
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

    # Confidence counts
    confidence_counts = _get_confidence_counts(results)

    # Sort results
    sorted_results = sorted(results, key=_get_result_sort_key)

    report = {
        "report_type": "tensortrap_security_scan",
        "version": "0.3.3",
        "scan_target": scan_path,
        "scan_date": datetime.now().isoformat(),
        "summary": {
            "total_files": len(results),
            "safe_files": safe_count,
            "files_with_issues": len(results) - safe_count,
            "findings_by_severity": severity_counts,
            "findings_by_confidence": {
                "high_confidence": confidence_counts["HIGH"],
                "medium_confidence": confidence_counts["MEDIUM"],
                "low_confidence_likely_fp": confidence_counts["LOW"],
            },
        },
        "results": [r.to_dict() for r in sorted_results],
    }

    return json.dumps(report, indent=2, default=str)


def generate_html_report(results: list[ScanResult], scan_path: str) -> str:
    """Generate a styled HTML report with interactive features.

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

    # Confidence counts
    confidence_counts = _get_confidence_counts(results)

    # Sort results
    sorted_results = sorted(results, key=_get_result_sort_key)
    unsafe_results = [r for r in sorted_results if not r.is_safe]
    safe_results = [r for r in sorted_results if r.is_safe]

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
            --confidence-high: #ff4757;
            --confidence-medium: #ffa502;
            --confidence-low: #2ed573;
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
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 0.75rem;
            margin-bottom: 1.5rem;
        }}

        .stat-card {{
            background: var(--bg-card);
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-card h3 {{
            font-size: 1.75rem;
            margin-bottom: 0.25rem;
        }}

        .stat-card p {{
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .stat-card.critical h3 {{ color: var(--critical); }}
        .stat-card.high h3 {{ color: var(--high); }}
        .stat-card.medium h3 {{ color: var(--medium); }}
        .stat-card.safe h3 {{ color: var(--safe); }}
        .stat-card.conf-high h3 {{ color: var(--confidence-high); }}
        .stat-card.conf-medium h3 {{ color: var(--confidence-medium); }}
        .stat-card.conf-low h3 {{ color: var(--confidence-low); }}

        .confidence-summary {{
            background: var(--bg-card);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            border-left: 4px solid var(--accent);
        }}

        .confidence-summary h3 {{
            margin-bottom: 0.5rem;
            font-size: 1rem;
        }}

        .confidence-bar {{
            display: flex;
            gap: 1.5rem;
            flex-wrap: wrap;
        }}

        .conf-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .conf-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}

        .conf-dot.high {{ background: var(--confidence-high); }}
        .conf-dot.medium {{ background: var(--confidence-medium); }}
        .conf-dot.low {{ background: var(--confidence-low); }}

        .results {{
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
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
            padding: 0.75rem 1rem;
            background: var(--accent);
            cursor: pointer;
            user-select: none;
        }}

        .result-header:hover {{
            background: #1a4a7a;
        }}

        .result-header .toggle-icon {{
            transition: transform 0.2s;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        .result-header.collapsed .toggle-icon {{
            transform: rotate(-90deg);
        }}

        .file-path {{
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            word-break: break-all;
            flex: 1;
        }}

        .header-buttons {{
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }}

        .status {{
            padding: 0.2rem 0.6rem;
            border-radius: 4px;
            font-size: 0.75rem;
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

        .btn {{
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: bold;
            text-transform: uppercase;
            cursor: pointer;
            border: none;
            transition: opacity 0.2s;
        }}

        .btn:hover {{
            opacity: 0.8;
        }}

        .btn-copy {{
            background: #5dade2;
            color: #000;
        }}

        .btn-copy.copied {{
            background: var(--safe);
        }}

        .result-body {{
            padding: 1rem;
            display: block;
        }}

        .result-body.hidden {{
            display: none;
        }}

        .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 0.5rem;
            margin-bottom: 0.75rem;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}

        .findings {{
            margin-top: 0.75rem;
        }}

        .finding {{
            padding: 0.75rem 1rem;
            margin-bottom: 0.5rem;
            border-radius: 4px;
            border-left: 4px solid;
        }}

        .finding.critical, .finding.critical-high {{
            background: rgba(255, 71, 87, 0.15);
            border-color: var(--critical);
        }}

        .finding.high, .finding.critical-medium {{
            background: rgba(255, 107, 107, 0.1);
            border-color: var(--high);
        }}

        .finding.medium, .finding.critical-low {{
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

        .finding.critical .finding-severity,
        .finding.critical-high .finding-severity {{ color: var(--critical); }}
        .finding.high .finding-severity,
        .finding.critical-medium .finding-severity {{ color: var(--high); }}
        .finding.medium .finding-severity,
        .finding.critical-low .finding-severity {{ color: var(--medium); }}
        .finding.low .finding-severity {{ color: var(--low); }}
        .finding.info .finding-severity {{ color: var(--info); }}

        .finding-message {{
            margin-bottom: 0.25rem;
        }}

        .finding-confidence {{
            font-size: 0.8rem;
            color: #888;
            margin-top: 0.25rem;
        }}

        .finding-action {{
            font-size: 0.85rem;
            color: #5dade2;
            font-style: italic;
            margin-top: 0.25rem;
        }}

        .verification {{
            margin-top: 0.75rem;
            padding: 0.75rem;
            background: rgba(0,0,0,0.2);
            border-radius: 4px;
            font-size: 0.8rem;
        }}

        .verification ol {{
            margin-left: 1.5rem;
            margin-top: 0.5rem;
        }}

        .verification li {{
            margin-bottom: 0.25rem;
        }}

        .verification code {{
            background: rgba(0,0,0,0.3);
            padding: 0.1rem 0.3rem;
            border-radius: 3px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.75rem;
            word-break: break-all;
        }}

        .safe-files-section {{
            background: var(--bg-card);
            border-radius: 8px;
            margin-top: 1rem;
        }}

        .safe-files-header {{
            padding: 1rem;
            background: var(--accent);
            border-radius: 8px 8px 0 0;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .safe-files-header:hover {{
            background: #1a4a7a;
        }}

        .safe-files-header h3 {{
            color: var(--safe);
            font-size: 1rem;
        }}

        .safe-files-list {{
            max-height: 400px;
            overflow-y: auto;
            padding: 0.5rem;
            display: none;
        }}

        .safe-files-list.expanded {{
            display: block;
        }}

        .safe-file-item {{
            padding: 0.3rem 0.5rem;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.75rem;
            color: var(--text-secondary);
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}

        .safe-file-item:last-child {{
            border-bottom: none;
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

        .section-title {{
            margin: 1.5rem 0 1rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--accent);
        }}

        /* Toast notification */
        .toast {{
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--safe);
            color: #000;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            font-weight: bold;
            opacity: 0;
            transition: opacity 0.3s;
            pointer-events: none;
        }}

        .toast.show {{
            opacity: 1;
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
                <p>With Issues</p>
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
            <div class="stat-card conf-high">
                <h3>{confidence_counts["HIGH"]}</h3>
                <p>High Conf</p>
            </div>
            <div class="stat-card conf-low">
                <h3>{confidence_counts["LOW"]}</h3>
                <p>Likely FP</p>
            </div>
        </div>

        <div class="confidence-summary">
            <h3>Confidence Analysis Summary</h3>
            <div class="confidence-bar">
                <div class="conf-item">
                    <span class="conf-dot high"></span>
                    <span><strong>{confidence_counts["HIGH"]}</strong> HIGH confidence -
                        Likely real threats, investigate immediately</span>
                </div>
                <div class="conf-item">
                    <span class="conf-dot medium"></span>
                    <span><strong>{confidence_counts["MEDIUM"]}</strong> MEDIUM confidence -
                        May need investigation</span>
                </div>
                <div class="conf-item">
                    <span class="conf-dot low"></span>
                    <span><strong>{confidence_counts["LOW"]}</strong> LOW confidence -
                        Likely false positives</span>
                </div>
            </div>
        </div>
"""

    # Threats section
    if unsafe_results:
        html += f"""
        <h2 class="section-title">Threats Detected ({len(unsafe_results)} files)</h2>
        <div class="results">
"""

        for result in unsafe_results:
            # Get max confidence for this result
            max_conf = 0.0
            max_conf_level = "LOW"
            for finding in result.findings:
                if finding.details and "context_analysis" in finding.details:
                    ctx = finding.details["context_analysis"]
                    conf = ctx.get("confidence_score", 0.0)
                    if conf > max_conf:
                        max_conf = conf
                        max_conf_level = ctx.get("confidence_level", "LOW")

            filepath_escaped = _escape_html(str(result.filepath))

            js_path = _escape_js(str(result.filepath))
            conf_color = max_conf_level.lower()
            html += f"""
            <div class="result-card">
                <div class="result-header" onclick="toggleCard(this)">
                    <span class="toggle-icon">▼</span>
                    <span class="file-path">{filepath_escaped}</span>
                    <div class="header-buttons">
                        <button class="btn btn-copy"
                            onclick="copyPath(event, '{js_path}')">Copy Path</button>
                        <span class="status threat">THREATS</span>
                    </div>
                </div>
                <div class="result-body">
                    <div class="meta">
                        <span>Format: <strong>{result.format}</strong></span>
                        <span>Size: <strong>{_format_size(result.file_size)}</strong></span>
                        <span>Scan Time: <strong>{result.scan_time_ms:.1f}ms</strong></span>
                        <span>Max Confidence:
                            <strong style="color: var(--confidence-{conf_color})"
                            >{max_conf_level}</strong></span>
                    </div>
"""

            if result.findings:
                html += '                    <div class="findings">\n'
                sorted_findings = sorted(
                    result.findings, key=lambda f: list(Severity).index(f.severity)
                )
                for finding in sorted_findings:
                    sev_class = finding.severity.value
                    severity_str = finding.severity.value.upper()

                    confidence_html = ""
                    if finding.details and "adjusted_severity" in finding.details:
                        severity_str = finding.details["adjusted_severity"]
                        if "-HIGH" in severity_str:
                            sev_class = "critical-high"
                        elif "-MEDIUM" in severity_str:
                            sev_class = "critical-medium"
                        elif "-LOW" in severity_str:
                            sev_class = "critical-low"

                    if finding.details and "context_analysis" in finding.details:
                        ctx = finding.details["context_analysis"]
                        conf_pct = ctx.get("confidence_percent", "")
                        if conf_pct:
                            reasons = ctx.get("reasons", [])
                            reason_str = "; ".join(reasons[:2]) if reasons else ""
                            confidence_html = (
                                f'<div class="finding-confidence">'
                                f"Confidence: {conf_pct} ({_escape_html(reason_str)})</div>"
                            )

                    # Get verification instructions
                    offset = finding.location if finding.location else 0
                    verification_html = _get_verification_instructions(
                        finding.message, str(result.filepath), offset
                    )

                    html += f"""                        <div class="finding {sev_class}">
                            <div class="finding-severity">{severity_str}</div>
                            <div class="finding-message">{_escape_html(finding.message)}</div>
{confidence_html}
"""
                    if finding.recommendation:
                        rec = _escape_html(finding.recommendation)
                        html += '                            <div class="finding-action">'
                        html += f"{rec}</div>\n"

                    # Add verification instructions
                    html += '                            <div class="verification">'
                    html += f"{verification_html}</div>\n"

                    html += "                        </div>\n"
                html += "                    </div>\n"

            html += """                </div>
            </div>
"""

        html += "        </div>\n"

    # Safe files section (collapsible list)
    if safe_results:
        html += f"""
        <div class="safe-files-section">
            <div class="safe-files-header" onclick="toggleSafeFiles()">
                <h3>✓ Safe Files ({len(safe_results)} files)</h3>
                <span class="toggle-icon" id="safe-toggle">▼</span>
            </div>
            <div class="safe-files-list" id="safe-files-list">
"""
        for result in safe_results:
            safe_path = _escape_html(str(result.filepath))
            html += f'                <div class="safe-file-item">{safe_path}</div>\n'

        html += """            </div>
        </div>
"""

    html += """
        <footer>
            Generated by TensorTrap - AI/ML Model Security Scanner<br>
            <small>Tip: Click on threat cards to expand/collapse.
                Use "Copy Path" to quickly access files.</small>
        </footer>
    </div>

    <div class="toast" id="toast">Path copied to clipboard!</div>

    <script>
        function toggleCard(header) {
            const body = header.nextElementSibling;
            const icon = header.querySelector('.toggle-icon');

            if (body.classList.contains('hidden')) {
                body.classList.remove('hidden');
                header.classList.remove('collapsed');
            } else {
                body.classList.add('hidden');
                header.classList.add('collapsed');
            }
        }

        function toggleSafeFiles() {
            const list = document.getElementById('safe-files-list');
            const icon = document.getElementById('safe-toggle');

            if (list.classList.contains('expanded')) {
                list.classList.remove('expanded');
                icon.style.transform = 'rotate(0deg)';
            } else {
                list.classList.add('expanded');
                icon.style.transform = 'rotate(180deg)';
            }
        }

        function copyPath(event, path) {
            event.stopPropagation();
            navigator.clipboard.writeText(path).then(function() {
                const btn = event.target;
                btn.textContent = 'Copied!';
                btn.classList.add('copied');

                const toast = document.getElementById('toast');
                toast.classList.add('show');

                setTimeout(function() {
                    btn.textContent = 'Copy Path';
                    btn.classList.remove('copied');
                    toast.classList.remove('show');
                }, 2000);
            });
        }

        // Collapse all cards by default except HIGH confidence ones
        document.addEventListener('DOMContentLoaded', function() {
            const headers = document.querySelectorAll('.result-header');
            headers.forEach(function(header) {
                const body = header.nextElementSibling;
                const maxConfText = body.querySelector('.meta')?.textContent || '';

                // Keep HIGH confidence expanded, collapse others
                if (!maxConfText.includes('HIGH')) {
                    body.classList.add('hidden');
                    header.classList.add('collapsed');
                }
            });
        });
    </script>
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
            "Confidence Level",
            "Finding Message",
            "Recommended Action",
        ]
    )

    # Sort results
    sorted_results = sorted(results, key=_get_result_sort_key)

    for result in sorted_results:
        status = "SAFE" if result.is_safe else "THREATS DETECTED"

        if result.findings:
            for finding in result.findings:
                adjusted_sev = ""
                confidence = ""
                confidence_level = ""
                if finding.details:
                    adjusted_sev = finding.details.get("adjusted_severity", "")
                    if "context_analysis" in finding.details:
                        ctx = finding.details["context_analysis"]
                        confidence = ctx.get("confidence_percent", "")
                        confidence_level = ctx.get("confidence_level", "")

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
                        confidence_level,
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
        Severity.HIGH: "! ",
        Severity.MEDIUM: "* ",
        Severity.LOW: "- ",
        Severity.INFO: "i ",
    }
    return icons.get(severity, "? ")


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _escape_js(text: str) -> str:
    """Escape string for JavaScript."""
    return (
        text.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )
