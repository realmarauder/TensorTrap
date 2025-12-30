"""Rich console output for scan results."""

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from tensortrap.scanner.results import ScanResult, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "red bold",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "[red]!![/red]",
    Severity.HIGH: "[red]![/red]",
    Severity.MEDIUM: "[yellow]*[/yellow]",
    Severity.LOW: "[blue]-[/blue]",
    Severity.INFO: "[dim]i[/dim]",
}


def print_results(results: list[ScanResult], verbose: bool = False) -> None:
    """Print scan results to console.

    Args:
        results: List of scan results
        verbose: Show detailed output including info-level findings
    """
    if not results:
        console.print("[dim]No files scanned[/dim]")
        return

    for result in results:
        _print_single_result(result, verbose)

    # Print summary
    console.print()
    _print_summary(results)


def _print_single_result(result: ScanResult, verbose: bool) -> None:
    """Print a single scan result."""
    # Header line
    if result.is_safe:
        status = "[green]SAFE[/green]"
    else:
        status = "[red]THREATS DETECTED[/red]"

    console.print()
    console.print(f"[bold]{result.filepath}[/bold] [dim]({result.format})[/dim] - {status}")

    # File info if verbose
    if verbose:
        console.print(f"  [dim]Size: {_format_size(result.file_size)}[/dim]")
        if result.file_hash:
            console.print(f"  [dim]SHA-256: {result.file_hash[:16]}...[/dim]")
        console.print(f"  [dim]Scan time: {result.scan_time_ms:.1f}ms[/dim]")

    # Filter findings based on verbosity
    findings = result.findings
    if not verbose:
        findings = [f for f in findings if f.severity != Severity.INFO]

    if not findings:
        if verbose:
            console.print("  [dim]No issues found[/dim]")
        return

    # Build findings table
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
    )
    table.add_column("", width=3)  # Icon
    table.add_column("Severity", width=16)  # Wider for adjusted severity
    table.add_column("Finding", no_wrap=False)
    table.add_column("Action", no_wrap=False, style="cyan")

    # Sort by severity
    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    sorted_findings = sorted(findings, key=lambda f: severity_order.index(f.severity))

    for finding in sorted_findings:
        icon = SEVERITY_ICONS[finding.severity]
        style = SEVERITY_COLORS[finding.severity]
        recommendation = finding.recommendation or ""

        # Get adjusted severity if available (from context analysis)
        severity_display = finding.severity.value.upper()
        if finding.details and "adjusted_severity" in finding.details:
            adjusted = finding.details["adjusted_severity"]
            # Color based on confidence level in adjusted severity
            if "-HIGH" in adjusted:
                style = "red bold"
                icon = "[red]!![/red]"
            elif "-MEDIUM" in adjusted:
                style = "yellow"
                icon = "[yellow]*[/yellow]"
            elif "-LOW" in adjusted:
                style = "green"
                icon = "[green] [/green]"
            severity_display = adjusted

        # Get confidence info if available
        finding_msg = finding.message
        if finding.details and "context_analysis" in finding.details:
            ctx = finding.details["context_analysis"]
            conf_pct = ctx.get("confidence_percent", "")
            if conf_pct:
                finding_msg = f"{finding.message} [dim]({conf_pct})[/dim]"

        table.add_row(
            icon,
            f"[{style}]{severity_display}[/{style}]",
            finding_msg,
            recommendation,
        )

    console.print(table)


def _print_summary(results: list[ScanResult]) -> None:
    """Print summary of all scan results."""
    total = len(results)
    safe = sum(1 for r in results if r.is_safe)
    unsafe = total - safe

    # Count by severity
    severity_counts = {sev: 0 for sev in Severity}
    for result in results:
        for finding in result.findings:
            severity_counts[finding.severity] += 1

    # Count by confidence level (for context-analyzed findings)
    confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    context_analyzed = 0
    for result in results:
        for finding in result.findings:
            if finding.details and "context_analysis" in finding.details:
                context_analyzed += 1
                ctx = finding.details["context_analysis"]
                level = ctx.get("confidence_level", "LOW")
                confidence_counts[level] = confidence_counts.get(level, 0) + 1

    # Summary line
    if unsafe == 0:
        console.print(f"[green]Scanned {total} file(s): All safe[/green]")
    else:
        console.print(
            f"[bold]Scanned {total} file(s):[/bold] "
            f"[green]{safe} safe[/green], "
            f"[red]{unsafe} with issues[/red]"
        )

    # Severity breakdown if there are findings
    if any(severity_counts.values()):
        parts = []
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts[sev]
            if count > 0:
                style = SEVERITY_COLORS[sev]
                parts.append(f"[{style}]{count} {sev.value}[/{style}]")
        if parts:
            console.print("  " + ", ".join(parts))

    # Context analysis summary if any were analyzed
    if context_analyzed > 0:
        console.print()
        console.print("[dim]Context Analysis:[/dim]")
        conf_parts = []
        if confidence_counts["HIGH"] > 0:
            conf_parts.append(f"[red]{confidence_counts['HIGH']} HIGH confidence[/red]")
        if confidence_counts["MEDIUM"] > 0:
            conf_parts.append(f"[yellow]{confidence_counts['MEDIUM']} MEDIUM[/yellow]")
        if confidence_counts["LOW"] > 0:
            conf_parts.append(f"[green]{confidence_counts['LOW']} LOW (likely FP)[/green]")
        if conf_parts:
            console.print("  " + ", ".join(conf_parts))


def _format_size(size_bytes: int) -> str:
    """Format file size in human-readable form."""
    size: float = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def print_file_info(result: ScanResult) -> None:
    """Print detailed file information without full security analysis.

    Args:
        result: Scan result with file metadata
    """
    console.print()
    console.print(Panel(f"[bold]{result.filepath}[/bold]", expand=False))

    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Format", result.format)
    table.add_row("Size", _format_size(result.file_size))
    if result.file_hash:
        table.add_row("SHA-256", result.file_hash)
    table.add_row("Scan Time", f"{result.scan_time_ms:.1f}ms")

    console.print(table)
