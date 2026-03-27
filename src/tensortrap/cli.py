"""Command-line interface for TensorTrap."""

from pathlib import Path

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from tensortrap import __version__
from tensortrap.config import (
    DEFAULT_CONFIG_PATH,
    get_report_dir,
    get_report_formats,
    get_retain_days,
    load_config,
    save_default_config,
    update_config_value,
)
from tensortrap.output.console import print_file_info, print_results
from tensortrap.output.json_output import output_json
from tensortrap.output.reports import save_reports
from tensortrap.scanner.engine import collect_files, scan_file, scan_files_with_progress

app = typer.Typer(
    name="tensortrap",
    help="Security scanner for AI/ML model files",
    add_completion=False,
    no_args_is_help=True,
)
config_app = typer.Typer(
    name="config",
    help="Manage TensorTrap configuration",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")
service_app = typer.Typer(
    name="service",
    help="Manage TensorTrap background service",
    no_args_is_help=True,
)
app.add_typer(service_app, name="service")
console = Console()


@app.command()
def scan(
    path: Path = typer.Argument(
        ...,
        help="File or directory to scan",
        exists=True,
    ),
    recursive: bool = typer.Option(
        True,
        "--recursive/--no-recursive",
        "-r/-R",
        help="Scan directories recursively",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        "-j",
        help="Output results as JSON to console",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed output including info-level findings",
    ),
    no_hash: bool = typer.Option(
        False,
        "--no-hash",
        help="Skip computing file hashes",
    ),
    report: bool = typer.Option(
        True,
        "--report/--no-report",
        help="Generate report files (txt, json, html, csv)",
    ),
    report_dir: Path | None = typer.Option(
        None,
        "--report-dir",
        "-o",
        help="Directory to save reports (overrides config)",
    ),
    report_formats: str | None = typer.Option(
        None,
        "--report-formats",
        "-f",
        help="Comma-separated report formats: txt,json,html,csv (overrides config)",
    ),
    retain_days: int | None = typer.Option(
        None,
        "--retain-days",
        help="Days to keep old reports (overrides config, 0 = keep forever)",
    ),
    # Context Analysis options (v0.3.0)
    context_analysis: bool = typer.Option(
        True,
        "--context-analysis/--no-context-analysis",
        help="Run context analysis on findings to score confidence (default: enabled)",
    ),
    external_validation: bool = typer.Option(
        False,
        "--external-validation/--no-external-validation",
        help="Run external tool validation (exiftool/binwalk) for confirmation",
    ),
    confidence_threshold: float = typer.Option(
        0.5,
        "--confidence-threshold",
        "-c",
        help="Minimum confidence to report as actionable (0.0-1.0, default: 0.5)",
        min=0.0,
        max=1.0,
    ),
    entropy_threshold: float = typer.Option(
        7.0,
        "--entropy-threshold",
        help="Entropy above this is considered compressed data (default: 7.0)",
        min=0.0,
        max=8.0,
    ),
) -> None:
    """Scan model files for security issues.

    Analyzes pickle, safetensors, and GGUF files to detect potentially
    malicious content before loading them.

    Context analysis (enabled by default) reduces false positive noise by
    analyzing pattern context, entropy, and AI metadata to score confidence.

    Examples:
        tensortrap scan model.safetensors
        tensortrap scan ./models/ --recursive
        tensortrap scan model.pkl --json
        tensortrap scan ./models/ --report-dir ./reports
        tensortrap scan ./models/ --report-formats txt,html
        tensortrap scan ./images/ --external-validation
        tensortrap scan ./models/ --confidence-threshold 0.7
        tensortrap scan ./models/ --retain-days 14
    """
    compute_hash = not no_hash

    # Load config for defaults
    config = load_config()

    # Parse report formats (CLI overrides config)
    if report_formats:
        formats = [f.strip().lower() for f in report_formats.split(",")]
        valid_formats = {"txt", "json", "html", "csv"}
        invalid = set(formats) - valid_formats
        if invalid:
            console.print(f"[red]Invalid report formats: {', '.join(invalid)}[/red]")
            console.print(f"[dim]Valid formats: {', '.join(valid_formats)}[/dim]")
            raise typer.Exit(1)
    else:
        formats = get_report_formats(config)

    # Set report directory (CLI overrides config)
    if report_dir is None:
        report_dir = get_report_dir(config)

    # Set retention (CLI overrides config)
    if retain_days is None:
        retain_days = get_retain_days(config)

    if path.is_file():
        # Single file scan - simple progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(f"Scanning {path.name}...", total=None)
            results = [
                scan_file(
                    path,
                    compute_hash=compute_hash,
                    use_context_analysis=context_analysis,
                    use_external_validation=external_validation,
                    confidence_threshold=confidence_threshold,
                    entropy_threshold=entropy_threshold,
                )
            ]
    elif path.is_dir():
        # Directory scan with progress bar
        console.print(f"[bold]Collecting files from {path}...[/bold]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task("Discovering model files...", total=None)
            files = collect_files(path, recursive=recursive)

        if not files:
            console.print("[yellow]No model files found to scan[/yellow]")
            raise typer.Exit(0)

        console.print(f"[green]Found {len(files)} model file(s)[/green]")
        console.print()

        # Scan with progress bar
        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Scanning files...", total=len(files))

            for result in scan_files_with_progress(
                files,
                compute_hash=compute_hash,
                use_context_analysis=context_analysis,
                use_external_validation=external_validation,
                confidence_threshold=confidence_threshold,
                entropy_threshold=entropy_threshold,
            ):
                results.append(result)
                # Update progress with current file name (truncated)
                filename = result.filepath.name
                if len(filename) > 40:
                    filename = filename[:37] + "..."
                progress.update(task, advance=1, description=f"Scanning: {filename}")

            progress.update(task, description="[green]Scan complete![/green]")

        console.print()
    else:
        console.print(f"[red]Error: {path} is not a file or directory[/red]")
        raise typer.Exit(1)

    if not results:
        console.print("[yellow]No model files found to scan[/yellow]")
        raise typer.Exit(0)

    # Output results to console
    if json_output:
        output_json(results)
    else:
        print_results(results, verbose=verbose)

    # Generate reports
    if report and path.is_dir():
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task("Generating reports...", total=None)
            saved_files = save_reports(
                results,
                scan_path=str(path),
                output_dir=report_dir,
                formats=formats,
                retain_days=retain_days,
            )

        console.print("[bold green]Reports saved:[/bold green]")
        for fmt, filepath in saved_files.items():
            console.print(f"  [cyan]{fmt.upper()}:[/cyan] {filepath}")

    # Exit with error code if any critical/high findings
    if any(not r.is_safe for r in results):
        raise typer.Exit(1)


@config_app.command("show")
def config_show() -> None:
    """Show current configuration."""
    config = load_config()
    config_path = DEFAULT_CONFIG_PATH

    if config_path.exists():
        console.print(f"[dim]Config file: {config_path}[/dim]")
    else:
        console.print("[dim]No config file found (using defaults)[/dim]")

    console.print()
    console.print("[bold]Reports[/bold]")
    console.print(f"  directory:   {config['reports']['directory']}")
    console.print(f"  retain_days: {config['reports']['retain_days']}")
    console.print(f"  formats:     {', '.join(config['reports']['formats'])}")


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key (e.g. reports.retain_days)"),
    value: str = typer.Argument(..., help="Value to set"),
) -> None:
    """Set a configuration value.

    Examples:
        tensortrap config set reports.retain_days 14
        tensortrap config set reports.directory ~/my-reports
        tensortrap config set reports.formats txt,html
    """
    try:
        update_config_value(key, value)
        console.print(f"[green]Set {key} = {value}[/green]")
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@config_app.command("init")
def config_init() -> None:
    """Interactive setup for TensorTrap configuration."""
    if DEFAULT_CONFIG_PATH.exists():
        console.print(f"[yellow]Config already exists: {DEFAULT_CONFIG_PATH}[/yellow]")
        console.print("[dim]Use 'tensortrap config set' to modify values[/dim]")
        console.print("[dim]Use 'tensortrap config reset' to start over[/dim]")
        raise typer.Exit(0)

    console.print("[bold]TensorTrap Configuration Setup[/bold]")
    console.print()

    # Report format selection
    available_formats = {
        "html": "Interactive HTML report with collapsible findings (recommended)",
        "txt": "Plain text report",
        "json": "Machine-readable JSON report",
        "csv": "Spreadsheet-compatible CSV report",
    }

    console.print("[bold]Select report formats to generate:[/bold]")
    console.print()
    for i, (fmt, desc) in enumerate(available_formats.items(), 1):
        default_tag = " [green](default)[/green]" if fmt == "html" else ""
        console.print(f"  {i}. [cyan]{fmt}[/cyan] - {desc}{default_tag}")

    console.print()
    selection = typer.prompt(
        "Enter format numbers separated by commas (e.g. 1,2)",
        default="1",
    )

    format_keys = list(available_formats.keys())
    chosen_formats = []
    for part in selection.split(","):
        part = part.strip()
        try:
            idx = int(part) - 1
            if 0 <= idx < len(format_keys):
                chosen_formats.append(format_keys[idx])
            else:
                console.print(f"[yellow]Skipping invalid selection: {part}[/yellow]")
        except ValueError:
            # Allow format names directly
            if part.lower() in available_formats:
                chosen_formats.append(part.lower())
            else:
                console.print(f"[yellow]Skipping invalid selection: {part}[/yellow]")

    if not chosen_formats:
        chosen_formats = ["html"]
        console.print("[dim]No valid selection, defaulting to html[/dim]")

    # Retention days
    console.print()
    retain_days = typer.prompt(
        "Days to keep reports (0 = keep forever)",
        default=30,
        type=int,
    )

    # Save config
    path = save_default_config(formats=chosen_formats, retain_days=retain_days)

    console.print()
    console.print(f"[bold green]Config created: {path}[/bold green]")
    console.print()
    console.print("[bold]Your settings:[/bold]")
    console.print("  Report directory: ~/.local/share/tensortrap/reports")
    console.print(f"  Report formats:   {', '.join(chosen_formats)}")
    if retain_days > 0:
        console.print(f"  Retention:        {retain_days} days")
    else:
        console.print("  Retention:        forever")
    console.print()
    console.print("[dim]Change settings anytime with: tensortrap config set <key> <value>[/dim]")


@config_app.command("reset")
def config_reset() -> None:
    """Reset configuration to defaults."""
    path = save_default_config()
    console.print(f"[green]Config reset to defaults: {path}[/green]")


# --- Service Commands ---


@service_app.command("install")
def service_install() -> None:
    """Install TensorTrap as a background service.

    Sets up a systemd user service that starts on login and runs
    the web dashboard automatically.
    """
    from tensortrap.web.service import install_service

    console.print("Installing TensorTrap service...")
    result = install_service()

    if result.get("active"):
        console.print("[bold green]Service installed and running![/bold green]")
        config = load_config()
        port = config.get("web", {}).get("port", 7780)
        console.print(f"  Web UI: [cyan]http://127.0.0.1:{port}[/cyan]")
        console.print(f"  Service: {result['service_path']}")
        console.print()
        console.print("[dim]Bookmark the URL above for easy access.[/dim]")
    else:
        console.print("[yellow]Service installed but may not have started.[/yellow]")
        console.print("[dim]Check status with: tensortrap service status[/dim]")


@service_app.command("uninstall")
def service_uninstall() -> None:
    """Remove the TensorTrap background service."""
    from tensortrap.web.service import uninstall_service

    result = uninstall_service()
    if not result.get("installed", True):
        console.print(f"[green]{result.get('message', 'Service uninstalled')}[/green]")
    else:
        console.print("[red]Failed to uninstall service[/red]")


@service_app.command("status")
def service_status() -> None:
    """Show TensorTrap service status."""
    from tensortrap.web.service import get_service_status

    status = get_service_status()

    if not status["installed"]:
        console.print("[yellow]Service not installed[/yellow]")
        console.print("[dim]Install with: tensortrap service install[/dim]")
        return

    active_str = "[green]running[/green]" if status["active"] else "[red]stopped[/red]"
    enabled_str = "[green]enabled[/green]" if status["enabled"] else "[yellow]disabled[/yellow]"

    console.print("[bold]TensorTrap Service[/bold]")
    console.print(f"  Status:  {active_str}")
    console.print(f"  Startup: {enabled_str}")
    console.print(f"  Path:    {status['service_path']}")


@service_app.command("restart")
def service_restart() -> None:
    """Restart the TensorTrap background service."""
    from tensortrap.web.service import restart_service

    result = restart_service()
    if result.get("error"):
        console.print(f"[red]{result['error']}[/red]")
    elif result.get("restarted"):
        console.print("[green]Service restarted[/green]")
    else:
        console.print("[yellow]Restart may have failed[/yellow]")
        console.print("[dim]Check status with: tensortrap service status[/dim]")


@app.command()
def serve(
    port: int | None = typer.Option(
        None,
        "--port",
        "-p",
        help="Port to listen on (default: from config or 7780)",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Bind address",
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Don't auto-open browser",
    ),
) -> None:
    """Start the TensorTrap web dashboard.

    Launches a local web server with a browser-based UI for viewing
    reports, running scans, and managing configuration.

    Examples:
        tensortrap serve
        tensortrap serve --port 8080
        tensortrap serve --no-browser
    """
    try:
        import uvicorn
    except ImportError:
        console.print("[red]Web UI dependencies not installed.[/red]")
        console.print("Install with: [cyan]pip install tensortrap[web][/cyan]")
        raise typer.Exit(1)

    config = load_config()
    if port is None:
        port = config.get("web", {}).get("port", 7780)

    auto_open = config.get("web", {}).get("auto_open_browser", True)
    if not no_browser and auto_open:
        import threading
        import webbrowser

        def open_browser():
            import time

            time.sleep(1.5)
            webbrowser.open(f"http://{host}:{port}")

        threading.Thread(target=open_browser, daemon=True).start()

    console.print("[bold green]TensorTrap Web UI[/bold green]")
    console.print(f"  Running at: [cyan]http://{host}:{port}[/cyan]")
    console.print("  Press Ctrl+C to stop")
    console.print()

    from tensortrap.web.app import app as web_app

    try:
        uvicorn.run(web_app, host=host, port=port, log_level="warning")
    except KeyboardInterrupt:
        console.print("\n[dim]Shutting down...[/dim]")


@app.command()
def info(
    file: Path = typer.Argument(
        ...,
        help="Model file to inspect",
        exists=True,
    ),
) -> None:
    """Show file metadata without full security scan.

    Displays format, size, and hash information for a model file.

    Examples:
        tensortrap info model.safetensors
    """
    if not file.is_file():
        console.print(f"[red]Error: {file} is not a file[/red]")
        raise typer.Exit(1)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(f"Analyzing {file.name}...", total=None)
        result = scan_file(file, compute_hash=True)

    print_file_info(result)


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"TensorTrap v{__version__}")


@app.callback()
def main() -> None:
    """TensorTrap - Security scanner for AI/ML model files.

    Detect malicious code in pickle, safetensors, and GGUF files
    before loading them.
    """
    pass


if __name__ == "__main__":
    app()
