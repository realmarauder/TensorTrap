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
        help="Directory to save reports (default: current directory)",
    ),
    report_formats: str | None = typer.Option(
        None,
        "--report-formats",
        "-f",
        help="Comma-separated report formats: txt,json,html,csv (default: all)",
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
    """
    compute_hash = not no_hash

    # Parse report formats
    formats = None
    if report_formats:
        formats = [f.strip().lower() for f in report_formats.split(",")]
        valid_formats = {"txt", "json", "html", "csv"}
        invalid = set(formats) - valid_formats
        if invalid:
            console.print(f"[red]Invalid report formats: {', '.join(invalid)}[/red]")
            console.print(f"[dim]Valid formats: {', '.join(valid_formats)}[/dim]")
            raise typer.Exit(1)

    # Set default report directory
    if report_dir is None:
        report_dir = Path.cwd()

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
            )

        console.print("[bold green]Reports saved:[/bold green]")
        for fmt, filepath in saved_files.items():
            console.print(f"  [cyan]{fmt.upper()}:[/cyan] {filepath}")

    # Exit with error code if any critical/high findings
    if any(not r.is_safe for r in results):
        raise typer.Exit(1)


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
