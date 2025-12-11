# TensorTrap MVP Specification

## Document Purpose

This specification provides Claude Code with everything needed to build the TensorTrap MVP. It includes project context, technical requirements, architecture decisions, and implementation details.

---

## Project Genesis

### The Problem

AI/ML model files are a significant attack vector. Users download models from Hugging Face, CivitAI, GitHub, and other sources without verification. These files can contain malicious code that executes when the model is loaded.

**Key statistics:**
- 83.5% of Hugging Face models use pickle-based formats (arbitrary code execution risk)
- 2.1 billion monthly downloads from Hugging Face alone
- 100+ confirmed malicious models discovered on public repositories
- Zero commercial desktop scanners exist for prosumer users

### The Opportunity

M2 Dynamics is building TensorTrap as an open-source scanner to:
1. Establish credibility as AI model security experts
2. Support professional services business development
3. Serve an underserved community (AI artists, local LLM users, hobbyists)
4. Generate visibility through useful tooling

### Why Open Source

This is not a product play. The scanner is a credibility engine. We want maximum distribution, community contributions, and name recognition. Revenue comes from consulting services, not software subscriptions.

---

## MVP Scope

### In Scope (Build This)

1. **Pickle file analysis**
   - Parse pickle bytecode without executing
   - Identify dangerous opcodes (GLOBAL, REDUCE, BUILD, INST)
   - Flag dangerous imports (os, subprocess, socket, sys, builtins, etc.)
   - Support .pkl, .pickle, .pt, .pth, .bin, .ckpt extensions

2. **Safetensors validation**
   - Validate header structure
   - Check for oversized headers (potential DoS)
   - Detect embedded pickle data in metadata
   - Verify tensor offset integrity

3. **GGUF validation**
   - Validate magic number and version
   - Check metadata structure
   - Flag suspicious metadata keys
   - Basic format integrity checks

4. **CLI interface**
   - `tensortrap scan <path>` - Scan file or directory
   - `tensortrap info <file>` - Show file metadata without full scan
   - `tensortrap version` - Show version info
   - Support for glob patterns
   - Recursive directory scanning

5. **Output formats**
   - Human-readable console output (default)
   - JSON output (--json flag) for tooling integration
   - Configurable verbosity levels

6. **Cross-platform support**
   - Linux (primary development platform)
   - macOS
   - Windows

### Out of Scope (Do Not Build Yet)

- GUI/desktop application
- Real-time file system monitoring
- Signature database updates
- YARA rule support
- Fuzzy hash matching
- Browser extensions
- Platform integrations (ComfyUI, LM Studio)
- Rust/PyO3 performance optimization

---

## Technical Architecture

### Project Structure

```
tensortrap/
├── pyproject.toml          # Project metadata, dependencies
├── README.md               # Installation, usage, contributing
├── LICENSE                 # MIT license
├── CHANGELOG.md            # Version history
├── .gitignore
├── src/
│   └── tensortrap/
│       ├── __init__.py     # Package init, version
│       ├── __main__.py     # Entry point for python -m tensortrap
│       ├── cli.py          # Typer CLI definitions
│       ├── scanner/
│       │   ├── __init__.py
│       │   ├── engine.py   # Main scanning orchestrator
│       │   ├── pickle_scanner.py
│       │   ├── safetensors_scanner.py
│       │   ├── gguf_scanner.py
│       │   └── results.py  # Result data structures
│       ├── formats/
│       │   ├── __init__.py
│       │   ├── pickle_parser.py   # Low-level pickle parsing
│       │   ├── safetensors_parser.py
│       │   └── gguf_parser.py
│       ├── signatures/
│       │   ├── __init__.py
│       │   ├── dangerous_imports.py  # Known dangerous modules/functions
│       │   └── patterns.py           # Known malicious patterns
│       └── output/
│           ├── __init__.py
│           ├── console.py    # Rich console output
│           └── json_output.py
├── tests/
│   ├── __init__.py
│   ├── test_pickle_scanner.py
│   ├── test_safetensors_scanner.py
│   ├── test_gguf_scanner.py
│   └── fixtures/            # Test model files
│       ├── safe_model.safetensors
│       ├── malicious_pickle.pkl
│       └── valid_gguf.gguf
└── docs/
    ├── CONTRIBUTING.md
    └── SECURITY.md
```

### Dependencies

```toml
[project]
name = "tensortrap"
version = "0.1.0"
description = "Security scanner for AI/ML model files"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.10"
authors = [
    {name = "M2 Dynamics", email = "contact@m2dynamics.us"}
]
keywords = ["security", "ai", "ml", "machine-learning", "scanner", "pickle", "safetensors"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
    "Topic :: Scientific/Engineering :: Artificial Intelligence",
]

dependencies = [
    "typer>=0.9.0",
    "rich>=13.0.0",
    "safetensors>=0.4.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-cov>=4.0.0",
    "black>=23.0.0",
    "ruff>=0.1.0",
    "mypy>=1.0.0",
]

[project.scripts]
tensortrap = "tensortrap.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/tensortrap"]
```

---

## Implementation Details

### Pickle Scanner

The pickle scanner is the most critical component. Pickle files can execute arbitrary code during deserialization via the `__reduce__` method.

**Dangerous opcodes to detect:**

| Opcode | Name | Risk |
|--------|------|------|
| 0x63 | GLOBAL | Imports arbitrary module.attribute |
| 0x52 | REDUCE | Calls callable with args |
| 0x62 | BUILD | Sets instance attributes |
| 0x69 | INST | Creates class instance |
| 0x6f | OBJ | Creates object |
| 0x81 | NEWOBJ | Creates object (protocol 2+) |
| 0x92 | NEWOBJ_EX | Creates object with kwargs |
| 0x93 | STACK_GLOBAL | Imports from stack |

**Dangerous imports to flag:**

```python
DANGEROUS_MODULES = {
    "os",
    "sys", 
    "subprocess",
    "socket",
    "builtins",
    "commands",  # Python 2 legacy
    "pty",
    "posix",
    "nt",
    "io",
    "code",
    "codeop",
    "pickle",  # Nested pickle
    "marshal",
    "shelve",
    "tempfile",
    "shutil",
    "signal",
    "ctypes",
    "multiprocessing",
    "concurrent",
    "_thread",
    "threading",
    "asyncio",
    "importlib",
    "runpy",
    "pkgutil",
    "urllib",
    "http",
    "ftplib",
    "smtplib",
    "telnetlib",
    "requests",  # Third-party but common
    "httpx",
    "aiohttp",
}

DANGEROUS_FUNCTIONS = {
    "eval",
    "exec",
    "compile",
    "open",
    "input",  
    "breakpoint",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
}
```

**Implementation approach:**

Do NOT use Python's pickle module to load the file. Parse the bytecode directly using the `pickletools` module (safe) or custom parsing.

```python
import pickletools
import io

def analyze_pickle(data: bytes) -> list[Finding]:
    """Analyze pickle bytecode without executing."""
    findings = []
    
    try:
        ops = list(pickletools.genops(io.BytesIO(data)))
    except Exception as e:
        findings.append(Finding(
            severity="error",
            message=f"Failed to parse pickle: {e}",
            location=None
        ))
        return findings
    
    for opcode, arg, pos in ops:
        if opcode.name == "GLOBAL":
            module, name = arg.split(" ", 1) if " " in arg else (arg, "")
            if module in DANGEROUS_MODULES:
                findings.append(Finding(
                    severity="critical",
                    message=f"Dangerous import: {module}.{name}",
                    location=pos
                ))
        elif opcode.name == "REDUCE":
            findings.append(Finding(
                severity="high", 
                message="REDUCE opcode found (function call)",
                location=pos
            ))
        # ... etc
    
    return findings
```

### Safetensors Scanner

Safetensors is designed to be safe (no code execution), but we still validate:

1. **Header size** - Must be reasonable (not gigabytes)
2. **Header JSON** - Valid JSON, no embedded code
3. **Metadata inspection** - Check for suspicious keys
4. **Tensor offsets** - Must be within file bounds

```python
def analyze_safetensors(filepath: Path) -> list[Finding]:
    """Analyze safetensors file structure."""
    findings = []
    
    with open(filepath, "rb") as f:
        # First 8 bytes are header size (little-endian u64)
        header_size_bytes = f.read(8)
        header_size = int.from_bytes(header_size_bytes, "little")
        
        # Sanity check header size
        if header_size > 100_000_000:  # 100MB header is suspicious
            findings.append(Finding(
                severity="high",
                message=f"Unusually large header: {header_size} bytes",
                location=0
            ))
            return findings
        
        # Read and parse header JSON
        header_json = f.read(header_size)
        try:
            header = json.loads(header_json)
        except json.JSONDecodeError as e:
            findings.append(Finding(
                severity="critical",
                message=f"Invalid header JSON: {e}",
                location=8
            ))
            return findings
        
        # Check for __metadata__ section
        metadata = header.get("__metadata__", {})
        
        # Look for suspicious patterns in metadata
        for key, value in metadata.items():
            if isinstance(value, str):
                # Check for embedded pickle
                if value.startswith("\\x80"):  # Pickle magic
                    findings.append(Finding(
                        severity="critical",
                        message=f"Possible embedded pickle in metadata key: {key}",
                        location=8
                    ))
                # Check for suspicious strings
                for pattern in ["eval(", "exec(", "import os", "__import__"]:
                    if pattern in value:
                        findings.append(Finding(
                            severity="high",
                            message=f"Suspicious pattern '{pattern}' in metadata",
                            location=8
                        ))
    
    return findings
```

### GGUF Scanner

GGUF (GPT-Generated Unified Format) is used by llama.cpp. Validate structure and check for anomalies.

```python
GGUF_MAGIC = 0x46554747  # "GGUF" in little-endian

def analyze_gguf(filepath: Path) -> list[Finding]:
    """Analyze GGUF file structure."""
    findings = []
    
    with open(filepath, "rb") as f:
        # Check magic number
        magic = int.from_bytes(f.read(4), "little")
        if magic != GGUF_MAGIC:
            findings.append(Finding(
                severity="critical",
                message=f"Invalid GGUF magic number: {hex(magic)}",
                location=0
            ))
            return findings
        
        # Read version
        version = int.from_bytes(f.read(4), "little")
        if version not in (1, 2, 3):
            findings.append(Finding(
                severity="medium",
                message=f"Unknown GGUF version: {version}",
                location=4
            ))
        
        # Read tensor count and metadata kv count
        tensor_count = int.from_bytes(f.read(8), "little")
        metadata_kv_count = int.from_bytes(f.read(8), "little")
        
        # Sanity checks
        if tensor_count > 100000:
            findings.append(Finding(
                severity="high",
                message=f"Unusually high tensor count: {tensor_count}",
                location=8
            ))
        
        if metadata_kv_count > 10000:
            findings.append(Finding(
                severity="high",
                message=f"Unusually high metadata count: {metadata_kv_count}",
                location=16
            ))
        
        # Check for chat_template (potential Jinja injection - CVE-2024-34359)
        # This requires parsing the KV pairs to find it
        # ... implementation details ...
    
    return findings
```

### Result Data Structures

```python
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
import json

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Finding:
    severity: Severity
    message: str
    location: Optional[int] = None  # Byte offset
    details: Optional[dict] = None

@dataclass  
class ScanResult:
    filepath: Path
    format: str  # "pickle", "safetensors", "gguf", "unknown"
    findings: list[Finding] = field(default_factory=list)
    scan_time_ms: float = 0.0
    file_size: int = 0
    file_hash: str = ""  # SHA-256
    
    @property
    def is_safe(self) -> bool:
        return not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)
    
    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in severity_order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None
    
    def to_dict(self) -> dict:
        return {
            "filepath": str(self.filepath),
            "format": self.format,
            "is_safe": self.is_safe,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "findings": [
                {
                    "severity": f.severity.value,
                    "message": f.message,
                    "location": f.location,
                    "details": f.details,
                }
                for f in self.findings
            ],
            "scan_time_ms": self.scan_time_ms,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
```

### CLI Implementation

```python
import typer
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table

from tensortrap.scanner.engine import scan_file, scan_directory
from tensortrap.output.console import print_results
from tensortrap.output.json_output import output_json

app = typer.Typer(
    name="tensortrap",
    help="Security scanner for AI/ML model files",
    add_completion=False,
)
console = Console()

@app.command()
def scan(
    path: Path = typer.Argument(..., help="File or directory to scan"),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", "-r", help="Scan directories recursively"),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output results as JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
):
    """Scan model files for security issues."""
    if path.is_file():
        results = [scan_file(path)]
    elif path.is_dir():
        results = scan_directory(path, recursive=recursive)
    else:
        console.print(f"[red]Error: {path} does not exist[/red]")
        raise typer.Exit(1)
    
    if json_output:
        output_json(results)
    else:
        print_results(results, verbose=verbose)
    
    # Exit with error code if any critical/high findings
    if any(not r.is_safe for r in results):
        raise typer.Exit(1)

@app.command()
def info(
    file: Path = typer.Argument(..., help="Model file to inspect"),
):
    """Show file metadata without full security scan."""
    # Implementation: show format, size, basic structure info
    pass

@app.command()
def version():
    """Show version information."""
    from tensortrap import __version__
    console.print(f"TensorTrap v{__version__}")

if __name__ == "__main__":
    app()
```

### Console Output

Use Rich library for attractive, readable output:

```python
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

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
    Severity.CRITICAL: "🚨",
    Severity.HIGH: "⚠️",
    Severity.MEDIUM: "⚡",
    Severity.LOW: "ℹ️",
    Severity.INFO: "📝",
}

def print_results(results: list[ScanResult], verbose: bool = False):
    """Print scan results to console."""
    
    for result in results:
        # Header
        status = "[green]✓ SAFE[/green]" if result.is_safe else "[red]✗ THREATS DETECTED[/red]"
        console.print(f"\n[bold]{result.filepath}[/bold] ({result.format}) - {status}")
        
        if not result.findings:
            if verbose:
                console.print("  No issues found")
            continue
        
        # Findings table
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        table.add_column("Severity", width=10)
        table.add_column("Finding", no_wrap=False)
        
        for finding in sorted(result.findings, key=lambda f: list(Severity).index(f.severity)):
            icon = SEVERITY_ICONS[finding.severity]
            style = SEVERITY_COLORS[finding.severity]
            table.add_row(
                f"{icon} [{style}]{finding.severity.value.upper()}[/{style}]",
                finding.message
            )
        
        console.print(table)
    
    # Summary
    console.print()
    total = len(results)
    safe = sum(1 for r in results if r.is_safe)
    console.print(f"Scanned {total} file(s): {safe} safe, {total - safe} with issues")
```

---

## File Extension Mapping

```python
FORMAT_EXTENSIONS = {
    # Pickle-based formats
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".pt": "pickle",      # PyTorch
    ".pth": "pickle",     # PyTorch
    ".bin": "pickle",     # Often PyTorch or generic
    ".ckpt": "pickle",    # Checkpoint (legacy SD)
    ".joblib": "pickle",  # Scikit-learn
    
    # Safetensors
    ".safetensors": "safetensors",
    
    # GGUF
    ".gguf": "gguf",
    
    # Keras/HDF5 (future)
    # ".h5": "hdf5",
    # ".keras": "keras",
}

def detect_format(filepath: Path) -> str:
    """Detect file format from extension."""
    ext = filepath.suffix.lower()
    return FORMAT_EXTENSIONS.get(ext, "unknown")
```

---

## Testing Requirements

### Test Cases for Pickle Scanner

1. **Safe pickle file** - Simple data, no dangerous opcodes
2. **Obvious malicious pickle** - Contains `os.system` call
3. **Subtle malicious pickle** - Uses `builtins.getattr` indirection
4. **Nested pickle** - Pickle within pickle
5. **Corrupted pickle** - Invalid bytecode
6. **Empty file** - Zero bytes
7. **Large file** - Performance test

### Test Cases for Safetensors Scanner

1. **Valid safetensors** - Proper structure, clean metadata
2. **Oversized header** - Header claims to be larger than file
3. **Embedded pickle in metadata** - Metadata contains pickle bytes
4. **Invalid JSON header** - Malformed JSON
5. **Suspicious metadata patterns** - Contains "eval(" strings

### Test Cases for GGUF Scanner

1. **Valid GGUF** - Proper structure
2. **Invalid magic** - Wrong magic bytes
3. **Unknown version** - Version 99
4. **Chat template present** - Should flag for review
5. **Excessive tensor count** - Sanity check failure

---

## README Template

```markdown
# TensorTrap

Security scanner for AI/ML model files. Detect malicious code in pickle, safetensors, and GGUF files before loading them.

## Why TensorTrap?

AI model files can contain executable code. Pickle files in particular can run arbitrary Python when loaded. TensorTrap analyzes model files without executing them, identifying dangerous patterns before they can harm your system.

## Installation

```bash
pip install tensortrap
```

## Usage

Scan a single file:
```bash
tensortrap scan model.safetensors
```

Scan a directory:
```bash
tensortrap scan ./models/
```

Output as JSON (for tooling integration):
```bash
tensortrap scan model.pkl --json
```

## Supported Formats

| Format | Extensions | Risk Level |
|--------|------------|------------|
| Pickle | .pkl, .pickle, .pt, .pth, .bin, .ckpt | High (code execution) |
| Safetensors | .safetensors | Low (data only) |
| GGUF | .gguf | Medium (template injection) |

## What We Detect

- **Dangerous imports**: os, subprocess, socket, etc.
- **Code execution opcodes**: REDUCE, BUILD, GLOBAL
- **Embedded payloads**: Pickle data hidden in metadata
- **Format anomalies**: Oversized headers, invalid structure

## Contributing

Contributions welcome! See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

MIT License - see [LICENSE](LICENSE).

## About

TensorTrap is developed by [M2 Dynamics](https://m2dynamics.us), specializing in AI/ML security consulting.
```

---

## Success Criteria for MVP

1. **Functional**: Scans pickle, safetensors, and GGUF files without crashing
2. **Accurate**: Detects known malicious patterns (test against fixtures)
3. **Fast**: Scans typical model files (<1GB) in under 5 seconds
4. **Usable**: Clear CLI interface, helpful error messages
5. **Documented**: README with installation and usage instructions
6. **Distributable**: Installable via pip
7. **Tested**: Core functionality has test coverage

---

## Handoff Notes for Claude Code

When building this:

1. Start with the project structure and pyproject.toml
2. Build the data structures (results.py) first
3. Implement pickle scanner as priority (highest risk format)
4. Add safetensors scanner
5. Add GGUF scanner
6. Build CLI layer
7. Add console output formatting
8. Write tests
9. Create README and LICENSE

The user runs Pop!_OS Linux, so focus on Linux compatibility first. They will test on real model files from CivitAI and Hugging Face.

This is an open-source project. Write clean, documented code that community members could contribute to.
