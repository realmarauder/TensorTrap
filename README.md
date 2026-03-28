# TensorTrap

This is a novel Security scanner for AI/ML model files. It detects malicious code in pickle, safetensors, and GGUF files before loading them into workflows. It also checks output files to see if the model files generated malicious code embedded within media files (e.g., jpeg, png, mp4) that could harm your environment when opening/viewing.

## Why TensorTrap?

AI model files can contain executable code. Pickle files in particular can run arbitrary Python when loaded. TensorTrap analyzes model files without executing them, identifying dangerous patterns before they can harm your system.

**Key statistics:**
- 83.5% of Hugging Face models use pickle-based formats (arbitrary code execution risk)
- 2.1 billion monthly downloads from Hugging Face alone
- 100+ confirmed malicious models discovered on public repositories

## Platform Support

TensorTrap is cross-platform and runs on all major operating systems:

| Platform | Status | CI Tested |
|----------|--------|-----------|
| **Linux** | Full Support | Ubuntu (Python 3.10-3.12) |
| **Windows** | Full Support | Windows Server (Python 3.10-3.12) |
| **macOS** | Full Support | macOS (Python 3.10-3.12) |

All core functionality works identically across platforms. TensorTrap uses pure Python with cross-platform libraries (`pathlib`, `struct`, `zipfile`), ensuring consistent behavior everywhere.

## Installation

### Windows (Recommended: Standalone Executable)

No Python installation required. Download and run:

1. Go to the [Releases](https://github.com/realmarauder/TensorTrap/releases) page
2. Download **`tensortrap-windows-x64.exe`**
3. Move it to a folder in your PATH (e.g., `C:\Program Files\TensorTrap\`)
4. Open Command Prompt or PowerShell and run:

```powershell
tensortrap scan .\models\
```

> **Tip:** To add TensorTrap to your PATH, open System Properties > Environment Variables > edit the `Path` variable and add the folder where you saved the executable.

### Linux / macOS (pip)

```bash
pip install tensortrap
```

### Web Dashboard (All Platforms)

The web dashboard provides a browser-based UI for scanning, viewing reports, and managing configuration. Install the web extras:

```bash
pip install tensortrap[web]
```

### Development

```bash
pip install tensortrap[dev,web]
```

## Web Dashboard

TensorTrap includes a browser-based dashboard that makes scanning and report management accessible without the command line.

### Starting the Dashboard

```bash
tensortrap serve
```

This starts a local web server and automatically opens the dashboard in your browser at `http://127.0.0.1:7780`. To start without opening the browser:

```bash
tensortrap serve --no-browser
tensortrap serve --port 8080    # Custom port
```

### Running a Scan

1. Click **Scan** in the left sidebar
2. Click **Browse** to open the folder picker and navigate to the directory you want to scan, or type the path directly
3. Adjust scan options if needed (recursive scanning, context analysis, confidence threshold)
4. Click **Start Scan**
5. Watch the real-time progress bar as files are scanned
6. When complete, click **View Full Report** to see detailed results

You can navigate to other tabs while a scan is running — the progress is preserved and a banner will show the scan status on other pages.

### Viewing Reports

Click **Reports** in the left sidebar to see all scan reports sorted by date. Click any report to view the full details including:

- Summary statistics (safe files, files with issues, severity breakdown)
- Detailed findings for each flagged file with severity badges
- Confidence scores and recommended actions
- File format, size, and scan time for each result

### What To Do With Report Results

- **Critical / High severity findings**: Do not load these files. Delete them or quarantine them immediately. These indicate known malicious patterns like `os.system` calls or dangerous pickle opcodes.
- **Medium severity findings**: Investigate further. These may be legitimate patterns (like standard pickle REDUCE opcodes) or potential threats. Check the confidence score — high confidence means the finding is more likely to be a real threat.
- **Low / Info findings**: Generally informational. Review if you want to be thorough, but these are unlikely to be threats.
- **Safe files**: No action needed. These files passed all security checks.

### Configuration

Click **Configuration** in the left sidebar to manage all settings from the browser:

**Reports**
- **Report Directory**: Where scan reports are saved (use Browse to select a folder)
- **Retention**: Number of days to keep reports (default: 30, set to 0 to keep forever)
- **Report Formats**: Choose which formats to generate (HTML, TXT, JSON, CSV)

**Web UI**
- **Port**: The port the dashboard runs on (default: 7780)
- **Auto-open browser**: Whether to open the browser automatically when starting the dashboard

**Scheduled Scans**
- **Enable daily scan**: Toggle automatic daily scanning
- **Scan Time**: What time of day to run the scan (24-hour format, default: 03:00)
- **Scan Paths**: Directories to scan automatically (one per line)
- **Scan Options**: Recursive scanning, context analysis, confidence threshold

Click **Save Configuration** to apply changes, **Discard Changes** to revert unsaved edits, or **Reset to Defaults** to restore all settings to their original values.

### Running as a Background Service

To have TensorTrap start automatically when you log in:

```bash
tensortrap service install    # Install and start the service
tensortrap service status     # Check if it's running
tensortrap service restart    # Restart after config changes
tensortrap service uninstall  # Remove the service
```

Once installed, the dashboard is always available at `http://127.0.0.1:7780` — bookmark this URL for easy access.

> **Note:** Background service uses systemd on Linux and launchd on macOS. Logs on macOS are saved to `~/Library/Logs/TensorTrap/`.

## CLI Usage

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

Show file info without full scan:
```bash
tensortrap info model.safetensors
```

### CLI Options

```
tensortrap scan <path> [OPTIONS]

Options:
  -r, --recursive / -R, --no-recursive  Scan directories recursively (default: recursive)
  -j, --json                            Output results as JSON to console
  -v, --verbose                         Show detailed output including info-level findings
  --no-hash                             Skip computing file hashes
  --report / --no-report                Generate report files (default: enabled for directories)
  -o, --report-dir PATH                 Directory to save reports (overrides config)
  -f, --report-formats TEXT             Comma-separated formats: txt,json,html,csv (overrides config)
  --retain-days INT                     Days to keep old reports (overrides config, 0 = keep forever)
  --context-analysis / --no-context-analysis  Context analysis for confidence scoring (default: enabled)
  --external-validation                 Run external tool validation (exiftool/binwalk)
  -c, --confidence-threshold FLOAT      Minimum confidence to report (0.0-1.0, default: 0.5)
  --entropy-threshold FLOAT             Entropy threshold for compressed data (0.0-8.0, default: 7.0)
```

### CLI Configuration

TensorTrap stores configuration in `~/.config/tensortrap/config.toml`. Manage it from the command line:

```bash
tensortrap config init          # Interactive setup
tensortrap config show          # Display current settings
tensortrap config set <key> <value>  # Update a setting
tensortrap config reset         # Restore defaults
```

### Report Generation

When scanning directories, TensorTrap automatically generates reports:

```bash
# Scan with configured report formats (default)
tensortrap scan ./models/

# Disable report generation
tensortrap scan ./models/ --no-report

# Specific formats only
tensortrap scan ./models/ -f txt,html

# Custom output directory
tensortrap scan ./models/ -o ./reports/
```

Reports are saved with timestamps: `tensortrap_report_YYYYMMDD_HHMMSS.{txt,json,html,csv}`

## Supported Formats

| Format | Extensions | Risk Level |
|--------|------------|------------|
| Pickle | .pkl, .pickle, .pt, .pth, .bin, .ckpt, .joblib | High (code execution) |
| PyTorch ZIP | .pt, .pth (ZIP archives) | High (internal pickles) |
| Safetensors | .safetensors | Low (data only) |
| GGUF | .gguf | Medium (template injection) |
| ONNX | .onnx | Medium (path traversal) |
| Keras/HDF5 | .h5, .hdf5, .keras | High (Lambda layers, pickle) |
| YAML | .yaml, .yml | Medium (unsafe deserialization) |
| ComfyUI | .json (workflows) | High (eval nodes) |
| Images | .png, .jpg, .gif, .svg, .webp, .bmp, .tiff, .ico | Medium (polyglot attacks) |
| Video | .mp4, .mkv, .avi, .mov, .webm, .flv, .wmv | Medium (polyglot attacks) |

## What We Detect

### Pickle Files
- **Dangerous imports**: os, subprocess, socket, builtins, sys, etc.
- **Code execution opcodes**: REDUCE, BUILD, GLOBAL, INST, NEWOBJ
- **Known malicious patterns**: os.system, subprocess.Popen, eval, exec
- **Nested pickle attacks**: pickle importing pickle

### Safetensors Files
- **Oversized headers**: Potential DoS attacks
- **Embedded payloads**: Pickle data hidden in metadata
- **Suspicious patterns**: Code snippets in metadata
- **Invalid structure**: Malformed headers, bad tensor offsets

### GGUF Files
- **Invalid format**: Wrong magic number, unknown versions
- **Jinja template injection**: CVE-2024-34359 patterns
- **Anomalous structure**: Excessive tensor/metadata counts
- **Suspicious metadata**: Code patterns in metadata values

### ONNX Files
- **Path traversal**: CVE-2024-27318, CVE-2024-5187 via external_data
- **Suspicious external references**: Access to system files
- **Arbitrary file read/write**: Via malicious external data paths

### Keras/HDF5 Files
- **Lambda layers**: Arbitrary code execution on load
- **Embedded pickle**: Pickle-serialized custom objects
- **Suspicious config patterns**: eval(), exec(), os.system()

### YAML Configuration Files
- **Unsafe deserialization**: !!python/object tags (CVE-2025-50460)
- **Code execution**: subprocess, os.system patterns
- **Dynamic imports**: __import__ patterns

### ComfyUI Workflows
- **Vulnerable nodes**: ACE_ExpressionEval, HueAdjust (CVE-2024-21576/77)
- **Code execution**: eval() patterns in node inputs
- **Arbitrary code**: Malicious workflow structures

### Polyglot & Media Files (Defense-in-Depth)
- **Extension mismatch**: Pickle/archive disguised as image (CVE-2025-1889)
- **Archive-in-image**: ZIP/7z/RAR appended to valid images
- **Archive-in-video**: Archives appended to video files
- **SVG script injection**: JavaScript, onclick handlers, data URIs
- **Metadata payloads**: Malicious code in EXIF/XMP metadata
- **Double extensions**: Tricks like `model.pkl.png`
- **Trailing data**: Hidden data after image end markers
- **MKV attachments**: Embedded files in Matroska containers

### Additional Detections
- **Magic byte analysis**: Detects disguised pickle files (CVE-2025-1889)
- **7z archives**: nullifAI bypass detection (CVE-2025-1716)
- **Obfuscation**: Base64, hex encoding, compression, high entropy
- **PyTorch archives**: Extracts and scans internal pickle files

## Benchmark Results

TensorTrap achieves **100% detection rate** on comprehensive security benchmarks with zero false positives.

### Overall Results

| Metric | Result |
|--------|--------|
| **Overall Accuracy** | 43/43 (100%) |
| **Malicious Detected** | 34/34 (100%) |
| **False Positives** | 0 |
| **False Negatives** | 0 |

### Detection by Category

| Category | Detection Rate |
|----------|---------------|
| Pickle Bypass | 9/9 (100%) |
| JFrog Zero-Days | 6/6 (100%) |
| Polyglot Attacks | 4/4 (100%) |
| GGUF (Jinja Injection) | 1/1 (100%) |
| ONNX (Path Traversal) | 2/2 (100%) |
| YAML (Unsafe Deserialization) | 2/2 (100%) |
| ComfyUI (ACE/Eval) | 2/2 (100%) |
| Keras/HDF5 (Lambda Layer) | 2/2 (100%) |
| Safetensors | 3/3 (100%) |
| SVG (Script Injection) | 3/3 (100%) |
| Benign (No FP) | 9/9 (100%) |

### CVE Coverage

| CVE | Description | Detection |
|-----|-------------|-----------|
| CVE-2025-1716 | nullifAI 7z/pip bypass | 2/2 (100%) |
| CVE-2025-1889 | ZIP trailing data bypass | 2/2 (100%) |
| CVE-2025-10155 | Extension bypass (.bin/.pt) | 2/2 (100%) |
| CVE-2025-10156 | ZIP zeroed CRC bypass | 1/1 (100%) |
| CVE-2025-10157 | asyncio/_posixsubprocess bypass | 3/3 (100%) |
| CVE-2024-34359 | GGUF Jinja template injection | 1/1 (100%) |
| CVE-2024-27318 | ONNX path traversal | 1/1 (100%) |
| CVE-2024-5187 | ONNX arbitrary file read | 1/1 (100%) |
| CVE-2025-50460 | YAML unsafe deserialization | 1/1 (100%) |
| CVE-2024-21576 | ComfyUI ACE eval | 1/1 (100%) |
| CVE-2024-21577 | ComfyUI HueAdjust eval | 1/1 (100%) |

### Running Benchmarks

```bash
# Run comprehensive benchmark suite
python tests/benchmark_comprehensive.py --all

# Setup only (generate test files)
python tests/benchmark_comprehensive.py --setup

# Run tests only (after setup)
python tests/benchmark_comprehensive.py --run

# View latest report
python tests/benchmark_comprehensive.py --report
```

## Exit Codes

- `0`: All files safe (no critical/high findings)
- `1`: Threats detected (critical or high severity findings)

## Example Output

```
Collecting files from ./models/...
Found 15 model file(s)

Scanning: model.pkl ━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 15/15 0:00:02

model.pkl (pickle) - THREATS DETECTED

   Severity   Finding                                    Action
   !! CRITICAL  Known malicious call: os.system           DO NOT LOAD. Delete this file immediately.
   *  MEDIUM    REDUCE opcode found 1 time(s)             Normal for pickle models. Convert to safetensors.

Scanned 15 file(s): 14 safe, 1 with issues
  1 critical, 1 medium

Reports saved:
  TXT:  ./tensortrap_report_20251211_120000.txt
  JSON: ./tensortrap_report_20251211_120000.json
  HTML: ./tensortrap_report_20251211_120000.html
  CSV:  ./tensortrap_report_20251211_120000.csv
```

## JSON Output

```json
{
  "report_type": "tensortrap_security_scan",
  "scan_target": "./models/",
  "scan_date": "2025-12-11T12:00:00",
  "summary": {
    "total_files": 1,
    "safe_files": 0,
    "files_with_issues": 1,
    "findings_by_severity": {"critical": 1, "medium": 1}
  },
  "results": [
    {
      "filepath": "model.pkl",
      "format": "pickle",
      "is_safe": false,
      "max_severity": "critical",
      "findings": [
        {
          "severity": "critical",
          "message": "Known malicious call: os.system",
          "location": 0,
          "details": {"module": "os", "function": "system"},
          "recommendation": "DO NOT LOAD. Delete this file immediately."
        }
      ],
      "scan_time_ms": 1.23,
      "file_size": 256,
      "file_hash": "abc123..."
    }
  ]
}
```

## Defense in Depth

TensorTrap focuses on AI model file security. For comprehensive protection of your AI workflow, we recommend combining TensorTrap with these complementary tools:

### Recommended Security Stack

| Tool | Purpose | Install |
|------|---------|---------|
| **TensorTrap** | AI model file scanning | `pip install tensortrap` |
| **Stego** | Steganography detection | See [stego-toolkit](https://github.com/DominicBreuker/stego-toolkit) |
| **YARA** | Pattern-based malware detection | `apt install yara` / [yara.readthedocs.io](https://yara.readthedocs.io/) |
| **RKHunter** | Rootkit detection | `apt install rkhunter` |
| **ClamAV** | General antivirus | `apt install clamav` |

### What Each Tool Catches

```
                         AI Workflow Security
 ─────────────────────────────────────────────────────────────
  Downloaded Models       Generated Output       System Level
  ─────────────────       ────────────────       ────────────
  TensorTrap              Stego                  RKHunter
  - Pickle exploits       - Hidden data          - Rootkits
  - Format attacks        - Steganography        - Backdoors
  - Polyglot files
                                                 ClamAV
  YARA                                           - Known malware
  - Known signatures                             - Viruses
```

### Quick Setup

**Linux (pip):**
```bash
pip install tensortrap        # CLI only
pip install tensortrap[web]   # CLI + web dashboard

# Optional: full security stack
sudo apt update
sudo apt install yara rkhunter clamav clamav-daemon
sudo freshclam
```

**Windows (Standalone Executable):**

Download `tensortrap-windows-x64.exe` from the [Releases](https://github.com/realmarauder/TensorTrap/releases) page. No Python required.

```powershell
# Scan models
tensortrap scan .\models\
tensortrap scan $env:USERPROFILE\Downloads\*.pt
```

**Windows (pip):**
```powershell
pip install tensortrap
pip install tensortrap[web]   # For the web dashboard
```

**macOS (pip):**
```bash
pip install tensortrap
pip install tensortrap[web]   # For the web dashboard

# Optional: Install YARA via Homebrew
brew install yara
```

**macOS / Linux (Standalone Executable):**

Pre-built binaries are also available on the [Releases](https://github.com/realmarauder/TensorTrap/releases) page:
- `tensortrap-linux-x64`
- `tensortrap-macos-arm64` (Apple Silicon)
- `tensortrap-macos-x64` (Intel)

## Active Research: Workflow Execution Security

TensorTrap is actively researching a critical gap in AI/ML security: **workflow execution attacks**.

Current security tools (including TensorTrap v1.2.0) focus on scanning individual files — detecting malicious pickle opcodes, polyglot attacks, and format exploits. But the next frontier is *workflow-level* security, where the danger isn't in any single file but in how components interact at runtime.

### The Problem

Platforms like [CivitAI](https://civitai.com), [Hugging Face](https://huggingface.co), [ComfyUI](https://github.com/comfyanonymous/ComfyUI), and [Replicate](https://replicate.com) enable users to share AI workflows that reference third-party custom node packages. A workflow JSON file can be completely clean — no malicious code, no eval statements — while still producing malicious behavior through the nodes it invokes.

This affects any platform where users:
- Download and run shared workflows ([CivitAI](https://civitai.com), [OpenArt](https://openart.ai), [ComfyWorkflows](https://comfyworkflows.com))
- Install custom node packages from community repositories ([ComfyUI Manager](https://github.com/ltdrdata/ComfyUI-Manager))
- Execute AI pipelines that combine multiple components ([Hugging Face Spaces](https://huggingface.co/spaces), [RunPod](https://www.runpod.io), [Replicate](https://replicate.com))

### Attack Vectors Under Investigation

| Vector | Description | Risk |
|--------|-------------|------|
| **Malicious Custom Nodes** | Node packages with hidden backdoors, data exfiltration, or reverse shells | Critical |
| **Input Injection** | Workflow values that exploit nodes using `eval()`, `exec()`, or template injection | Critical |
| **Execution Graph Exploitation** | Two benign nodes that create a dangerous combination when connected | High |
| **Workflow-Triggered Downloads** | Nodes that fetch files from attacker-controlled URLs specified in workflows | High |
| **Supply Chain via Package Managers** | Compromised updates to popular custom node packages | Critical |

### Research Plan

We are conducting a 6-phase research program covering landscape survey, vulnerability analysis, dangerous pattern identification, proof-of-concept development, feature design, and implementation. The goal is to build the first tool that analyzes AI workflow execution graphs for security threats.

**Full research document:** [research_projects/comfyui_workflow_execution_analysis.md](research_projects/comfyui_workflow_execution_analysis.md)

### Call for Collaboration

This research has implications for every platform in the AI/ML ecosystem. If you work on AI infrastructure security at any of these organizations, we'd love to collaborate:

- **[CivitAI](https://civitai.com)** — Largest community model and workflow sharing platform
- **[Hugging Face](https://huggingface.co)** — Model hub and Spaces platform
- **[ComfyUI](https://github.com/comfyanonymous/ComfyUI)** — Node-based AI workflow engine
- **[Replicate](https://replicate.com)** — Cloud AI model deployment
- **[RunPod](https://www.runpod.io)** — GPU cloud for AI workloads
- **[Stability AI](https://stability.ai)** — Stable Diffusion ecosystem
- **[OpenArt](https://openart.ai)** — AI art and workflow platform

Contact: smichael.us@gmail.com | [M2 Dynamics](https://m2dynamics.us)

---

## Read More at M2Dynamics.us
[https://m2dynamics.us/2026/01/11/tensortrap/]

## Contributing

Contributions welcome! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

```bash
# Clone the repo
git clone https://github.com/realmarauder/TensorTrap.git
cd TensorTrap

# Install dev dependencies
pip install -e ".[dev,web]"

# Run tests
pytest

# Run linting
ruff check src/
mypy src/
```

## License

MIT License - see [LICENSE](LICENSE).

## About

TensorTrap is developed by [M2 Dynamics](https://m2dynamics.us), specializing in AI/ML security consulting.
