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
| **Linux** | ✓ Full Support | Ubuntu (Python 3.10-3.12) |
| **Windows** | ✓ Full Support | Windows Server (Python 3.10-3.12) |
| **macOS** | ✓ Full Support | macOS (Python 3.10-3.12) |

All core functionality works identically across platforms. TensorTrap uses pure Python with cross-platform libraries (`pathlib`, `struct`, `zipfile`), ensuring consistent behavior everywhere.

## Installation

```bash
pip install tensortrap
```

For development:
```bash
pip install tensortrap[dev]
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
  -o, --report-dir PATH                 Directory to save reports (default: current directory)
  -f, --report-formats TEXT             Comma-separated formats: txt,json,html,csv (default: all)
```

### Report Generation

When scanning directories, TensorTrap automatically generates reports in multiple formats:

```bash
# Scan with all report formats (default)
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

⠋ Scanning: model.pkl ━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 15/15 0:00:02

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
┌─────────────────────────────────────────────────────────────────┐
│                    AI Workflow Security                         │
├─────────────────────────────────────────────────────────────────┤
│  Downloaded Models    │  Generated Output    │  System Level    │
│  ─────────────────    │  ────────────────    │  ────────────    │
│  TensorTrap ✓         │  Stego ✓             │  RKHunter ✓      │
│  • Pickle exploits    │  • Hidden data       │  • Rootkits      │
│  • Format attacks     │  • Steganography     │  • Backdoors     │
│  • Polyglot files     │                      │                  │
│                       │                      │  ClamAV ✓        │
│  YARA ✓               │                      │  • Known malware │
│  • Known signatures   │                      │  • Viruses       │
└─────────────────────────────────────────────────────────────────┘
```

### Quick Setup

**All Platforms (TensorTrap only):**
```bash
pip install tensortrap
tensortrap scan ./models/
```

**Linux (Full Security Stack):**
```bash
# Install TensorTrap
pip install tensortrap

# Install system tools
sudo apt update
sudo apt install yara rkhunter clamav clamav-daemon

# Initialize ClamAV database
sudo freshclam

# Run comprehensive scan
tensortrap scan ~/Models ~/Downloads    # AI models + polyglot detection
yara -r /path/to/rules ~/Downloads      # Pattern matching
rkhunter --check                        # System integrity
clamscan -r ~/Downloads                 # General malware
```

**Windows:**
```powershell
# Install TensorTrap
pip install tensortrap

# Scan models
tensortrap scan .\models\
tensortrap scan $env:USERPROFILE\Downloads\*.pt
```

**macOS:**
```bash
# Install TensorTrap
pip install tensortrap

# Optional: Install YARA via Homebrew
brew install yara

# Scan models
tensortrap scan ~/Models ~/Downloads
```
## Read More at M2Dynamics.us
[https://m2dynamics.us/2026/01/11/tensortrap/]

## Contributing

Contributions welcome! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

```bash
# Clone the repo
git clone https://github.com/realmarauder/TensorTrap.git
cd TensorTrap

# Install dev dependencies
pip install -e ".[dev]"

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
