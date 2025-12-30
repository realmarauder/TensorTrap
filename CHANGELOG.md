# Changelog

All notable changes to TensorTrap will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.3] - 2025-12-30

### Fixed
- Fix mypy type errors in `external_validators.py` and `cli.py`
- Fix lint errors (import sorting, line length, unused imports)
- Fix broken test for renamed `_check_code_structure_context` method

## [0.3.0] - 2025-12-29

### Added
- **Multi-tier Context Analysis**: Reduces false positive noise while maintaining detection sensitivity
  - **Tier 2: Context Analyzer** (`context_analyzer.py`)
    - Entropy analysis to detect compressed/encrypted regions (threshold: 7.0 bits/byte)
    - Archive structure validation (ZIP, RAR, 7z, GZIP)
    - AI generation metadata detection (ComfyUI, Stable Diffusion, Topaz, Midjourney, DALL-E)
    - Executable code context checking (ASP, PHP, JavaScript, Python, Shell)
    - Confidence scoring: 0.0-1.0 mapped to HIGH/MEDIUM/LOW
  - **Tier 3: External Validators** (`external_validators.py`)
    - exiftool integration for metadata confirmation
    - binwalk integration for archive extraction validation
    - Graceful degradation when tools not installed
- **Adjusted Severity Format**: CRITICAL-HIGH, CRITICAL-MEDIUM, CRITICAL-LOW
  - HIGH confidence: Quarantine immediately
  - MEDIUM confidence: Investigate manually
  - LOW confidence: Likely false positive
- **New CLI Options**:
  - `--context-analysis/--no-context-analysis`: Enable/disable context analysis (default: enabled)
  - `--external-validation/--no-external-validation`: Enable external tool validation
  - `--confidence-threshold`: Minimum confidence to report (0.0-1.0, default: 0.5)
  - `--entropy-threshold`: Entropy threshold for compressed detection (default: 7.0)
- **Enhanced Report Output**:
  - Console shows adjusted severity with confidence percentage
  - Reports include context analysis reasons and external validation status
  - Summary shows confidence level breakdown

### Changed
- Polyglot scanner now uses `scan_polyglot_with_context()` for enriched findings
- Engine passes context analysis options through scan pipeline
- Report generators display adjusted severity and confidence information

### Fixed
- False positives from AI-generated images with embedded metadata (ComfyUI workflows)
- False positives from high-entropy regions in compressed image data
- Pattern matches in random binary data incorrectly flagged as threats

## [0.2.0] - 2025-12-12

### Added
- **Polyglot scanner**: Defense-in-depth detection for image/video polyglot attacks
  - Extension mismatch detection (magic bytes vs file extension)
  - Archive-in-image attacks (ZIP/7z appended to valid images)
  - Pickle-in-image attacks (pickle bytes embedded after image data)
  - Double extension tricks (model.pkl.png)
  - SVG script injection (`<script>`, `onclick=`, `javascript:`)
  - Metadata payload detection (code patterns in EXIF/XMP)
  - Trailing data detection after image end markers
  - Video container analysis (MP4/MKV attachment scanning)
- **ONNX scanner**: Detects path traversal vulnerabilities (CVE-2024-27318, CVE-2024-5187)
- **Keras/HDF5 scanner**: Detects Lambda layers, embedded pickle, suspicious config patterns
- **YAML config scanner**: Detects unsafe deserialization (CVE-2025-50460) and code execution
- **ComfyUI workflow scanner**: Detects vulnerable nodes (CVE-2024-21576, CVE-2024-21577)
- **PyTorch ZIP extraction**: Scans internal pickle files within PyTorch archives
- **Magic byte detection**: Identifies file formats by content, not just extension (CVE-2025-1889)
- **7z archive detection**: Detects nullifAI bypass technique (CVE-2025-1716)
- **Obfuscation detection**: Base64, hex encoding, compression, high entropy analysis
- Support for .onnx, .h5, .hdf5, .keras, .yaml, .yml, .json extensions
- Support for image formats: .png, .jpg, .jpeg, .gif, .bmp, .webp, .svg
- Support for video formats: .mp4, .mov, .avi, .mkv, .webm

### Changed
- Protocol-aware pickle validation to reduce false positives in polyglot detection
- Stricter validation requiring GLOBAL opcode with module structure for protocol 2/3

### Security
- CVE-2024-27318: ONNX path traversal via external_data
- CVE-2024-5187: ONNX arbitrary file read
- CVE-2025-50460: YAML unsafe deserialization
- CVE-2024-21576: ComfyUI HueAdjust eval vulnerability
- CVE-2024-21577: ComfyUI ACE_ExpressionEval vulnerability
- CVE-2025-1889: Pickle files with non-standard extensions
- CVE-2025-1716: nullifAI bypass using 7z compression

## [0.1.0] - 2024-12-11

### Added
- Initial MVP release
- Pickle file scanner with dangerous import/opcode detection
- Safetensors file scanner with header validation
- GGUF file scanner with CVE-2024-34359 template injection detection
- CLI interface with `scan`, `info`, and `version` commands
- JSON output format for tooling integration
- Rich console output with color-coded severity levels
- SHA-256 file hashing
- Recursive directory scanning
- Comprehensive test suite

### Security
- Safe pickle analysis using `pickletools.genops()` (no code execution)
- Detection of 30+ dangerous Python modules
- Known malicious call pattern matching
- Jinja template injection detection for GGUF files
