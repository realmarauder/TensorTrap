# TensorTrap Development Context for Claude Code

## Business Context

TensorTrap is the open-source scanner component of M2 Dynamics' AI/ML security consulting practice. It follows a **reputation-first strategy** where the tool serves as a credibility engine rather than a direct revenue source. Revenue comes from professional services; the tool builds the expertise reputation that drives consulting engagements.

**Strategic model**: Cult of the Dead Cow → Back Orifice → Industry leadership

## Target Market

- AI artists using ComfyUI, AUTOMATIC1111, SwarmUI, Stable Diffusion
- Local LLM users running Ollama, LM Studio, text-generation-webui
- Hobbyist developers experimenting with fine-tuned models
- Security engineers and red teams assessing AI infrastructure

## Success Metrics (Year 1)

- 500+ GitHub stars
- 3+ published threat research pieces
- Recognition as the go-to AI model security scanner

## Current Scanner Capabilities

TensorTrap scans these formats:
- Pickle (.pkl, .pt, .pth, .bin, .ckpt, .joblib)
- Safetensors (.safetensors)
- GGUF (.gguf)
- ONNX (.onnx)
- Keras/HDF5 (.h5, .hdf5, .keras)
- YAML configs (.yaml, .yml)
- ComfyUI workflows (.json)

## Polyglot Scanner Addition (In Progress)

The polyglot scanner adds defense-in-depth by detecting:
- Extension mismatches (magic byte vs file extension)
- Archive-in-image attacks (ZIP/7z appended to valid images)
- Pickle-in-image attacks (pickle bytes after image data)
- Double extension tricks (model.pkl.png)
- SVG script injection (<script>, onclick=, javascript:)
- Metadata payloads (code patterns in EXIF/XMP)
- Trailing data (unexpected bytes after image end markers)

This is critical for the target market because ComfyUI users share images containing embedded workflows. Weaponized images are a documented attack vector.

## CVE Coverage

TensorTrap detects attacks documented in these CVEs:
- CVE-2024-34359 (GGUF Jinja SSTI)
- CVE-2024-27318, CVE-2024-5187 (ONNX path traversal)
- CVE-2024-21576, CVE-2024-21577 (ComfyUI eval injection)
- CVE-2025-50460 (YAML unsafe deserialization)
- CVE-2025-1716 (nullifAI 7z bypass)
- CVE-2025-1889 (extension mismatch bypass)
- CVE-2024-12029 (Keras Lambda layers)

## Immediate Priorities

1. Complete polyglot scanner implementation
2. Add GitHub Actions CI/CD (workflows provided)
3. Publish to PyPI
4. First threat research blog post (scan CivitAI models, document findings)

## Framework Integration

TensorTrap implements controls from three M2 Dynamics frameworks:

**Model Threat Lifecycle (MTL)**: Operates at Phase 3 (Delivery) and Phase 4 (Exploitation) detection

**AI Attack Surface Framework (AASF)**: Implements AASF-MA-002 (Pre-Load Model Scanning) and AASF-MP-001 (Safe Serialization Enforcement)

**AI Model Supply Chain Security Framework (AMSCF)**: Supports Level 2 controls for Integrity and Composition domains

## Development Roadmap

- Phase 1 (Current): Python CLI scanner ✓
- Phase 2 (Next): Rust core via PyO3 for performance
- Phase 3 (Future): Tauri desktop application with GUI

## Code Quality Standards

- MIT license for maximum adoption
- Professional Python packaging (src layout, pyproject.toml)
- Type hints throughout
- Ruff for linting/formatting
- pytest for testing
- Multiple report formats (JSON, HTML, CSV, TXT)

## Key Differentiators vs Competition

| Feature | ModelScan | Picklescan | TensorTrap |
|---------|-----------|------------|------------|
| ComfyUI workflows | No | No | Yes |
| Polyglot detection | No | No | Yes |
| Scanner bypass detection | No | No | Yes |
| Multi-format reports | No | No | Yes |
