"""Suspicious patterns to detect in model files."""

import re

# Suspicious string patterns that may indicate malicious content
SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "eval_call",
        re.compile(rb"eval\s*\(", re.IGNORECASE),
        "Potential eval() call detected",
    ),
    (
        "exec_call",
        re.compile(rb"exec\s*\(", re.IGNORECASE),
        "Potential exec() call detected",
    ),
    (
        "import_os",
        re.compile(rb"import\s+os", re.IGNORECASE),
        "Import of os module detected",
    ),
    (
        "import_subprocess",
        re.compile(rb"import\s+subprocess", re.IGNORECASE),
        "Import of subprocess module detected",
    ),
    (
        "dunder_import",
        re.compile(rb"__import__\s*\("),
        "Dynamic import using __import__ detected",
    ),
    (
        "base64_decode",
        re.compile(rb"base64\.(b64decode|decodebytes)", re.IGNORECASE),
        "Base64 decoding detected (potential obfuscation)",
    ),
    (
        "reverse_shell",
        re.compile(rb"socket.*connect.*\d+\.\d+\.\d+\.\d+", re.IGNORECASE | re.DOTALL),
        "Potential reverse shell pattern detected",
    ),
    (
        "powershell",
        re.compile(rb"powershell", re.IGNORECASE),
        "PowerShell reference detected",
    ),
    (
        "cmd_exe",
        re.compile(rb"cmd\.exe|cmd\s*/c", re.IGNORECASE),
        "Windows command prompt reference detected",
    ),
    (
        "bash_shell",
        re.compile(rb"/bin/(ba)?sh", re.IGNORECASE),
        "Unix shell reference detected",
    ),
]

# File extension to format mapping
FORMAT_EXTENSIONS: dict[str, str] = {
    # Pickle-based formats
    ".pkl": "pickle",
    ".pickle": "pickle",
    ".pt": "pickle",  # PyTorch (may be ZIP archive)
    ".pth": "pickle",  # PyTorch (may be ZIP archive)
    ".bin": "pickle",  # Often PyTorch or generic
    ".ckpt": "pickle",  # Checkpoint (legacy SD)
    ".joblib": "pickle",  # Scikit-learn
    # Safetensors
    ".safetensors": "safetensors",
    # GGUF
    ".gguf": "gguf",
    # ONNX
    ".onnx": "onnx",
    # Keras/HDF5
    ".h5": "keras",
    ".hdf5": "keras",
    ".keras": "keras",
    # YAML config files
    ".yaml": "yaml",
    ".yml": "yaml",
    # JSON (for ComfyUI workflows)
    ".json": "json",
    # Image formats (polyglot scanning)
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".webp": "image",
    ".bmp": "image",
    ".svg": "svg",
    ".tiff": "image",
    ".tif": "image",
    ".ico": "image",
    ".avif": "image",
    ".heic": "image",
    ".heif": "image",
    # Video formats (polyglot scanning)
    ".mp4": "video",
    ".webm": "video",
    ".avi": "video",
    ".mov": "video",
    ".mkv": "video",
    ".m4v": "video",
    ".flv": "video",
    ".wmv": "video",
    ".ogv": "video",
    ".3gp": "video",
    ".ts": "video",
    ".mts": "video",
    ".m2ts": "video",
}


def detect_format(filepath) -> str:
    """Detect file format from extension, with magic byte fallback.

    Args:
        filepath: Path to file

    Returns:
        Format name string
    """
    from pathlib import Path

    from tensortrap.formats.magic import detect_format as detect_by_magic

    filepath = Path(filepath)
    ext = filepath.suffix.lower()

    # First try extension-based detection
    ext_format = FORMAT_EXTENSIONS.get(ext)
    if ext_format:
        return ext_format

    # Fall back to magic byte detection for unknown extensions
    # This catches CVE-2025-1889 (non-standard extensions hiding pickle)
    try:
        magic_result = detect_by_magic(filepath)
        if magic_result and magic_result.confidence in ("high", "medium"):
            return magic_result.format
    except Exception:
        pass

    return "unknown"
