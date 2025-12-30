"""Magic byte detection for file format identification.

This module identifies file formats by their magic bytes rather than
relying solely on file extensions, which addresses CVE-2025-1889
(non-standard file extensions hiding pickle files).
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass
class FormatDetection:
    """Result of format detection."""

    format: str
    confidence: str  # "high", "medium", "low"
    magic_match: bool
    extension_match: bool
    details: dict | None = None


# Magic byte signatures for various formats
MAGIC_SIGNATURES = {
    # Pickle protocols
    "pickle_p0": (b"\x80\x00", 0),  # Protocol 0 (rare)
    "pickle_p1": (b"\x80\x01", 0),  # Protocol 1
    "pickle_p2": (b"\x80\x02", 0),  # Protocol 2
    "pickle_p3": (b"\x80\x03", 0),  # Protocol 3
    "pickle_p4": (b"\x80\x04", 0),  # Protocol 4
    "pickle_p5": (b"\x80\x05", 0),  # Protocol 5
    # ZIP (PyTorch models)
    "zip": (b"PK\x03\x04", 0),  # Standard ZIP
    "zip_empty": (b"PK\x05\x06", 0),  # Empty ZIP
    # 7z (nullifAI bypass)
    "7z": (b"7z\xbc\xaf\x27\x1c", 0),
    # GGUF
    "gguf": (b"GGUF", 0),
    # HDF5 (Keras)
    "hdf5": (b"\x89HDF\r\n\x1a\n", 0),
    # ONNX (protobuf)
    "onnx_v1": (b"\x08", 0),  # Field 1, varint
    # NumPy
    "numpy": (b"\x93NUMPY", 0),
    # Tar archives
    "tar": (b"ustar", 257),
    "tar_old": (b"ustar  \x00", 257),
    # Gzip
    "gzip": (b"\x1f\x8b", 0),
}


def detect_format(filepath: Path) -> FormatDetection | None:
    """Detect file format using magic bytes.

    Args:
        filepath: Path to file to analyze

    Returns:
        FormatDetection with format info, or None if unknown
    """
    filepath = Path(filepath)

    try:
        with open(filepath, "rb") as f:
            # Read enough bytes for all signatures
            header = f.read(512)
    except OSError:
        return None

    if len(header) < 2:
        return None

    # Check for pickle (high confidence)
    if header[0] == 0x80 and header[1] <= 5:
        protocol = header[1]
        return FormatDetection(
            format="pickle",
            confidence="high",
            magic_match=True,
            extension_match=filepath.suffix.lower() in (".pkl", ".pickle", ".pt", ".pth", ".bin"),
            details={"protocol": protocol},
        )

    # Check for ZIP (PyTorch archives)
    if header[:4] == b"PK\x03\x04" or header[:4] == b"PK\x05\x06":
        return FormatDetection(
            format="pytorch",
            confidence="high",
            magic_match=True,
            extension_match=filepath.suffix.lower() in (".pt", ".pth", ".zip"),
            details={"type": "zip_archive"},
        )

    # Check for 7z (nullifAI bypass - CVE-2025-1716)
    if header[:6] == b"7z\xbc\xaf\x27\x1c":
        return FormatDetection(
            format="7z_archive",
            confidence="high",
            magic_match=True,
            extension_match=filepath.suffix.lower() == ".7z",
            details={"warning": "7z archives may bypass security scanners"},
        )

    # Check for GGUF
    if header[:4] == b"GGUF":
        return FormatDetection(
            format="gguf",
            confidence="high",
            magic_match=True,
            extension_match=filepath.suffix.lower() == ".gguf",
            details={},
        )

    # Check for HDF5 (Keras)
    if header[:8] == b"\x89HDF\r\n\x1a\n":
        return FormatDetection(
            format="keras",
            confidence="high",
            magic_match=True,
            extension_match=filepath.suffix.lower() in (".h5", ".hdf5", ".keras"),
            details={"type": "hdf5"},
        )

    # Check for gzip (might contain pickle)
    if header[:2] == b"\x1f\x8b":
        return FormatDetection(
            format="gzip",
            confidence="high",
            magic_match=True,
            extension_match=filepath.suffix.lower() in (".gz", ".gzip"),
            details={"warning": "gzip may contain pickle data"},
        )

    # Check for NumPy
    if header[:6] == b"\x93NUMPY":
        return FormatDetection(
            format="numpy",
            confidence="high",
            magic_match=True,
            extension_match=filepath.suffix.lower() in (".npy", ".npz"),
            details={},
        )

    # Check for ONNX (protobuf - less reliable)
    # ONNX starts with protobuf field 1 (ir_version)
    if header[0] == 0x08 and filepath.suffix.lower() == ".onnx":
        return FormatDetection(
            format="onnx",
            confidence="medium",
            magic_match=True,
            extension_match=True,
            details={},
        )

    return None
