"""PyTorch ZIP archive handling.

PyTorch saves models as ZIP archives containing pickle files.
This module extracts and analyzes the internal structure.
"""

import zipfile
from pathlib import Path
from typing import Any


def is_pytorch_zip(filepath: Path) -> bool:
    """Check if file is a PyTorch ZIP archive.

    Args:
        filepath: Path to file

    Returns:
        True if file is a ZIP archive
    """
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            return magic == b"PK\x03\x04" or magic == b"PK\x05\x06"
    except OSError:
        return False


def is_7z_archive(filepath: Path) -> bool:
    """Check if file is a 7z archive (nullifAI bypass).

    Args:
        filepath: Path to file

    Returns:
        True if file is a 7z archive
    """
    try:
        with open(filepath, "rb") as f:
            magic = f.read(6)
            return magic == b"7z\xbc\xaf\x27\x1c"
    except OSError:
        return False


def extract_pickle_files(filepath: Path) -> list[tuple[str, bytes]]:
    """Extract pickle files from a PyTorch ZIP archive.

    Args:
        filepath: Path to ZIP archive

    Returns:
        List of (filename, data) tuples for pickle files
    """
    pickle_files = []

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            for name in zf.namelist():
                # Check for pickle files
                if name.endswith((".pkl", ".pickle", ".pt", ".pth", ".bin")):
                    try:
                        data = zf.read(name)
                        pickle_files.append((name, data))
                    except Exception:
                        pass
                # Also check data.pkl which is common in PyTorch
                elif "data.pkl" in name or name.endswith("/data.pkl"):
                    try:
                        data = zf.read(name)
                        pickle_files.append((name, data))
                    except Exception:
                        pass
    except (OSError, zipfile.BadZipFile):
        pass

    return pickle_files


def analyze_zip_structure(filepath: Path) -> dict[str, Any]:
    """Analyze the structure of a ZIP archive.

    Args:
        filepath: Path to ZIP archive

    Returns:
        Dict with archive information
    """
    is_valid_zip = False
    file_count = 0
    pickle_files: list[str] = []
    suspicious_paths: list[str] = []
    total_uncompressed_size = 0
    error_msg: str | None = None

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            is_valid_zip = True
            file_count = len(zf.namelist())

            for zi in zf.infolist():
                # Track total size
                total_uncompressed_size += zi.file_size

                # Check for pickle files
                if zi.filename.endswith((".pkl", ".pickle", ".pt", ".pth", ".bin")):
                    pickle_files.append(zi.filename)

                # Check for path traversal (ZipSlip)
                if ".." in zi.filename or zi.filename.startswith("/"):
                    suspicious_paths.append(zi.filename)

                # Check for absolute paths
                if zi.filename.startswith(("/", "C:", "\\", "~")):
                    suspicious_paths.append(zi.filename)

    except (OSError, zipfile.BadZipFile) as e:
        error_msg = str(e)

    info: dict[str, Any] = {
        "is_valid_zip": is_valid_zip,
        "file_count": file_count,
        "pickle_files": pickle_files,
        "suspicious_paths": suspicious_paths,
        "total_uncompressed_size": total_uncompressed_size,
    }
    if error_msg:
        info["error"] = error_msg

    return info
