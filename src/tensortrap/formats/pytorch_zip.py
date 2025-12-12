"""PyTorch ZIP archive handling.

PyTorch saves models as ZIP archives containing pickle files.
This module extracts and analyzes the internal structure.
"""

import zipfile
from pathlib import Path


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


def analyze_zip_structure(filepath: Path) -> dict:
    """Analyze the structure of a ZIP archive.

    Args:
        filepath: Path to ZIP archive

    Returns:
        Dict with archive information
    """
    info = {
        "is_valid_zip": False,
        "file_count": 0,
        "pickle_files": [],
        "suspicious_paths": [],
        "total_uncompressed_size": 0,
    }

    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            info["is_valid_zip"] = True
            info["file_count"] = len(zf.namelist())

            for zi in zf.infolist():
                # Track total size
                info["total_uncompressed_size"] += zi.file_size

                # Check for pickle files
                if zi.filename.endswith((".pkl", ".pickle", ".pt", ".pth", ".bin")):
                    info["pickle_files"].append(zi.filename)

                # Check for path traversal (ZipSlip)
                if ".." in zi.filename or zi.filename.startswith("/"):
                    info["suspicious_paths"].append(zi.filename)

                # Check for absolute paths
                if zi.filename.startswith(("/", "C:", "\\", "~")):
                    info["suspicious_paths"].append(zi.filename)

    except (OSError, zipfile.BadZipFile) as e:
        info["error"] = str(e)

    return info
