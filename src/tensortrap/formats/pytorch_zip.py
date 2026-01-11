"""PyTorch ZIP archive handling.

PyTorch saves models as ZIP archives containing pickle files.
This module extracts and analyzes the internal structure.

Enhanced with trailing data detection (CVE-2025-1889 style bypass)
and 7z archive pickle scanning.
"""

import struct
import zipfile
from pathlib import Path
from typing import Any

# Pickle protocol signatures for detecting embedded pickles
PICKLE_SIGNATURES = [
    b"\x80\x02",  # Protocol 2
    b"\x80\x03",  # Protocol 3
    b"\x80\x04",  # Protocol 4
    b"\x80\x05",  # Protocol 5
]

# Valid pickle opcodes that should follow the protocol marker
VALID_FRAME_OPCODES = {
    0x63,  # GLOBAL (c)
    0x7D,  # EMPTY_DICT (})
    0x5D,  # EMPTY_LIST (])
    0x29,  # EMPTY_TUPLE ())
    0x28,  # MARK (()
    0x8C,  # SHORT_BINUNICODE
    0x89,  # NEWOBJ_EX
    0x81,  # NEWOBJ
}


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


def scan_zip_raw_for_pickle(filepath: Path) -> dict[str, Any]:
    """Scan ZIP file raw bytes for pickle content (bypasses CRC check).

    CVE-2025-10156: Attackers zero out CRC values to bypass certain scanners.
    This function parses ZIP structure manually and extracts file content
    regardless of CRC validity.

    Args:
        filepath: Path to ZIP file

    Returns:
        Dict with scan results
    """
    result: dict[str, Any] = {
        "has_zeroed_crc": False,
        "zeroed_crc_files": [],
        "contains_pickle": False,
        "pickle_files_found": [],
        "pickle_offsets": [],
        "raw_extraction_success": False,
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError:
        return result

    if len(data) < 30:
        return result

    # Parse local file headers manually
    pos = 0
    while pos < len(data) - 30:
        # Look for local file header signature
        if data[pos : pos + 4] != b"PK\x03\x04":
            pos += 1
            continue

        # Parse local file header
        # Offset 14-17: CRC-32
        # Offset 18-21: Compressed size
        # Offset 22-25: Uncompressed size
        # Offset 26-27: Filename length
        # Offset 28-29: Extra field length

        crc32 = struct.unpack("<I", data[pos + 14 : pos + 18])[0]
        compressed_size = struct.unpack("<I", data[pos + 18 : pos + 22])[0]
        filename_len = struct.unpack("<H", data[pos + 26 : pos + 28])[0]
        extra_len = struct.unpack("<H", data[pos + 28 : pos + 30])[0]

        # Extract filename
        filename_start = pos + 30
        filename_end = filename_start + filename_len
        if filename_end > len(data):
            break
        filename = data[filename_start:filename_end].decode("utf-8", errors="ignore")

        # Detect zeroed CRC
        if crc32 == 0 and compressed_size > 0:
            result["has_zeroed_crc"] = True
            result["zeroed_crc_files"].append(filename)

        # File content starts after header + filename + extra
        content_start = filename_end + extra_len
        content_end = content_start + compressed_size

        if content_end > len(data):
            break

        file_content = data[content_start:content_end]
        result["raw_extraction_success"] = True

        # Check if content looks like pickle
        for pickle_sig in PICKLE_SIGNATURES:
            if file_content.startswith(pickle_sig):
                if _is_valid_pickle_at(file_content, 0):
                    result["contains_pickle"] = True
                    result["pickle_files_found"].append(filename)
                    result["pickle_offsets"].append(content_start)
                break

        # Move to next header
        pos = content_end

    return result


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


def _is_valid_pickle_at(data: bytes, pos: int) -> bool:
    """Validate that a pickle signature at position is followed by valid opcodes.

    This reduces false positives by ensuring the 2-byte protocol marker
    is actually part of a real pickle stream.

    Args:
        data: The full data buffer
        pos: Position of the pickle signature

    Returns:
        True if this looks like a real pickle
    """
    if pos + 2 >= len(data):
        return False

    protocol = data[pos + 1]
    next_byte = data[pos + 2]

    # Protocol 4 and 5: Expect FRAME opcode (0x95) with valid structure
    if protocol >= 4:
        if next_byte != 0x95:  # Must be FRAME
            return False
        # FRAME is followed by 8-byte length
        if pos + 11 >= len(data):
            return False
        frame_len = int.from_bytes(data[pos + 3 : pos + 11], "little")
        # Frame length must be reasonable (1 byte to 100MB)
        if frame_len < 1 or frame_len > 100_000_000:
            return False
        # Check byte after frame header is valid opcode
        if pos + 11 < len(data):
            opcode_after_frame = data[pos + 11]
            if opcode_after_frame not in VALID_FRAME_OPCODES:
                return False
        return True

    # Protocol 2 and 3: Only accept GLOBAL opcode with proper structure
    if protocol in (2, 3):
        if next_byte != 0x63:  # GLOBAL (c)
            return False
        # GLOBAL is followed by "module\nname\n"
        if pos + 10 >= len(data):
            return False
        found_newline = False
        for i in range(pos + 3, min(pos + 258, len(data))):
            b = data[i]
            if b == 0x0A:  # newline
                found_newline = True
                break
            # Must be printable ASCII
            if not (0x2E <= b <= 0x39 or 0x41 <= b <= 0x5A or 0x5F == b or 0x61 <= b <= 0x7A):
                return False
        return found_newline

    return False


def find_zip_end(data: bytes) -> int | None:
    """Find the end of a ZIP archive (after EOCD record).

    ZIP files end with the End of Central Directory (EOCD) record.
    This function finds the EOCD and returns the byte offset just after it.

    Args:
        data: File contents

    Returns:
        Byte offset just after ZIP ends, or None if no valid EOCD found
    """
    # EOCD signature
    eocd_sig = b"PK\x05\x06"

    # Search for EOCD from end (it can have a variable-length comment)
    # EOCD is minimum 22 bytes, max comment is 65535 bytes
    search_start = max(0, len(data) - 65557)

    # Find the LAST occurrence of EOCD signature
    pos = data.rfind(eocd_sig, search_start)

    if pos < 0:
        return None

    # EOCD structure:
    # 4 bytes: signature (PK\x05\x06)
    # 2 bytes: disk number
    # 2 bytes: disk with central directory
    # 2 bytes: entries on this disk
    # 2 bytes: total entries
    # 4 bytes: central directory size
    # 4 bytes: central directory offset
    # 2 bytes: comment length
    # N bytes: comment

    if pos + 22 > len(data):
        return None

    # Read comment length (little-endian uint16 at offset 20)
    comment_len: int = struct.unpack("<H", data[pos + 20 : pos + 22])[0]

    # Calculate end of ZIP
    zip_end: int = pos + 22 + comment_len

    return zip_end


def check_zip_trailing_data(filepath: Path) -> dict[str, Any]:
    """Check for data appended after a ZIP archive (CVE-2025-1889 bypass).

    Attackers can append malicious pickle data after the ZIP EOCD.
    ZIP parsers ignore trailing data, but if the file is loaded as
    a pickle, the trailing malicious code executes.

    Args:
        filepath: Path to ZIP archive

    Returns:
        Dict with trailing data info and any findings
    """
    result: dict[str, Any] = {
        "has_trailing_data": False,
        "zip_end_offset": None,
        "file_size": 0,
        "trailing_size": 0,
        "trailing_contains_pickle": False,
        "pickle_offset": None,
        "pickle_protocol": None,
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError:
        return result

    result["file_size"] = len(data)

    # Find where ZIP ends
    zip_end = find_zip_end(data)
    if zip_end is None:
        return result

    result["zip_end_offset"] = zip_end

    # Check for trailing data
    if zip_end < len(data):
        trailing_size = len(data) - zip_end
        result["has_trailing_data"] = True
        result["trailing_size"] = trailing_size

        # Check if trailing data contains pickle
        trailing_data = data[zip_end:]
        for pickle_sig in PICKLE_SIGNATURES:
            pos = trailing_data.find(pickle_sig)
            if pos >= 0:
                abs_pos = zip_end + pos
                if _is_valid_pickle_at(data, abs_pos):
                    result["trailing_contains_pickle"] = True
                    result["pickle_offset"] = abs_pos
                    result["pickle_protocol"] = pickle_sig[1]
                    break

    return result


def scan_7z_for_pickle(filepath: Path) -> dict[str, Any]:
    """Scan a 7z archive for embedded pickle data (CVE-2025-1889 bypass).

    7z archives can contain pickle files that bypass security scanners.
    This function scans the raw 7z file bytes for pickle signatures.

    Note: We scan raw bytes because extracting 7z requires additional
    dependencies (py7zr). Raw byte scanning catches the most common
    attack patterns where pickle data is embedded directly.

    Args:
        filepath: Path to 7z archive

    Returns:
        Dict with scan results
    """
    result: dict[str, Any] = {
        "is_7z": False,
        "contains_pickle": False,
        "pickle_offsets": [],
        "pickle_protocols": [],
        "file_size": 0,
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError:
        return result

    result["file_size"] = len(data)

    # Verify 7z magic
    if not data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return result

    result["is_7z"] = True

    # Scan for pickle signatures throughout the file
    # Skip the 7z header (first 32 bytes)
    for pickle_sig in PICKLE_SIGNATURES:
        pos = 32  # Start after 7z header
        while pos < len(data):
            pos = data.find(pickle_sig, pos)
            if pos < 0:
                break
            if _is_valid_pickle_at(data, pos):
                result["contains_pickle"] = True
                result["pickle_offsets"].append(pos)
                result["pickle_protocols"].append(pickle_sig[1])
            pos += 1

    return result


def extract_trailing_pickle(filepath: Path) -> bytes | None:
    """Extract pickle data appended after a ZIP archive.

    Args:
        filepath: Path to ZIP file with potential trailing pickle

    Returns:
        Pickle bytes if found, None otherwise
    """
    trailing_info = check_zip_trailing_data(filepath)

    if not trailing_info["trailing_contains_pickle"]:
        return None

    try:
        with open(filepath, "rb") as f:
            f.seek(trailing_info["pickle_offset"])
            return f.read()
    except (OSError, TypeError):
        return None
