"""Low-level GGUF format parser.

GGUF (GPT-Generated Unified Format) is used by llama.cpp.

Format structure:
- 4 bytes: magic number "GGUF" (0x46554747 little-endian)
- 4 bytes: version (u32)
- 8 bytes: tensor count (u64)
- 8 bytes: metadata kv count (u64)
- Metadata key-value pairs
- Tensor info
- Tensor data
"""

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

# GGUF magic number: "GGUF" in ASCII
GGUF_MAGIC = 0x46554747

# Supported GGUF versions
SUPPORTED_VERSIONS = {1, 2, 3}


class GGUFValueType(IntEnum):
    """GGUF metadata value types."""

    UINT8 = 0
    INT8 = 1
    UINT16 = 2
    INT16 = 3
    UINT32 = 4
    INT32 = 5
    FLOAT32 = 6
    BOOL = 7
    STRING = 8
    ARRAY = 9
    UINT64 = 10
    INT64 = 11
    FLOAT64 = 12


@dataclass
class GGUFHeader:
    """Parsed GGUF file header."""

    magic: int
    version: int
    tensor_count: int
    metadata_kv_count: int
    metadata: dict[str, Any] = field(default_factory=dict)


def read_string(f) -> str:
    """Read a GGUF string (length-prefixed)."""
    length = struct.unpack("<Q", f.read(8))[0]
    if length > 10_000_000:  # 10MB string limit
        raise ValueError(f"String too long: {length}")
    data: bytes = f.read(length)
    return data.decode("utf-8", errors="replace")


def read_value(f, value_type: int) -> Any:
    """Read a value of the given type."""
    if value_type == GGUFValueType.UINT8:
        return struct.unpack("<B", f.read(1))[0]
    elif value_type == GGUFValueType.INT8:
        return struct.unpack("<b", f.read(1))[0]
    elif value_type == GGUFValueType.UINT16:
        return struct.unpack("<H", f.read(2))[0]
    elif value_type == GGUFValueType.INT16:
        return struct.unpack("<h", f.read(2))[0]
    elif value_type == GGUFValueType.UINT32:
        return struct.unpack("<I", f.read(4))[0]
    elif value_type == GGUFValueType.INT32:
        return struct.unpack("<i", f.read(4))[0]
    elif value_type == GGUFValueType.FLOAT32:
        return struct.unpack("<f", f.read(4))[0]
    elif value_type == GGUFValueType.BOOL:
        return struct.unpack("<B", f.read(1))[0] != 0
    elif value_type == GGUFValueType.STRING:
        return read_string(f)
    elif value_type == GGUFValueType.UINT64:
        return struct.unpack("<Q", f.read(8))[0]
    elif value_type == GGUFValueType.INT64:
        return struct.unpack("<q", f.read(8))[0]
    elif value_type == GGUFValueType.FLOAT64:
        return struct.unpack("<d", f.read(8))[0]
    elif value_type == GGUFValueType.ARRAY:
        array_type = struct.unpack("<I", f.read(4))[0]
        array_len = struct.unpack("<Q", f.read(8))[0]
        if array_len > 1_000_000:  # Limit array size
            raise ValueError(f"Array too long: {array_len}")
        return [read_value(f, array_type) for _ in range(array_len)]
    else:
        raise ValueError(f"Unknown value type: {value_type}")


def parse_header(filepath: Path, max_metadata: int = 1000) -> tuple[GGUFHeader | None, str | None]:
    """Parse GGUF file header and metadata.

    Args:
        filepath: Path to GGUF file
        max_metadata: Maximum number of metadata entries to read

    Returns:
        Tuple of (header, error_message)
    """
    try:
        with open(filepath, "rb") as f:
            # Read magic number
            magic_bytes = f.read(4)
            if len(magic_bytes) < 4:
                return None, "File too small to contain GGUF header"

            magic = struct.unpack("<I", magic_bytes)[0]
            if magic != GGUF_MAGIC:
                return (
                    None,
                    f"Invalid magic number: {hex(magic)} (expected {hex(GGUF_MAGIC)})",
                )

            # Read version
            version = struct.unpack("<I", f.read(4))[0]

            # Read counts
            tensor_count = struct.unpack("<Q", f.read(8))[0]
            metadata_kv_count = struct.unpack("<Q", f.read(8))[0]

            header = GGUFHeader(
                magic=magic,
                version=version,
                tensor_count=tensor_count,
                metadata_kv_count=metadata_kv_count,
            )

            # Read metadata (up to max_metadata entries)
            entries_to_read = min(metadata_kv_count, max_metadata)
            for _ in range(entries_to_read):
                try:
                    key = read_string(f)
                    value_type = struct.unpack("<I", f.read(4))[0]
                    value = read_value(f, value_type)
                    header.metadata[key] = value
                except Exception:
                    # Stop reading metadata on error but return what we have
                    break

            return header, None

    except OSError as e:
        return None, f"Failed to read file: {e}"
    except struct.error as e:
        return None, f"Failed to parse header: {e}"
    except Exception as e:
        return None, f"Unexpected error: {e}"


def get_chat_template(header: GGUFHeader) -> str | None:
    """Extract chat template from GGUF metadata if present.

    Args:
        header: Parsed GGUF header

    Returns:
        Chat template string if present, None otherwise
    """
    # Common keys for chat templates
    template_keys = [
        "tokenizer.chat_template",
        "chat_template",
    ]

    for key in template_keys:
        if key in header.metadata:
            value = header.metadata[key]
            if isinstance(value, str):
                return value

    return None
