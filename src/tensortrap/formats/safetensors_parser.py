"""Low-level safetensors format parser.

Safetensors format:
- 8 bytes: header size (little-endian u64)
- N bytes: header JSON
- Rest: tensor data
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SafetensorsHeader:
    """Parsed safetensors header information."""

    header_size: int
    tensors: dict[str, dict[str, Any]]
    metadata: dict[str, str]
    raw_json: str


def parse_header(filepath: Path) -> tuple[SafetensorsHeader | None, str | None]:
    """Parse safetensors file header.

    Args:
        filepath: Path to safetensors file

    Returns:
        Tuple of (header, error_message)
    """
    try:
        with open(filepath, "rb") as f:
            # Read header size (8 bytes, little-endian u64)
            header_size_bytes = f.read(8)
            if len(header_size_bytes) < 8:
                return None, "File too small to contain header size"

            header_size = int.from_bytes(header_size_bytes, "little")

            # Sanity check header size
            file_size = filepath.stat().st_size
            if header_size > file_size - 8:
                return (
                    None,
                    f"Header size ({header_size}) exceeds file size ({file_size})",
                )

            if header_size > 100_000_000:  # 100MB header is suspicious
                return None, f"Header size suspiciously large: {header_size} bytes"

            # Read header JSON
            header_json_bytes = f.read(header_size)
            if len(header_json_bytes) < header_size:
                return None, "File truncated before end of header"

            try:
                header_json = header_json_bytes.decode("utf-8")
            except UnicodeDecodeError as e:
                return None, f"Header is not valid UTF-8: {e}"

            try:
                header_data = json.loads(header_json)
            except json.JSONDecodeError as e:
                return None, f"Invalid JSON in header: {e}"

            if not isinstance(header_data, dict):
                return (
                    None,
                    f"Header must be a JSON object, got {type(header_data).__name__}",
                )

            # Extract metadata (special __metadata__ key)
            metadata = header_data.pop("__metadata__", {})
            if not isinstance(metadata, dict):
                metadata = {}

            return (
                SafetensorsHeader(
                    header_size=header_size,
                    tensors=header_data,
                    metadata=metadata,
                    raw_json=header_json,
                ),
                None,
            )

    except OSError as e:
        return None, f"Failed to read file: {e}"


def validate_tensor_offsets(filepath: Path, header: SafetensorsHeader) -> list[tuple[str, str]]:
    """Validate that tensor offsets are within file bounds.

    Args:
        filepath: Path to safetensors file
        header: Parsed header

    Returns:
        List of (tensor_name, error_message) tuples for invalid tensors
    """
    errors = []
    file_size = filepath.stat().st_size
    data_start = 8 + header.header_size

    for name, tensor_info in header.tensors.items():
        if not isinstance(tensor_info, dict):
            errors.append((name, f"Tensor info is not a dict: {type(tensor_info).__name__}"))
            continue

        offsets = tensor_info.get("data_offsets")
        if offsets is None:
            errors.append((name, "Missing data_offsets"))
            continue

        if not isinstance(offsets, list) or len(offsets) != 2:
            errors.append((name, f"Invalid data_offsets format: {offsets}"))
            continue

        start, end = offsets
        absolute_start = data_start + start
        absolute_end = data_start + end

        if absolute_start > file_size:
            errors.append(
                (
                    name,
                    f"Tensor start offset ({absolute_start}) exceeds file size ({file_size})",
                )
            )
        if absolute_end > file_size:
            errors.append(
                (
                    name,
                    f"Tensor end offset ({absolute_end}) exceeds file size ({file_size})",
                )
            )
        if start > end:
            errors.append((name, f"Tensor start ({start}) > end ({end})"))

    return errors
