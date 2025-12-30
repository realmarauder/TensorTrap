"""Pytest fixtures for ModelGuard tests."""

import json
import pickle
import struct

import pytest


@pytest.fixture
def fixtures_dir(tmp_path):
    """Create a temporary fixtures directory."""
    return tmp_path


@pytest.fixture
def safe_pickle_file(fixtures_dir):
    """Create a safe pickle file with just data."""
    filepath = fixtures_dir / "safe.pkl"
    data = {"name": "test", "values": [1, 2, 3]}
    with open(filepath, "wb") as f:
        pickle.dump(data, f)
    return filepath


@pytest.fixture
def malicious_pickle_bytes():
    """Create malicious pickle bytecode that imports os.system.

    This creates pickle bytecode WITHOUT executing anything dangerous.
    It just crafts the bytes that would be dangerous if loaded.
    """
    # Protocol 4 pickle that does: os.system("echo pwned")
    # We craft this manually to avoid any actual code execution
    malicious = (
        b"\x80\x04"  # Protocol 4
        b"\x95\x1e\x00\x00\x00\x00\x00\x00\x00"  # Frame
        b"\x8c\x02os"  # Short string "os"
        b"\x94"  # Memoize
        b"\x8c\x06system"  # Short string "system"
        b"\x94"  # Memoize
        b"\x93"  # STACK_GLOBAL (import os.system)
        b"\x94"  # Memoize
        b"\x8c\x0becho pwned"  # Short string "echo pwned"
        b"\x94"  # Memoize
        b"\x85"  # TUPLE1
        b"\x94"  # Memoize
        b"R"  # REDUCE (call os.system with args)
        b"\x94"  # Memoize
        b"."  # STOP
    )
    return malicious


@pytest.fixture
def malicious_pickle_file(fixtures_dir, malicious_pickle_bytes):
    """Create a malicious pickle file."""
    filepath = fixtures_dir / "malicious.pkl"
    with open(filepath, "wb") as f:
        f.write(malicious_pickle_bytes)
    return filepath


@pytest.fixture
def simple_malicious_pickle_file(fixtures_dir):
    """Create a simpler malicious pickle with GLOBAL opcode."""
    filepath = fixtures_dir / "malicious_global.pkl"
    # Protocol 0 pickle with explicit GLOBAL opcode
    # cos\nsystem\n is "import os.system"
    malicious = (
        b"cos\n"  # Push module "os"
        b"system\n"  # Push name "system"
        b"p0\n"  # Put in memo
        b"(S'id'\n"  # Push string 'id'
        b"tR"  # Tuple + REDUCE (call)
        b"."  # STOP
    )
    with open(filepath, "wb") as f:
        f.write(malicious)
    return filepath


@pytest.fixture
def valid_safetensors_file(fixtures_dir):
    """Create a valid safetensors file."""
    filepath = fixtures_dir / "model.safetensors"

    # Create header
    header = {
        "weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
        "__metadata__": {"format": "pt"},
    }
    header_json = json.dumps(header).encode("utf-8")
    header_size = len(header_json)

    # Tensor data (4 floats = 16 bytes)
    tensor_data = struct.pack("<4f", 1.0, 2.0, 3.0, 4.0)

    with open(filepath, "wb") as f:
        f.write(struct.pack("<Q", header_size))
        f.write(header_json)
        f.write(tensor_data)

    return filepath


@pytest.fixture
def suspicious_safetensors_file(fixtures_dir):
    """Create a safetensors file with suspicious metadata."""
    filepath = fixtures_dir / "suspicious.safetensors"

    header = {
        "weight": {"dtype": "F32", "shape": [2, 2], "data_offsets": [0, 16]},
        "__metadata__": {
            "description": "This contains eval(malicious_code) pattern",
            "script": "import os; os.system('bad')",
        },
    }
    header_json = json.dumps(header).encode("utf-8")
    header_size = len(header_json)

    tensor_data = struct.pack("<4f", 1.0, 2.0, 3.0, 4.0)

    with open(filepath, "wb") as f:
        f.write(struct.pack("<Q", header_size))
        f.write(header_json)
        f.write(tensor_data)

    return filepath


@pytest.fixture
def valid_gguf_file(fixtures_dir):
    """Create a minimal valid GGUF file."""
    filepath = fixtures_dir / "model.gguf"

    with open(filepath, "wb") as f:
        # Magic: "GGUF"
        f.write(struct.pack("<I", 0x46554747))
        # Version: 3
        f.write(struct.pack("<I", 3))
        # Tensor count: 0
        f.write(struct.pack("<Q", 0))
        # Metadata KV count: 0
        f.write(struct.pack("<Q", 0))

    return filepath


@pytest.fixture
def invalid_gguf_file(fixtures_dir):
    """Create a GGUF file with invalid magic."""
    filepath = fixtures_dir / "invalid.gguf"

    with open(filepath, "wb") as f:
        # Invalid magic
        f.write(struct.pack("<I", 0xDEADBEEF))
        f.write(struct.pack("<I", 3))
        f.write(struct.pack("<Q", 0))
        f.write(struct.pack("<Q", 0))

    return filepath


@pytest.fixture
def empty_file(fixtures_dir):
    """Create an empty file."""
    filepath = fixtures_dir / "empty.pkl"
    filepath.touch()
    return filepath
