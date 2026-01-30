"""Low-level pickle bytecode parser.

This module parses pickle files without executing them, extracting
information about opcodes and imports for security analysis.

Performance optimizations (v1.1.0):
- Streaming parser that skips binary data but scans ALL control opcodes
- This ensures we don't miss malicious code hidden after large data blocks
"""

import io
import pickletools
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any


@dataclass
class PickleOp:
    """Represents a single pickle opcode."""

    name: str
    arg: str | None
    pos: int
    raw_arg: bytes | None = None


# Security-relevant opcodes that we MUST check regardless of position
SECURITY_OPCODES = {
    "GLOBAL",        # Imports module.name
    "STACK_GLOBAL",  # Imports from stack values
    "REDUCE",        # Calls function with args
    "BUILD",         # Sets attributes (can trigger __setstate__)
    "INST",          # Creates class instance
    "OBJ",           # Creates object
    "NEWOBJ",        # Creates object (protocol 2+)
    "NEWOBJ_EX",     # Creates object with kwargs
    "UNKNOWN",       # Unknown/unrecognized opcode (potential evasion)
}

# Cached opcode lookup table (built once at module import for performance)
_OPCODES_BY_CODE: dict[int, Any] | None = None


def _get_opcodes_by_code() -> dict[int, Any]:
    """Get or build the cached opcode lookup table."""
    global _OPCODES_BY_CODE
    if _OPCODES_BY_CODE is None:
        _OPCODES_BY_CODE = {op.code.encode('latin-1')[0]: op for op in pickletools.opcodes}
    return _OPCODES_BY_CODE


# Opcode metadata for DRY parsing
# Format: opcode_name -> (length_prefix_size, encoding, yield_short_strings)
# length_prefix_size: 1, 4, or 8 bytes for length prefix
# encoding: 'latin-1', 'utf-8', or None (for binary data - don't yield)
_BINARY_OPCODES: dict[str, tuple[int, str | None]] = {
    # Binary data - skip entirely (tensor weights)
    "BINBYTES": (4, None),
    "BINBYTES8": (8, None),
    "SHORT_BINBYTES": (1, None),
    "BYTEARRAY8": (8, None),
    # Strings - yield short ones for STACK_GLOBAL support
    "BINSTRING": (4, "latin-1"),
    "BINUNICODE": (4, "utf-8"),
    "BINUNICODE8": (8, "utf-8"),
    "SHORT_BINUNICODE": (1, "utf-8"),
    "SHORT_BINSTRING": (1, "latin-1"),
}

# Fixed-size opcodes to skip (no security relevance)
_SKIP_OPCODES: dict[str, int] = {
    "BININT": 4,
    "BININT1": 1,
    "BININT2": 2,
    "BINFLOAT": 8,
    "BINGET": 1,
    "BINPUT": 1,
    "LONG_BINGET": 4,
    "LONG_BINPUT": 4,
    "FRAME": 8,
}

# Maximum string length to decode and yield (for STACK_GLOBAL stack simulation)
_MAX_STRING_LENGTH = 1024


def parse_pickle_ops(
    data: bytes,
    security_scan: bool = True,
) -> Iterator[PickleOp]:
    """Parse pickle bytecode and yield opcodes.

    Uses pickletools.genops which safely parses without executing.
    When security_scan=True, uses streaming mode that skips large binary
    data but ensures ALL security-relevant opcodes are scanned.

    Args:
        data: Raw pickle bytecode
        security_scan: If True, use fast streaming mode that skips binary data
                      but still scans ALL control opcodes for security

    Yields:
        PickleOp instances for each opcode
    """
    if security_scan:
        # Use streaming parser for security scanning
        yield from _parse_pickle_streaming(data)
    else:
        # Use standard pickletools for full parsing
        try:
            for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
                yield PickleOp(
                    name=opcode.name,
                    arg=str(arg) if arg is not None else None,
                    pos=pos if pos is not None else 0,
                )
        except Exception:
            return


def _parse_pickle_streaming(data: bytes) -> Iterator[PickleOp]:
    """Streaming pickle parser that skips binary data but scans ALL opcodes.

    This is optimized for security scanning:
    - Skips large BINBYTES/BINBYTES8 data (tensor weights) for speed
    - But still scans ALL control opcodes (GLOBAL, REDUCE, etc.)
    - This ensures we don't miss malicious code hidden after large data

    Args:
        data: Raw pickle bytecode

    Yields:
        PickleOp instances for security-relevant opcodes
    """
    # Use cached opcode lookup table (built once for performance)
    opcodes_by_code = _get_opcodes_by_code()

    pos = 0
    data_len = len(data)

    # Handle protocol header
    if data_len >= 2 and data[0] == 0x80:
        protocol = data[1]
        yield PickleOp(name="PROTO", arg=str(protocol), pos=0)
        pos = 2

    unknown_opcode_count = 0
    max_unknown_opcodes = 10  # Give up after too many unknowns
    pickle_stream_count = 0
    max_pickle_streams = 100  # Limit for concatenated pickles (DoS prevention)

    while pos < data_len:
        opcode_byte = data[pos]
        opcode_pos = pos

        if opcode_byte not in opcodes_by_code:
            # SECURITY FIX: Unknown opcode - flag it and try to continue
            # An attacker could use unknown opcodes to try to stop the scanner
            unknown_opcode_count += 1
            yield PickleOp(
                name="UNKNOWN",
                arg=f"0x{opcode_byte:02x}",
                pos=opcode_pos,
            )
            pos += 1  # Skip the unknown byte and try to continue
            if unknown_opcode_count > max_unknown_opcodes:
                # Too many unknowns - data is likely corrupt or not pickle
                return
            continue

        op = opcodes_by_code[opcode_byte]
        pos += 1

        # Handle binary/string opcodes using lookup table (DRY)
        if op.name in _BINARY_OPCODES:
            prefix_size, encoding = _BINARY_OPCODES[op.name]
            if pos + prefix_size > data_len:
                continue

            # Read length based on prefix size
            if prefix_size == 1:
                length = data[pos]
            elif prefix_size == 4:
                length = struct.unpack("<I", data[pos:pos + 4])[0]
            else:  # prefix_size == 8
                length = struct.unpack("<Q", data[pos:pos + 8])[0]

            new_pos = pos + prefix_size + length

            # For string opcodes, yield short strings for STACK_GLOBAL support
            if encoding is not None and length <= _MAX_STRING_LENGTH and new_pos <= data_len:
                arg_data = data[pos + prefix_size:new_pos]
                try:
                    arg_str = arg_data.decode(encoding)
                except Exception:
                    arg_str = repr(arg_data)
                pos = new_pos
                yield PickleOp(name=op.name, arg=arg_str, pos=opcode_pos)
                continue

            # Skip data (cap at buffer end if truncated)
            pos = min(new_pos, data_len)
            continue

        # Handle fixed-size skip opcodes using lookup table (DRY)
        if op.name in _SKIP_OPCODES:
            pos += _SKIP_OPCODES[op.name]
            continue

        # Parse argument for security-relevant opcodes
        arg_str = None

        if op.name == "GLOBAL":
            # GLOBAL format: "module\nname\n"
            end = data.find(b'\n', pos)
            if end < 0:
                return
            module_end = end
            end2 = data.find(b'\n', end + 1)
            if end2 < 0:
                return
            try:
                module = data[pos:module_end].decode('utf-8')
                name = data[module_end+1:end2].decode('utf-8')
                arg_str = f"{module} {name}"
            except Exception:
                arg_str = "<decode error>"
            pos = end2 + 1

        elif op.name == "STOP":
            yield PickleOp(name="STOP", arg=None, pos=opcode_pos)
            # Continue parsing for concatenated pickles (multi-object files)
            # This prevents attackers from hiding malicious payloads after first STOP
            pickle_stream_count += 1
            if pickle_stream_count >= max_pickle_streams:
                return
            # Reset unknown count for next pickle stream
            unknown_opcode_count = 0
            continue

        # Yield security-relevant and other control opcodes
        if op.name in SECURITY_OPCODES or op.name in (
            "PROTO", "STOP", "MARK", "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3",
            "EMPTY_DICT", "EMPTY_LIST", "EMPTY_TUPLE", "EMPTY_SET",
            "APPEND", "APPENDS", "SETITEM", "SETITEMS", "ADDITEMS",
            "POP", "DUP", "POP_MARK", "MEMOIZE", "NONE", "NEWTRUE", "NEWFALSE",
        ):
            yield PickleOp(name=op.name, arg=arg_str, pos=opcode_pos)


def parse_pickle_ops_full(data: bytes) -> Iterator[PickleOp]:
    """Parse ALL pickle bytecode without streaming optimization.

    Use this when you need complete opcode information including binary data.
    For large files this will be slow.

    Args:
        data: Raw pickle bytecode

    Yields:
        PickleOp instances for each opcode
    """
    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            yield PickleOp(
                name=opcode.name,
                arg=str(arg) if arg is not None else None,
                pos=pos if pos is not None else 0,
            )
    except Exception:
        return


def extract_globals(data: bytes) -> list[tuple[str, str, int]]:
    """Extract all GLOBAL/STACK_GLOBAL imports from pickle.

    For STACK_GLOBAL (protocol 4+), we simulate the stack to extract
    the actual module and name values that were pushed via
    SHORT_BINUNICODE or BINUNICODE opcodes.

    Uses streaming parser to scan ALL opcodes while skipping binary data,
    ensuring we don't miss malicious imports hidden after large data blocks.

    Args:
        data: Raw pickle bytecode

    Returns:
        List of (module, name, position) tuples
    """
    globals_found = []
    stack: list[str] = []  # Simple stack simulation for string values

    for op in parse_pickle_ops(data, security_scan=True):
        if op.name == "GLOBAL" and op.arg:
            # GLOBAL arg format is "module name" (space-separated)
            parts = op.arg.split(" ", 1)
            if len(parts) == 2:
                module, name = parts
            else:
                module, name = parts[0], ""
            globals_found.append((module, name, op.pos))
            stack.append("<callable>")  # Result of GLOBAL goes on stack

        elif op.name == "STACK_GLOBAL":
            # STACK_GLOBAL pops name then module from stack
            if len(stack) >= 2:
                name = stack.pop()
                module = stack.pop()
                globals_found.append((module, name, op.pos))
            else:
                # Couldn't determine values, fall back to placeholder
                globals_found.append(("<stack>", "<stack>", op.pos))
            stack.append("<callable>")  # Result goes on stack

        # Track string values pushed to stack
        elif op.name in ("SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8") and op.arg:
            stack.append(op.arg)

        elif op.name in ("SHORT_BINSTRING", "BINSTRING") and op.arg:
            stack.append(op.arg)

        elif op.name == "UNICODE" and op.arg:
            stack.append(op.arg)

        # Handle opcodes that pop from stack
        elif op.name == "MEMOIZE":
            pass  # Doesn't affect stack
        elif op.name == "POP":
            if stack:
                stack.pop()
        elif op.name == "POP_MARK":
            # Pop everything back to mark - simplified, just clear stack
            stack.clear()
        elif op.name in ("TUPLE1", "TUPLE2", "TUPLE3"):
            # Pop N items, push tuple
            n = int(op.name[-1])
            for _ in range(min(n, len(stack))):
                stack.pop()
            stack.append("<tuple>")
        elif op.name == "REDUCE":
            # Pop args and callable, push result
            if len(stack) >= 2:
                stack.pop()  # args
                stack.pop()  # callable
            stack.append("<result>")
        elif op.name in ("NEWOBJ", "NEWOBJ_EX"):
            # Pop class and args, push instance
            if len(stack) >= 2:
                stack.pop()
                stack.pop()
            stack.append("<instance>")
        # Other opcodes that push values
        elif op.name in (
            "NONE",
            "NEWTRUE",
            "NEWFALSE",
            "EMPTY_DICT",
            "EMPTY_LIST",
            "EMPTY_TUPLE",
            "EMPTY_SET",
        ):
            stack.append("<value>")

    return globals_found


def get_dangerous_opcodes(data: bytes, full_scan: bool = False) -> list[PickleOp]:
    """Find opcodes that can trigger code execution.

    Uses streaming parser to scan ALL opcodes while skipping binary data.
    This ensures we detect malicious code even if hidden after large data.

    Args:
        data: Raw pickle bytecode
        full_scan: If True, use slow full parsing. If False (default), use
                  fast streaming parser that skips binary data.

    Returns:
        List of dangerous PickleOp instances
    """
    dangerous_names = {
        "REDUCE",  # Calls callable with args
        "BUILD",  # Sets instance attributes (can trigger __setstate__)
        "INST",  # Creates class instance
        "OBJ",  # Creates object
        "NEWOBJ",  # Creates object (protocol 2+)
        "NEWOBJ_EX",  # Creates object with kwargs
        "UNKNOWN",  # Unknown/unrecognized opcode (potential evasion)
    }

    dangerous_ops = []

    # Use streaming parser (default) - fast but complete security scan
    if full_scan:
        parser = parse_pickle_ops_full(data)
    else:
        parser = parse_pickle_ops(data, security_scan=True)

    for op in parser:
        if op.name in dangerous_names:
            dangerous_ops.append(op)

    return dangerous_ops


def is_valid_pickle(data: bytes) -> tuple[bool, str | None]:
    """Check if data is valid pickle format.

    This is a quick check that only looks at the header and
    attempts limited parsing.

    Args:
        data: Raw bytes to check

    Returns:
        Tuple of (is_valid, error_message)
    """
    import io
    import pickletools

    if len(data) == 0:
        return False, "Empty file"

    # Check for pickle protocol markers
    # Protocol 0-2: Various ASCII opcodes
    # Protocol 3+: 0x80 followed by protocol version
    first_byte = data[0]

    # Protocol 3+ starts with 0x80
    if first_byte == 0x80:
        if len(data) < 2:
            return False, "Truncated pickle header"
        protocol = data[1]
        if protocol > 5:
            return False, f"Unknown pickle protocol: {protocol}"

    # Try to parse just the start of the pickle
    # Use pickletools directly to get proper error reporting
    try:
        ops_parsed = 0
        # Limit to first 1MB for performance
        parse_data = data[:1024 * 1024] if len(data) > 1024 * 1024 else data
        for opcode, arg, pos in pickletools.genops(io.BytesIO(parse_data)):
            ops_parsed += 1
            if ops_parsed >= 10:  # Found enough to confirm it's pickle
                break

        if ops_parsed == 0:
            return False, "No opcodes found"
        return True, None
    except Exception as e:
        return False, f"Parse error: {e}"
