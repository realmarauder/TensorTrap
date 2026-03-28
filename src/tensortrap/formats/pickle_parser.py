"""Low-level pickle bytecode parser.

This module parses pickle files without executing them, extracting
information about opcodes and imports for security analysis.

Performance optimizations:
- Streaming parser that skips binary data blobs (tensor weights) but
  scans ALL security-relevant control opcodes. This reduces scan time
  for large model files from minutes to seconds.
- Quick validation that checks header and tail without parsing the full file.
"""

import io
import pickletools
import struct
from collections.abc import Iterator
from dataclasses import dataclass

# Build opcode lookup table from pickletools for the streaming parser
_OPCODE_BY_CODE: dict[int, pickletools.OpcodeInfo] = {}
for _op in pickletools.opcodes:
    _OPCODE_BY_CODE[_op.code.encode("latin-1")[0]] = _op

# Opcodes that carry large binary data we can skip over.
# These are the tensor weight storage opcodes — the vast majority of
# bytes in a model file. We read the length header and seek past them.
_SKIP_DATA_OPCODES = {
    "SHORT_BINBYTES",  # 1-byte length + data
    "BINBYTES",  # 4-byte length + data
    "BINBYTES8",  # 8-byte length + data
    "SHORT_BINUNICODE",  # 1-byte length + data
    "BINUNICODE",  # 4-byte length + data
    "BINUNICODE8",  # 8-byte length + data
    "SHORT_BINSTRING",  # 1-byte length + data
    "BINSTRING",  # 4-byte length + data
    "BYTEARRAY8",  # 8-byte length + data
}

# Security-relevant opcodes we always need to examine
_SECURITY_OPCODES = {
    "GLOBAL",  # Import: "module name\n"
    "STACK_GLOBAL",  # Import from stack
    "INST",  # Instance creation: "module name\n"
    "REDUCE",  # Call callable with args
    "BUILD",  # Trigger __setstate__
    "OBJ",  # Create object
    "NEWOBJ",  # Create object (protocol 2+)
    "NEWOBJ_EX",  # Create object with kwargs
}


@dataclass
class PickleOp:
    """Represents a single pickle opcode."""

    name: str
    arg: str | None
    pos: int
    raw_arg: bytes | None = None


def parse_pickle_ops(data: bytes) -> Iterator[PickleOp]:
    """Parse pickle bytecode and yield opcodes using the streaming parser.

    For small files (<1MB), falls back to pickletools.genops for full accuracy.
    For large files, uses the streaming parser that skips binary data blobs
    while scanning all security-relevant control opcodes.

    Args:
        data: Raw pickle bytecode

    Yields:
        PickleOp instances for each opcode
    """
    # For small files, use the full parser — it's fast enough and more accurate
    if len(data) < 1_048_576:
        yield from _parse_pickle_full(data)
    else:
        yield from _parse_pickle_streaming(data)


def _parse_pickle_full(data: bytes) -> Iterator[PickleOp]:
    """Full pickle parser using pickletools.genops (accurate, slower on large files)."""
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
    """Streaming pickle parser that skips binary data blobs.

    Reads opcode headers, identifies the opcode type, and either:
    - Yields it (for security-relevant opcodes and stack-manipulation opcodes)
    - Skips the data payload (for large binary data like tensor weights)

    This is the key performance optimization: a 2GB model file is 99.9%
    tensor weight data stored in BINBYTES8 opcodes. We read the 8-byte
    length header and seek past the blob, rather than reading every byte.
    """
    pos = 0
    length = len(data)

    # Skip protocol header if present
    if length >= 2 and data[0] == 0x80:
        pos = 2

    while pos < length:
        opcode_byte = data[pos]
        opcode_info = _OPCODE_BY_CODE.get(opcode_byte)

        if opcode_info is None:
            pos += 1
            continue

        name = opcode_info.name
        op_pos = pos
        pos += 1  # Move past opcode byte

        # Handle STOP — end of pickle
        if name == "STOP":
            yield PickleOp(name="STOP", arg=None, pos=op_pos)
            return

        # Handle FRAME (protocol 4+): 8-byte frame length, then continue parsing inside
        if name == "FRAME":
            if pos + 8 <= length:
                pos += 8  # Skip frame length, parse contents normally
            else:
                return
            continue

        # Handle PROTO: 1-byte protocol number
        if name == "PROTO":
            if pos < length:
                pos += 1
            continue

        # Opcodes with large binary data — read length and skip
        if name == "SHORT_BINBYTES" or name == "SHORT_BINUNICODE" or name == "SHORT_BINSTRING":
            if pos >= length:
                return
            data_len = data[pos]
            pos += 1
            arg_data = data[pos : pos + data_len] if data_len < 256 else None
            arg_str = arg_data.decode("utf-8", errors="replace") if arg_data else None
            # Only yield string opcodes (needed for STACK_GLOBAL resolution)
            if name in ("SHORT_BINUNICODE", "SHORT_BINSTRING"):
                yield PickleOp(name=name, arg=arg_str, pos=op_pos)
            pos += data_len
            continue

        if name == "BINBYTES" or name == "BINUNICODE" or name == "BINSTRING":
            if pos + 4 > length:
                return
            data_len = struct.unpack("<I", data[pos : pos + 4])[0]
            pos += 4
            # For unicode/string: yield small ones (needed for stack), skip large
            if name in ("BINUNICODE", "BINSTRING") and data_len < 1024:
                arg_str = data[pos : pos + data_len].decode("utf-8", errors="replace")
                yield PickleOp(name=name, arg=arg_str, pos=op_pos)
            pos += data_len
            continue

        if name == "BINBYTES8" or name == "BINUNICODE8" or name == "BYTEARRAY8":
            if pos + 8 > length:
                return
            data_len = struct.unpack("<Q", data[pos : pos + 8])[0]
            pos += 8
            # These are almost always massive tensor blobs — skip entirely
            pos += data_len
            continue

        # GLOBAL: reads "module\nname\n" — security critical
        if name == "GLOBAL":
            end = data.find(b"\n", pos)
            if end < 0:
                return
            module_name = data[pos:end].decode("utf-8", errors="replace")
            pos = end + 1
            end2 = data.find(b"\n", pos)
            if end2 < 0:
                return
            func_name = data[pos:end2].decode("utf-8", errors="replace")
            pos = end2 + 1
            yield PickleOp(name="GLOBAL", arg=f"{module_name} {func_name}", pos=op_pos)
            continue

        # INST: like GLOBAL, reads "module\nname\n"
        if name == "INST":
            end = data.find(b"\n", pos)
            if end < 0:
                return
            module_name = data[pos:end].decode("utf-8", errors="replace")
            pos = end + 1
            end2 = data.find(b"\n", pos)
            if end2 < 0:
                return
            func_name = data[pos:end2].decode("utf-8", errors="replace")
            pos = end2 + 1
            yield PickleOp(name="INST", arg=f"{module_name} {func_name}", pos=op_pos)
            continue

        # Fixed-size argument opcodes
        if name in ("BININT", "BINGET", "BINPUT"):
            pos += 4
            yield PickleOp(name=name, arg=None, pos=op_pos)
            continue

        if name in ("BININT1", "BINGET", "BINPUT"):
            pos += 1
            yield PickleOp(name=name, arg=None, pos=op_pos)
            continue

        if name in ("BININT2",):
            pos += 2
            yield PickleOp(name=name, arg=None, pos=op_pos)
            continue

        if name == "BINFLOAT":
            pos += 8
            yield PickleOp(name=name, arg=None, pos=op_pos)
            continue

        if name in ("LONG_BINGET", "LONG_BINPUT"):
            pos += 4
            yield PickleOp(name=name, arg=None, pos=op_pos)
            continue

        if name == "LONG1":
            if pos >= length:
                return
            n = data[pos]
            pos += 1 + n
            yield PickleOp(name=name, arg=None, pos=op_pos)
            continue

        if name == "LONG4":
            if pos + 4 > length:
                return
            n = struct.unpack("<I", data[pos : pos + 4])[0]
            pos += 4 + n
            yield PickleOp(name=name, arg=None, pos=op_pos)
            continue

        # Text-line opcodes (protocol 0): read until newline
        if name in ("FLOAT", "INT", "LONG", "STRING", "UNICODE", "GET", "PUT", "PERSID"):
            end = data.find(b"\n", pos)
            if end < 0:
                return
            arg_str = data[pos:end].decode("utf-8", errors="replace")
            pos = end + 1
            if name == "UNICODE":
                yield PickleOp(name=name, arg=arg_str, pos=op_pos)
            else:
                yield PickleOp(name=name, arg=arg_str, pos=op_pos)
            continue

        if name == "MEMOIZE":
            yield PickleOp(name=name, arg=None, pos=op_pos)
            continue

        # All other opcodes: no argument (REDUCE, BUILD, STACK_GLOBAL, MARK,
        # POP, TUPLE, EMPTY_*, NONE, NEWTRUE, NEWFALSE, NEWOBJ, etc.)
        yield PickleOp(name=name, arg=None, pos=op_pos)


def extract_globals(data: bytes) -> list[tuple[str, str, int]]:
    """Extract all GLOBAL/STACK_GLOBAL imports from pickle.

    For STACK_GLOBAL (protocol 4+), we simulate the stack to extract
    the actual module and name values that were pushed via
    SHORT_BINUNICODE or BINUNICODE opcodes.

    Args:
        data: Raw pickle bytecode

    Returns:
        List of (module, name, position) tuples
    """
    globals_found = []
    stack: list[str] = []  # Simple stack simulation for string values

    for op in parse_pickle_ops(data):
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
            "BININT",
            "BININT1",
            "BININT2",
            "BINFLOAT",
            "EMPTY_DICT",
            "EMPTY_LIST",
            "EMPTY_TUPLE",
            "EMPTY_SET",
            "BINGET",
            "LONG_BINGET",
        ):
            stack.append("<value>")

    return globals_found


def get_dangerous_opcodes(data: bytes) -> list[PickleOp]:
    """Find opcodes that can trigger code execution.

    Args:
        data: Raw pickle bytecode

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
    }

    dangerous_ops = []
    for op in parse_pickle_ops(data):
        if op.name in dangerous_names:
            dangerous_ops.append(op)

    return dangerous_ops


def is_valid_pickle(data: bytes) -> tuple[bool, str | None]:
    """Check if data is valid pickle format.

    Uses a quick header/tail check for large files to avoid parsing
    the entire file just for validation.

    Args:
        data: Raw bytes to check

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(data) == 0:
        return False, "Empty file"

    # Check for pickle protocol markers
    first_byte = data[0]

    # Protocol 3+ starts with 0x80
    if first_byte == 0x80:
        if len(data) < 2:
            return False, "Truncated pickle header"
        protocol = data[1]
        if protocol > 5:
            return False, f"Unknown pickle protocol: {protocol}"

    # For large files, do a quick check: valid header + STOP at end
    if len(data) > 1_048_576:
        # The last byte of a valid pickle must be STOP (0x2E = '.')
        if data[-1] == 0x2E:
            return True, None
        # Check last few bytes in case of trailing whitespace
        for i in range(min(16, len(data))):
            if data[-(i + 1)] == 0x2E:
                return True, None
        return False, "Missing STOP opcode"

    # For small files, do the full parse
    try:
        ops = list(pickletools.genops(io.BytesIO(data)))
        if not ops:
            return False, "No opcodes found"
        if ops[-1][0].name != "STOP":
            return False, "Missing STOP opcode"
        return True, None
    except Exception as e:
        return False, f"Parse error: {e}"
