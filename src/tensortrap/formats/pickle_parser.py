"""Low-level pickle bytecode parser.

This module parses pickle files without executing them, extracting
information about opcodes and imports for security analysis.
"""

import io
import pickletools
from collections.abc import Iterator
from dataclasses import dataclass


@dataclass
class PickleOp:
    """Represents a single pickle opcode."""

    name: str
    arg: str | None
    pos: int
    raw_arg: bytes | None = None


def parse_pickle_ops(data: bytes) -> Iterator[PickleOp]:
    """Parse pickle bytecode and yield opcodes.

    Uses pickletools.genops which safely parses without executing.

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
        # If parsing fails partway through, we've yielded what we could
        return


def extract_globals(data: bytes) -> list[tuple[str, str, int]]:
    """Extract all GLOBAL/STACK_GLOBAL imports from pickle.

    Args:
        data: Raw pickle bytecode

    Returns:
        List of (module, name, position) tuples
    """
    globals_found = []

    for op in parse_pickle_ops(data):
        if op.name == "GLOBAL" and op.arg:
            # GLOBAL arg format is "module name" (space-separated)
            parts = op.arg.split(" ", 1)
            if len(parts) == 2:
                module, name = parts
            else:
                module, name = parts[0], ""
            globals_found.append((module, name, op.pos))
        elif op.name == "STACK_GLOBAL":
            # STACK_GLOBAL gets module and name from stack
            # We can't determine the actual values without execution
            globals_found.append(("<stack>", "<stack>", op.pos))

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

    Args:
        data: Raw bytes to check

    Returns:
        Tuple of (is_valid, error_message)
    """
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

    # Try to parse the pickle
    try:
        ops = list(pickletools.genops(io.BytesIO(data)))
        if not ops:
            return False, "No opcodes found"
        # Check for STOP opcode at end
        if ops[-1][0].name != "STOP":
            return False, "Missing STOP opcode"
        return True, None
    except Exception as e:
        return False, f"Parse error: {e}"
