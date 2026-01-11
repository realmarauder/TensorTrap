"""Known dangerous modules and functions for pickle analysis."""

# Modules that can execute arbitrary code or access system resources
DANGEROUS_MODULES: set[str] = {
    # System access
    "os",
    "sys",
    "subprocess",
    "commands",  # Python 2 legacy
    "pty",
    "posix",
    "nt",
    # Internal subprocess modules (CVE-2025-10157)
    "_posixsubprocess",
    "_winapi",
    # Network access
    "socket",
    "urllib",
    "http",
    "ftplib",
    "smtplib",
    "telnetlib",
    "requests",  # Third-party but common
    "httpx",
    "aiohttp",
    # Code execution
    "builtins",
    "code",
    "codeop",
    "importlib",
    "runpy",
    "pkgutil",
    # Serialization (nested attacks)
    "pickle",
    "marshal",
    "shelve",
    # File/IO operations
    "io",
    "tempfile",
    "shutil",
    # Process/threading
    "signal",
    "ctypes",
    "multiprocessing",
    "concurrent",
    "_thread",
    "threading",
    "asyncio",
    # Package management (CVE-2025-1716)
    "pip",
}

# Specific functions that are dangerous regardless of module
DANGEROUS_FUNCTIONS: set[str] = {
    "eval",
    "exec",
    "compile",
    "open",
    "input",
    "breakpoint",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "locals",
    "vars",
}

# Known malicious module.function combinations seen in the wild
KNOWN_MALICIOUS_CALLS: set[tuple[str, str]] = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execl"),
    ("os", "execle"),
    ("os", "execlp"),
    ("os", "execlpe"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "execvpe"),
    ("os", "spawnl"),
    ("os", "spawnle"),
    ("os", "spawnlp"),
    ("os", "spawnlpe"),
    ("os", "spawnv"),
    ("os", "spawnve"),
    ("os", "spawnvp"),
    ("os", "spawnvpe"),
    # posix is the underlying module on Unix (os.system -> posix.system)
    ("posix", "system"),
    ("posix", "popen"),
    ("posix", "execv"),
    ("posix", "execve"),
    ("posix", "spawnv"),
    ("posix", "spawnve"),
    ("posix", "fork"),
    # nt is the underlying module on Windows
    ("nt", "system"),
    ("nt", "popen"),
    ("nt", "spawnv"),
    ("nt", "spawnve"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("builtins", "__import__"),
    ("socket", "socket"),
    ("urllib.request", "urlopen"),
    ("requests", "get"),
    ("requests", "post"),
    # CVE-2025-10157: Internal module and asyncio bypasses
    ("_posixsubprocess", "fork_exec"),
    ("asyncio.subprocess", "create_subprocess_exec"),
    ("asyncio.subprocess", "create_subprocess_shell"),
    ("asyncio", "create_subprocess_exec"),
    ("asyncio", "create_subprocess_shell"),
    # CVE-2025-1716: pip bypass
    ("pip", "main"),
    ("pip._internal", "main"),
    ("pip._internal.main", "main"),
    # multiprocessing can spawn processes
    ("multiprocessing", "Process"),
    ("multiprocessing.reduction", "ForkingPickler"),
}
