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
}
