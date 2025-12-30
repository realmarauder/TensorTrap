"""YAML configuration file scanner.

Scans YAML files for unsafe deserialization patterns that could enable
remote code execution (CVE-2025-50460 and similar).

PyYAML with yaml.load() and FullLoader/UnsafeLoader can execute
arbitrary Python code via YAML tags.
"""

import re
from pathlib import Path

from tensortrap.scanner.results import Finding, Severity

# Dangerous YAML tags that enable code execution
DANGEROUS_YAML_TAGS = [
    # Python object instantiation
    (r"!!python/object:", "Python object instantiation", Severity.CRITICAL),
    (r"!!python/object/new:", "Python object creation", Severity.CRITICAL),
    (r"!!python/object/apply:", "Python function application", Severity.CRITICAL),
    (r"!!python/module:", "Python module import", Severity.CRITICAL),
    (r"!!python/name:", "Python name reference", Severity.HIGH),
    (r"!!python/tuple:", "Python tuple (may contain objects)", Severity.MEDIUM),
    # Common exploit patterns
    (r"subprocess\.Popen", "Subprocess execution", Severity.CRITICAL),
    (r"os\.system", "OS command execution", Severity.CRITICAL),
    (r"os\.popen", "OS pipe execution", Severity.CRITICAL),
    (r"commands\.getoutput", "Command execution", Severity.CRITICAL),
    (r"pty\.spawn", "PTY spawn", Severity.CRITICAL),
    (r"builtins\.eval", "eval() execution", Severity.CRITICAL),
    (r"builtins\.exec", "exec() execution", Severity.CRITICAL),
    (r"__import__", "Dynamic import", Severity.CRITICAL),
    (r"__reduce__", "Pickle reduce method", Severity.HIGH),
    (r"__reduce_ex__", "Pickle reduce_ex method", Severity.HIGH),
    # Network-related
    (r"socket\.socket", "Socket creation", Severity.HIGH),
    (r"urllib\.request", "URL request", Severity.MEDIUM),
    (r"requests\.(get|post)", "HTTP request", Severity.MEDIUM),
]

# Patterns indicating this might be an AI/ML config file
ML_CONFIG_INDICATORS = [
    r"model",
    r"training",
    r"dataset",
    r"epochs?",
    r"batch_size",
    r"learning_rate",
    r"optimizer",
    r"checkpoint",
    r"weights",
    r"transformers?",
    r"huggingface",
    r"torch",
    r"tensorflow",
    r"pytorch",
    r"cuda",
    r"gpu",
]


def scan_yaml(filepath: Path) -> list[Finding]:
    """Scan a YAML file for unsafe deserialization patterns.

    Args:
        filepath: Path to YAML file

    Returns:
        List of security findings
    """
    findings = []
    filepath = Path(filepath)

    # Check if this is a GitHub/CI config file (lower sensitivity)
    is_github_file = _is_github_or_ci_file(filepath)

    # Check if this is a dataset config file (shell commands expected for downloads)
    is_dataset_config = _is_dataset_config_file(filepath)

    # Read file content
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        return [
            Finding(
                severity=Severity.MEDIUM,
                message=f"Failed to read file: {e}",
                location=None,
                details={"error": str(e)},
            )
        ]

    # Check if this looks like a YAML file
    if not _is_yaml_like(content):
        findings.append(
            Finding(
                severity=Severity.INFO,
                message="File does not appear to be valid YAML",
                location=None,
                details={},
            )
        )
        return findings

    # Check if this is likely an ML config file
    is_ml_config = _is_ml_config(content)

    # Scan for dangerous YAML tags
    for pattern, description, severity in DANGEROUS_YAML_TAGS:
        matches = list(re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE))
        if matches:
            findings.append(
                Finding(
                    severity=severity,
                    message=f"Dangerous YAML pattern: {description}",
                    location=matches[0].start(),
                    details={
                        "pattern": pattern,
                        "match_count": len(matches),
                        "line_numbers": _get_line_numbers(content, matches),
                        "is_ml_config": is_ml_config,
                        "cve": "CVE-2025-50460" if "python/object" in pattern else None,
                    },
                )
            )

    # Check for Python code blocks (skip for GitHub Actions files and dataset configs)
    if not is_github_file and not is_dataset_config:
        python_code_patterns = [
            (r"^\s*python:\s*\|", "Multiline Python code block"),
            (r"^\s*script:\s*\|", "Multiline script block"),
            (r"^\s*code:\s*\|", "Multiline code block"),
            (r"^\s*eval:\s*", "Eval field"),
            (r"^\s*exec:\s*", "Exec field"),
        ]

        for pattern, description in python_code_patterns:
            matches = list(re.finditer(pattern, content, re.MULTILINE))
            if matches:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        message=f"Code execution pattern: {description}",
                        location=matches[0].start(),
                        details={
                            "pattern": pattern,
                            "match_count": len(matches),
                        },
                    )
                )

    # Check for shell commands (skip for GitHub/CI files and dataset configs)
    if not is_github_file and not is_dataset_config:
        shell_patterns = [
            (r"^\s*command:\s*['\"]?[\w/]", "Shell command"),
            (r"^\s*shell:\s*", "Shell execution"),
            (r"\$\([^)]+\)", "Command substitution"),
        ]

        for pattern, description in shell_patterns:
            matches = list(re.finditer(pattern, content, re.MULTILINE))
            if matches:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        message=f"Shell command pattern: {description}",
                        location=matches[0].start(),
                        details={
                            "pattern": pattern,
                            "match_count": len(matches),
                        },
                    )
                )

    # Info about ML config detection
    if is_ml_config and not findings:
        findings.append(
            Finding(
                severity=Severity.INFO,
                message="ML configuration file detected - no unsafe patterns found",
                location=None,
                details={"indicators_found": _get_ml_indicators(content)},
            )
        )

    return findings


# Alias for consistency
scan_yaml_file = scan_yaml


def _is_yaml_like(content: str) -> bool:
    """Check if content appears to be YAML.

    Args:
        content: File content

    Returns:
        True if appears to be YAML
    """
    # Check for common YAML patterns
    yaml_patterns = [
        r"^\s*[\w_-]+:\s*",  # key: value
        r"^\s*-\s+",  # list item
        r"^---",  # document start
        r"^\.\.\.$",  # document end
    ]

    for pattern in yaml_patterns:
        if re.search(pattern, content, re.MULTILINE):
            return True

    return False


def _is_ml_config(content: str) -> bool:
    """Check if content appears to be an ML configuration.

    Args:
        content: File content

    Returns:
        True if appears to be ML config
    """
    content_lower = content.lower()
    matches = sum(1 for pattern in ML_CONFIG_INDICATORS if re.search(pattern, content_lower))
    return matches >= 2


def _get_ml_indicators(content: str) -> list[str]:
    """Get list of ML indicators found in content.

    Args:
        content: File content

    Returns:
        List of indicator patterns found
    """
    content_lower = content.lower()
    return [p for p in ML_CONFIG_INDICATORS if re.search(p, content_lower)]


def _get_line_numbers(content: str, matches: list) -> list[int]:
    """Get line numbers for regex matches.

    Args:
        content: Full file content
        matches: List of regex match objects

    Returns:
        List of line numbers (1-indexed)
    """
    line_numbers = []
    for match in matches[:10]:  # Limit to first 10
        line_num = content[: match.start()].count("\n") + 1
        line_numbers.append(line_num)
    return line_numbers


def _is_github_or_ci_file(filepath: Path) -> bool:
    """Check if file is a GitHub/CI config where shell commands are expected.

    Args:
        filepath: Path to file

    Returns:
        True if file is in .github/ or common CI directories
    """
    path_str = str(filepath).lower()

    # GitHub-specific paths
    if "/.github/" in path_str or "\\.github\\" in path_str:
        return True

    # Common CI config files
    ci_patterns = [
        ".gitlab-ci",
        ".travis",
        "azure-pipelines",
        "jenkinsfile",
        ".circleci",
        "bitbucket-pipelines",
    ]

    filename = filepath.name.lower()
    for pattern in ci_patterns:
        if pattern in filename or pattern in path_str:
            return True

    return False


def _is_dataset_config_file(filepath: Path) -> bool:
    """Check if file is a dataset config where download commands are expected.

    Args:
        filepath: Path to file

    Returns:
        True if file is a dataset configuration file
    """
    path_str = str(filepath).lower()

    # Ultralytics dataset configs have legitimate bash download commands
    dataset_config_patterns = [
        "/ultralytics/cfg/datasets/",
        "\\ultralytics\\cfg\\datasets\\",
        "/datasets/",  # Generic datasets folder
        "/cfg/datasets/",
    ]

    for pattern in dataset_config_patterns:
        if pattern in path_str:
            return True

    return False
