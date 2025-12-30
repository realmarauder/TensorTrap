"""ComfyUI workflow scanner.

ComfyUI workflows are JSON files that can contain malicious node
configurations exploiting vulnerabilities like CVE-2024-21576 and
CVE-2024-21577 (eval() in custom nodes).
"""

import json
from pathlib import Path
from typing import Any

from tensortrap.scanner.results import Finding, Severity

# Known vulnerable node types (CVE-2024-21576, CVE-2024-21577)
VULNERABLE_NODE_TYPES: dict[str, dict[str, Any]] = {
    "ACE_ExpressionEval": {
        "severity": Severity.CRITICAL,
        "cve": "CVE-2024-21577",
        "description": "Arithmetic expression eval vulnerability",
    },
    "HueAdjust": {
        "severity": Severity.CRITICAL,
        "cve": "CVE-2024-21576",
        "description": "Hue adjustment eval vulnerability",
    },
    "ExpressionEval": {
        "severity": Severity.CRITICAL,
        "cve": None,
        "description": "Expression evaluation node",
    },
    "PythonExpression": {
        "severity": Severity.CRITICAL,
        "cve": None,
        "description": "Python expression evaluation",
    },
    "Eval": {
        "severity": Severity.CRITICAL,
        "cve": None,
        "description": "Generic eval node",
    },
    "Execute": {
        "severity": Severity.CRITICAL,
        "cve": None,
        "description": "Code execution node",
    },
    "RunPython": {
        "severity": Severity.CRITICAL,
        "cve": None,
        "description": "Python execution node",
    },
}

# Suspicious patterns in node inputs
# Patterns must be specific enough to avoid false positives in natural language
SUSPICIOUS_INPUT_PATTERNS = [
    (r"__import__", "Dynamic import", Severity.CRITICAL),
    (r"eval\s*\(", "eval() call", Severity.CRITICAL),
    (r"exec\s*\(", "exec() call", Severity.CRITICAL),
    (r"os\.system", "OS command execution", Severity.CRITICAL),
    (r"subprocess", "Subprocess execution", Severity.CRITICAL),
    (r"open\s*\(", "File operation", Severity.HIGH),
    # Match requests.<method>( to avoid false positives like "requests. Any style"
    (
        r"requests\.(get|post|put|delete|patch|head|options|session)\s*\(",
        "Network request",
        Severity.HIGH,
    ),
    (r"urllib\.(request|parse)", "URL operation", Severity.HIGH),
    (r"socket\.(socket|connect|bind|listen)", "Socket operation", Severity.HIGH),
    (r"\\x[0-9a-fA-F]{2}", "Hex escape sequence", Severity.MEDIUM),
    (
        r"base64\.(b64decode|b64encode|decode|encode)",
        "Base64 encoding",
        Severity.MEDIUM,
    ),
]


def scan_comfyui_workflow(filepath: Path) -> list[Finding]:
    """Scan a ComfyUI workflow JSON file for security issues.

    Args:
        filepath: Path to workflow JSON file

    Returns:
        List of security findings
    """
    findings = []
    filepath = Path(filepath)

    # Read and parse JSON
    try:
        with open(filepath, encoding="utf-8") as f:
            content = f.read()
            workflow = json.loads(content)
    except json.JSONDecodeError as e:
        return [
            Finding(
                severity=Severity.INFO,
                message=f"Invalid JSON: {e}",
                location=None,
                details={"error": str(e)},
            )
        ]
    except OSError as e:
        return [
            Finding(
                severity=Severity.MEDIUM,
                message=f"Failed to read file: {e}",
                location=None,
                details={"error": str(e)},
            )
        ]

    # Check if this looks like a ComfyUI workflow
    if not _is_comfyui_workflow(workflow):
        findings.append(
            Finding(
                severity=Severity.INFO,
                message="File does not appear to be a ComfyUI workflow",
                location=None,
                details={},
            )
        )
        return findings

    # Scan for vulnerable node types
    nodes = workflow.get("nodes", [])
    for node in nodes:
        node_type = node.get("type", "")
        node_id = node.get("id", "unknown")

        if node_type in VULNERABLE_NODE_TYPES:
            vuln_info = VULNERABLE_NODE_TYPES[node_type]
            findings.append(
                Finding(
                    severity=vuln_info["severity"],
                    message=f"Vulnerable node type: {node_type}",
                    location=node_id,
                    details={
                        "node_type": node_type,
                        "node_id": node_id,
                        "cve": vuln_info["cve"],
                        "description": vuln_info["description"],
                    },
                )
            )

        # Scan node inputs for suspicious patterns
        input_findings = _scan_node_inputs(node, content)
        findings.extend(input_findings)

    # Scan widget values
    widget_findings = _scan_widgets(workflow, content)
    findings.extend(widget_findings)

    return findings


def _is_comfyui_workflow(data: Any) -> bool:
    """Check if data appears to be a ComfyUI workflow.

    Args:
        data: Parsed JSON data

    Returns:
        True if appears to be ComfyUI workflow
    """
    if not isinstance(data, dict):
        return False

    # nodes must be a list for this to be a valid workflow
    nodes = data.get("nodes")
    if not isinstance(nodes, list):
        return False

    # ComfyUI workflows typically have these fields
    comfyui_indicators = ["nodes", "last_node_id", "links", "groups"]
    matches = sum(1 for key in comfyui_indicators if key in data)

    return matches >= 2


def _scan_node_inputs(node: dict, content: str) -> list[Finding]:
    """Scan node inputs for suspicious patterns.

    Args:
        node: Node dictionary
        content: Full JSON content for context

    Returns:
        List of findings
    """
    import re

    findings: list[Finding] = []
    node_id = node.get("id", "unknown")
    node_type = node.get("type", "unknown")

    # Get widget values
    widgets = node.get("widgets_values", [])
    if not widgets:
        return findings

    for i, value in enumerate(widgets):
        if not isinstance(value, str):
            continue

        for pattern, description, severity in SUSPICIOUS_INPUT_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                findings.append(
                    Finding(
                        severity=severity,
                        message=f"Suspicious pattern in node input: {description}",
                        location=node_id,
                        details={
                            "node_id": node_id,
                            "node_type": node_type,
                            "widget_index": i,
                            "pattern": pattern,
                            "preview": value[:100] if len(value) > 100 else value,
                        },
                    )
                )
                break  # One finding per widget

    return findings


def _scan_widgets(workflow: dict, content: str) -> list[Finding]:
    """Scan all widgets in workflow for suspicious content.

    Args:
        workflow: Parsed workflow data
        content: Full JSON content

    Returns:
        List of findings
    """
    import re

    findings = []

    # Deep scan the entire content for suspicious patterns
    for pattern, description, severity in SUSPICIOUS_INPUT_PATTERNS:
        matches = list(re.finditer(pattern, content, re.IGNORECASE))
        if matches:
            # Only report if not already found in node scanning
            findings.append(
                Finding(
                    severity=severity,
                    message=f"Suspicious pattern in workflow: {description}",
                    location=matches[0].start(),
                    details={
                        "pattern": pattern,
                        "match_count": len(matches),
                    },
                )
            )

    return findings
