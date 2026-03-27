"""systemd user service management for TensorTrap."""

import subprocess
import sys
from pathlib import Path

SERVICE_NAME = "tensortrap"
SERVICE_DIR = Path.home() / ".config" / "systemd" / "user"
SERVICE_PATH = SERVICE_DIR / f"{SERVICE_NAME}.service"

SERVICE_TEMPLATE = """\
[Unit]
Description=TensorTrap AI Model Security Scanner
After=default.target

[Service]
Type=simple
ExecStart={python_exe} -m tensortrap serve --no-browser
Restart=on-failure
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
"""


def get_service_path() -> Path:
    """Get the path to the systemd service file."""
    return SERVICE_PATH


def get_service_status() -> dict:
    """Check if the TensorTrap service is installed, enabled, and running."""
    installed = SERVICE_PATH.exists()
    enabled = False
    active = False

    if installed:
        enabled = _systemctl("is-enabled") == 0
        active = _systemctl("is-active") == 0

    return {
        "installed": installed,
        "enabled": enabled,
        "active": active,
        "service_path": str(SERVICE_PATH),
    }


def install_service() -> dict:
    """Install and start the TensorTrap systemd user service."""
    SERVICE_DIR.mkdir(parents=True, exist_ok=True)

    # Write service file with the current Python executable
    content = SERVICE_TEMPLATE.format(python_exe=sys.executable)
    SERVICE_PATH.write_text(content, encoding="utf-8")

    # Reload, enable, and start
    _systemctl("daemon-reload")
    rc_enable = _systemctl("enable", SERVICE_NAME)
    rc_start = _systemctl("start", SERVICE_NAME)

    return {
        "installed": True,
        "enabled": rc_enable == 0,
        "active": rc_start == 0,
        "service_path": str(SERVICE_PATH),
    }


def uninstall_service() -> dict:
    """Stop, disable, and remove the TensorTrap service."""
    if not SERVICE_PATH.exists():
        return {"installed": False, "message": "Service not installed"}

    _systemctl("stop", SERVICE_NAME)
    _systemctl("disable", SERVICE_NAME)
    SERVICE_PATH.unlink(missing_ok=True)
    _systemctl("daemon-reload")

    return {"installed": False, "message": "Service uninstalled"}


def restart_service() -> dict:
    """Restart the TensorTrap service."""
    if not SERVICE_PATH.exists():
        return {"error": "Service not installed"}

    rc = _systemctl("restart", SERVICE_NAME)
    return {
        "restarted": rc == 0,
        "active": _systemctl("is-active") == 0,
    }


def _systemctl(*args: str) -> int:
    """Run a systemctl --user command. Returns the exit code."""
    cmd = ["systemctl", "--user", *args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=10,
        )
        return result.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 1
