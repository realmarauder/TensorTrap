"""Background service management for TensorTrap (systemd + launchd)."""

import platform
import subprocess
import sys
from pathlib import Path

SERVICE_NAME = "tensortrap"

# --- Platform detection ---

_SYSTEM = platform.system()

# systemd (Linux)
SYSTEMD_DIR = Path.home() / ".config" / "systemd" / "user"
SYSTEMD_PATH = SYSTEMD_DIR / f"{SERVICE_NAME}.service"

SYSTEMD_TEMPLATE = """\
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

# launchd (macOS)
LAUNCHD_LABEL = "com.tensortrap.server"
LAUNCHD_DIR = Path.home() / "Library" / "LaunchAgents"
LAUNCHD_PATH = LAUNCHD_DIR / f"{LAUNCHD_LABEL}.plist"

LAUNCHD_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_exe}</string>
        <string>-m</string>
        <string>tensortrap</string>
        <string>serve</string>
        <string>--no-browser</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/tensortrap.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/tensortrap.err</string>
</dict>
</plist>
"""


# --- Public API (platform-dispatched) ---


def get_service_path() -> Path:
    """Get the path to the service file."""
    if _SYSTEM == "Darwin":
        return LAUNCHD_PATH
    return SYSTEMD_PATH


def get_service_status() -> dict:
    """Check if the TensorTrap service is installed, enabled, and running."""
    if _SYSTEM == "Darwin":
        return _launchd_status()
    return _systemd_status()


def install_service() -> dict:
    """Install and start the TensorTrap background service."""
    if _SYSTEM == "Darwin":
        return _launchd_install()
    return _systemd_install()


def uninstall_service() -> dict:
    """Stop and remove the TensorTrap service."""
    if _SYSTEM == "Darwin":
        return _launchd_uninstall()
    return _systemd_uninstall()


def restart_service() -> dict:
    """Restart the TensorTrap service."""
    if _SYSTEM == "Darwin":
        return _launchd_restart()
    return _systemd_restart()


# --- systemd (Linux) ---


def _systemd_status() -> dict:
    installed = SYSTEMD_PATH.exists()
    enabled = False
    active = False

    if installed:
        enabled = _systemctl("is-enabled") == 0
        active = _systemctl("is-active") == 0

    return {
        "installed": installed,
        "enabled": enabled,
        "active": active,
        "service_path": str(SYSTEMD_PATH),
        "platform": "systemd",
    }


def _systemd_install() -> dict:
    SYSTEMD_DIR.mkdir(parents=True, exist_ok=True)

    content = SYSTEMD_TEMPLATE.format(python_exe=sys.executable)
    SYSTEMD_PATH.write_text(content, encoding="utf-8")

    _systemctl("daemon-reload")
    rc_enable = _systemctl("enable", SERVICE_NAME)
    rc_start = _systemctl("start", SERVICE_NAME)

    return {
        "installed": True,
        "enabled": rc_enable == 0,
        "active": rc_start == 0,
        "service_path": str(SYSTEMD_PATH),
        "platform": "systemd",
    }


def _systemd_uninstall() -> dict:
    if not SYSTEMD_PATH.exists():
        return {"installed": False, "message": "Service not installed"}

    _systemctl("stop", SERVICE_NAME)
    _systemctl("disable", SERVICE_NAME)
    SYSTEMD_PATH.unlink(missing_ok=True)
    _systemctl("daemon-reload")

    return {"installed": False, "message": "Service uninstalled"}


def _systemd_restart() -> dict:
    if not SYSTEMD_PATH.exists():
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


# --- launchd (macOS) ---


def _launchd_status() -> dict:
    installed = LAUNCHD_PATH.exists()
    active = False

    if installed:
        active = _launchctl_is_loaded()

    return {
        "installed": installed,
        "enabled": installed,  # launchd: installed == enabled (RunAtLoad)
        "active": active,
        "service_path": str(LAUNCHD_PATH),
        "platform": "launchd",
    }


def _launchd_install() -> dict:
    LAUNCHD_DIR.mkdir(parents=True, exist_ok=True)

    # Log directory
    log_dir = Path.home() / "Library" / "Logs" / "TensorTrap"
    log_dir.mkdir(parents=True, exist_ok=True)

    content = LAUNCHD_TEMPLATE.format(
        label=LAUNCHD_LABEL,
        python_exe=sys.executable,
        log_dir=str(log_dir),
    )
    LAUNCHD_PATH.write_text(content, encoding="utf-8")

    # Load the agent
    rc = _run_cmd("launchctl", "load", str(LAUNCHD_PATH))

    return {
        "installed": True,
        "enabled": True,
        "active": rc == 0,
        "service_path": str(LAUNCHD_PATH),
        "platform": "launchd",
    }


def _launchd_uninstall() -> dict:
    if not LAUNCHD_PATH.exists():
        return {"installed": False, "message": "Service not installed"}

    _run_cmd("launchctl", "unload", str(LAUNCHD_PATH))
    LAUNCHD_PATH.unlink(missing_ok=True)

    return {"installed": False, "message": "Service uninstalled"}


def _launchd_restart() -> dict:
    if not LAUNCHD_PATH.exists():
        return {"error": "Service not installed"}

    _run_cmd("launchctl", "unload", str(LAUNCHD_PATH))
    rc = _run_cmd("launchctl", "load", str(LAUNCHD_PATH))
    return {
        "restarted": rc == 0,
        "active": _launchctl_is_loaded(),
    }


def _launchctl_is_loaded() -> bool:
    """Check if the TensorTrap launchd agent is currently loaded."""
    try:
        result = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return LAUNCHD_LABEL in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _run_cmd(*args: str) -> int:
    """Run a command and return the exit code."""
    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            timeout=10,
        )
        return result.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 1
