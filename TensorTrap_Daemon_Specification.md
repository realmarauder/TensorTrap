# TensorTrap Daemon Mode Specification

## Purpose

This specification defines watch mode, systemd integration, and automated alerting for TensorTrap. The goal is to enable "install and forget" operation similar to ClamAV, where the scanner runs automatically and only notifies users when threats are detected.

---

## Current Pain Point

Users must manually:
1. Navigate to TensorTrap directory
2. Activate virtual environment (`source venv/bin/activate`)
3. Run scan command
4. Review output

This friction prevents adoption. Security tools must run automatically with zero daily interaction.

---

## New CLI Flags

### --quiet

Suppress all output unless findings meet threshold.

```bash
tensortrap scan ~/Models --quiet
# No output if clean
# Only prints findings if HIGH or CRITICAL detected

tensortrap scan ~/Models --quiet --threshold medium
# Prints if MEDIUM or higher detected
```

**Implementation:**
- Default threshold: HIGH
- Exit code 0 if clean, exit code 1 if findings meet threshold
- Enables use in cron jobs and CI/CD pipelines

### --alert

Trigger desktop notification on findings.

```bash
tensortrap scan ~/Models --alert
# Shows desktop notification if threats found
```

**Implementation (Linux):**
```python
import subprocess
import shutil

def send_notification(title: str, message: str, urgency: str = "normal"):
    """Send desktop notification via notify-send."""
    if shutil.which("notify-send"):
        subprocess.run([
            "notify-send",
            title,
            message,
            f"--urgency={urgency}",
            "--icon=dialog-warning"
        ], capture_output=True)
```

**Urgency mapping:**
- CRITICAL findings: `--urgency=critical`
- HIGH findings: `--urgency=normal`
- MEDIUM findings: `--urgency=low`

**Cross-platform (future):**
- macOS: `osascript -e 'display notification'`
- Windows: `powershell [Windows.UI.Notifications.ToastNotificationManager]`

### --log

Write scan results to log file instead of stdout.

```bash
tensortrap scan ~/Models --log /var/log/tensortrap/scan.log
```

**Log format:**
```
2025-12-11T21:30:00 INFO Scan started: /home/user/Models
2025-12-11T21:30:45 INFO Scanned 150 files in 45.2s
2025-12-11T21:30:45 WARNING Found 2 files with issues
2025-12-11T21:30:45 HIGH /home/user/Models/suspicious.safetensors: File appears truncated
2025-12-11T21:30:45 INFO Scan complete: 148 safe, 2 issues
```

### --threshold

Set minimum severity level for reporting/alerting.

```bash
tensortrap scan ~/Models --quiet --threshold critical
# Only report CRITICAL findings

tensortrap scan ~/Models --quiet --threshold medium
# Report MEDIUM, HIGH, and CRITICAL
```

**Valid values:** `info`, `low`, `medium`, `high`, `critical`

**Default:** `high` (report HIGH and CRITICAL only in quiet mode)

---

## New Commands

### tensortrap watch

Monitor directories continuously with scheduled rescans.

```bash
tensortrap watch ~/Models --interval 3600
# Scan every hour

tensortrap watch ~/Models ~/Downloads --interval 1800 --quiet --alert
# Watch multiple directories, scan every 30 minutes, notify on threats

tensortrap watch ~/Models --interval 3600 --on-change
# Also scan immediately when files change (inotify)
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| paths | list | required | Directories to monitor |
| --interval | int | 3600 | Seconds between scheduled scans |
| --on-change | flag | false | Also trigger scan on file system changes |
| --quiet | flag | false | Suppress output unless findings |
| --alert | flag | false | Desktop notification on findings |
| --log | path | none | Write to log file |
| --threshold | str | high | Minimum severity for alerts |
| --pid-file | path | none | Write PID for process management |

**Implementation:**

```python
import time
import signal
from pathlib import Path
from typing import Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class TensorTrapWatcher:
    def __init__(
        self,
        paths: list[Path],
        interval: int = 3600,
        on_change: bool = False,
        quiet: bool = False,
        alert: bool = False,
        log_file: Optional[Path] = None,
        threshold: str = "high",
    ):
        self.paths = paths
        self.interval = interval
        self.on_change = on_change
        self.quiet = quiet
        self.alert = alert
        self.log_file = log_file
        self.threshold = threshold
        self.running = True
        
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)
    
    def _handle_shutdown(self, signum, frame):
        self.running = False
    
    def run(self):
        """Main watch loop."""
        # Initial scan
        self._run_scan()
        
        # Set up file system watcher if enabled
        if self.on_change:
            observer = Observer()
            handler = ModelFileHandler(self._run_scan)
            for path in self.paths:
                observer.schedule(handler, str(path), recursive=True)
            observer.start()
        
        # Scheduled scan loop
        last_scan = time.time()
        while self.running:
            time.sleep(10)  # Check every 10 seconds
            if time.time() - last_scan >= self.interval:
                self._run_scan()
                last_scan = time.time()
        
        if self.on_change:
            observer.stop()
            observer.join()
    
    def _run_scan(self):
        """Execute scan on all watched paths."""
        # Implementation calls existing scan_directory()
        pass


class ModelFileHandler(FileSystemEventHandler):
    """Trigger scan on new model files."""
    
    MODEL_EXTENSIONS = {
        '.pt', '.pth', '.bin', '.pkl', '.pickle', '.ckpt',
        '.safetensors', '.gguf', '.onnx', '.h5', '.keras'
    }
    
    def __init__(self, scan_callback):
        self.scan_callback = scan_callback
        self._debounce_timer = None
    
    def on_created(self, event):
        if not event.is_directory:
            ext = Path(event.src_path).suffix.lower()
            if ext in self.MODEL_EXTENSIONS:
                # Debounce to avoid scanning during active downloads
                self._schedule_scan()
    
    def _schedule_scan(self):
        """Debounce scan trigger by 5 seconds."""
        # Cancel existing timer
        if self._debounce_timer:
            self._debounce_timer.cancel()
        # Schedule new scan
        self._debounce_timer = threading.Timer(5.0, self.scan_callback)
        self._debounce_timer.start()
```

**Dependencies to add:**
```toml
dependencies = [
    # ... existing deps ...
    "watchdog>=3.0.0",  # File system monitoring
]
```

### tensortrap install-service

Install TensorTrap as a systemd user service.

```bash
tensortrap install-service --watch ~/Models --interval 3600 --alert
# Creates and enables systemd user service

tensortrap install-service --uninstall
# Removes service

tensortrap install-service --status
# Shows service status
```

**Generated files:**

`~/.config/systemd/user/tensortrap.service`:
```ini
[Unit]
Description=TensorTrap AI Model Security Scanner
After=network.target

[Service]
Type=simple
ExecStart=/home/user/.local/bin/tensortrap watch /home/user/Models --interval 3600 --quiet --alert --log /home/user/.local/share/tensortrap/tensortrap.log
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
```

**Implementation:**

```python
import subprocess
from pathlib import Path

def install_service(
    watch_paths: list[Path],
    interval: int = 3600,
    alert: bool = True,
    quiet: bool = True,
):
    """Install TensorTrap as systemd user service."""
    
    # Find tensortrap executable
    tensortrap_bin = shutil.which("tensortrap")
    if not tensortrap_bin:
        # Fall back to current Python environment
        tensortrap_bin = f"{sys.executable} -m tensortrap"
    
    # Create data directory
    data_dir = Path.home() / ".local" / "share" / "tensortrap"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Build command
    paths_str = " ".join(str(p) for p in watch_paths)
    cmd = f"{tensortrap_bin} watch {paths_str} --interval {interval}"
    if quiet:
        cmd += " --quiet"
    if alert:
        cmd += " --alert"
    cmd += f" --log {data_dir}/tensortrap.log"
    
    # Generate service file
    service_content = f"""[Unit]
Description=TensorTrap AI Model Security Scanner
After=network.target

[Service]
Type=simple
ExecStart={cmd}
Restart=on-failure
RestartSec=30
Environment=DISPLAY=:0
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%U/bus

[Install]
WantedBy=default.target
"""
    
    # Write service file
    service_dir = Path.home() / ".config" / "systemd" / "user"
    service_dir.mkdir(parents=True, exist_ok=True)
    service_file = service_dir / "tensortrap.service"
    service_file.write_text(service_content)
    
    # Enable and start service
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "--user", "enable", "tensortrap.service"], check=True)
    subprocess.run(["systemctl", "--user", "start", "tensortrap.service"], check=True)
    
    print(f"TensorTrap service installed and started.")
    print(f"Log file: {data_dir}/tensortrap.log")
    print(f"Check status: systemctl --user status tensortrap")
    print(f"View logs: journalctl --user -u tensortrap -f")


def uninstall_service():
    """Remove TensorTrap systemd service."""
    subprocess.run(["systemctl", "--user", "stop", "tensortrap.service"], capture_output=True)
    subprocess.run(["systemctl", "--user", "disable", "tensortrap.service"], capture_output=True)
    
    service_file = Path.home() / ".config" / "systemd" / "user" / "tensortrap.service"
    if service_file.exists():
        service_file.unlink()
    
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    print("TensorTrap service removed.")


def service_status():
    """Show TensorTrap service status."""
    result = subprocess.run(
        ["systemctl", "--user", "status", "tensortrap.service"],
        capture_output=True,
        text=True
    )
    print(result.stdout)
    if result.stderr:
        print(result.stderr)
```

**Environment variables for desktop notifications:**

The service file includes `DISPLAY` and `DBUS_SESSION_BUS_ADDRESS` environment variables. These are required for `notify-send` to work from a systemd service. The `%U` is a systemd specifier that expands to the user's UID.

---

## Configuration File

Support persistent configuration via `~/.config/tensortrap/config.yaml`:

```yaml
# TensorTrap Configuration

# Directories to watch (used by 'watch' command and service)
watch_paths:
  - ~/Models
  - ~/Downloads
  - ~/SwarmUI/Models

# Scan interval in seconds
interval: 3600

# Alert settings
alert: true
threshold: high

# Logging
log_file: ~/.local/share/tensortrap/tensortrap.log
log_level: INFO

# Quiet mode for automated scans
quiet: true

# File extensions to scan
extensions:
  - .pt
  - .pth
  - .bin
  - .pkl
  - .pickle
  - .ckpt
  - .safetensors
  - .gguf
  - .onnx
  - .h5
  - .keras
  - .joblib

# Directories to exclude
exclude:
  - "**/venv/**"
  - "**/.git/**"
  - "**/node_modules/**"
```

**Loading config:**

```python
from pathlib import Path
import yaml

def load_config() -> dict:
    """Load configuration from file."""
    config_paths = [
        Path.home() / ".config" / "tensortrap" / "config.yaml",
        Path.home() / ".tensortrap.yaml",
        Path("/etc/tensortrap/config.yaml"),
    ]
    
    for path in config_paths:
        if path.exists():
            with open(path) as f:
                return yaml.safe_load(f)
    
    return {}  # Default empty config
```

---

## CLI Structure Update

Updated CLI commands:

```
tensortrap
├── scan <path>           # Existing - scan file or directory
│   ├── --recursive       # Existing
│   ├── --json           # Existing
│   ├── --output         # Existing
│   ├── --quiet          # NEW - suppress output unless findings
│   ├── --alert          # NEW - desktop notification
│   ├── --log <file>     # NEW - write to log file
│   └── --threshold      # NEW - minimum severity
│
├── watch <paths...>      # NEW - continuous monitoring
│   ├── --interval       # Seconds between scans
│   ├── --on-change      # Also scan on file changes
│   ├── --quiet
│   ├── --alert
│   ├── --log
│   ├── --threshold
│   └── --pid-file
│
├── install-service       # NEW - systemd integration
│   ├── --watch <paths>  # Directories to watch
│   ├── --interval
│   ├── --alert
│   ├── --uninstall
│   └── --status
│
├── info <file>          # Existing - show file metadata
└── version              # Existing
```

---

## Output Behavior Matrix

| Mode | Clean Scan | Findings Below Threshold | Findings At/Above Threshold |
|------|------------|-------------------------|----------------------------|
| Default | Full report | Full report | Full report |
| --quiet | No output, exit 0 | No output, exit 0 | Print findings, exit 1 |
| --alert | No notification | No notification | Desktop notification |
| --quiet --alert | No output, exit 0 | No output, exit 0 | Notification only, exit 1 |
| --log | Write to log | Write to log | Write to log |

---

## Log Rotation

For long-running daemon mode, implement log rotation:

```python
import logging
from logging.handlers import RotatingFileHandler

def setup_logging(log_file: Path):
    """Configure logging with rotation."""
    handler = RotatingFileHandler(
        log_file,
        maxBytes=10_000_000,  # 10 MB
        backupCount=5
    )
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    ))
    
    logger = logging.getLogger('tensortrap')
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    
    return logger
```

---

## Testing

### Unit Tests

```python
def test_quiet_mode_no_output_when_clean(tmp_path, capsys):
    """Quiet mode produces no output for clean files."""
    clean_file = tmp_path / "clean.safetensors"
    # Create valid safetensors file...
    
    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
    
    assert result.exit_code == 0
    assert result.output == ""

def test_quiet_mode_outputs_on_findings(tmp_path, capsys):
    """Quiet mode outputs findings above threshold."""
    # Create file with HIGH severity finding...
    
    result = runner.invoke(app, ["scan", str(tmp_path), "--quiet"])
    
    assert result.exit_code == 1
    assert "HIGH" in result.output

def test_alert_sends_notification(tmp_path, mocker):
    """Alert mode triggers desktop notification."""
    mock_notify = mocker.patch("tensortrap.notifications.send_notification")
    # Create file with findings...
    
    runner.invoke(app, ["scan", str(tmp_path), "--alert"])
    
    mock_notify.assert_called_once()

def test_watch_rescans_on_interval(tmp_path, mocker):
    """Watch mode rescans at specified interval."""
    # Test watch loop timing...
    pass

def test_install_service_creates_systemd_file(tmp_path, mocker):
    """install-service creates correct systemd unit file."""
    mocker.patch("pathlib.Path.home", return_value=tmp_path)
    mocker.patch("subprocess.run")
    
    runner.invoke(app, ["install-service", "--watch", "/home/user/Models"])
    
    service_file = tmp_path / ".config" / "systemd" / "user" / "tensortrap.service"
    assert service_file.exists()
    content = service_file.read_text()
    assert "tensortrap watch" in content
    assert "/home/user/Models" in content
```

---

## Implementation Priority

1. **--quiet and --threshold flags** - Enables cron usage immediately
2. **--alert flag** - Desktop notifications
3. **--log flag** - File logging for daemon mode
4. **watch command** - Continuous monitoring
5. **install-service command** - Systemd integration
6. **Config file support** - Persistent settings

---

## User Experience After Implementation

### Quick Start (New User)

```bash
# Install
pipx install tensortrap

# Set up automatic scanning
tensortrap install-service --watch ~/Models ~/Downloads --interval 3600 --alert

# Done. TensorTrap now:
# - Runs automatically on login
# - Scans every hour
# - Shows desktop notification if threats found
# - Logs to ~/.local/share/tensortrap/tensortrap.log
```

### Manual Scan

```bash
# Full report
tensortrap scan ~/Models

# Quick check (CI/CD)
tensortrap scan ~/Models --quiet && echo "Clean" || echo "Issues found"

# Generate reports
tensortrap scan ~/Models --output report --format html,json
```

### Service Management

```bash
# Check status
tensortrap install-service --status

# View live logs
journalctl --user -u tensortrap -f

# Stop temporarily
systemctl --user stop tensortrap

# Remove completely
tensortrap install-service --uninstall
```

---

## Dependencies Summary

Add to `pyproject.toml`:

```toml
dependencies = [
    "typer>=0.9.0",
    "rich>=13.0.0",
    "safetensors>=0.4.0",
    "watchdog>=3.0.0",    # NEW - file system monitoring
    "pyyaml>=6.0.0",      # NEW - config file support
]
```

---

## Notes for Claude Code

1. Start with `--quiet` and `--threshold` flags - these are the simplest and enable cron immediately
2. The `watch` command can initially be a simple sleep loop before adding watchdog/inotify
3. Desktop notifications only need Linux support initially (`notify-send`)
4. The systemd service should be a user service (`~/.config/systemd/user/`), not system-wide
5. Test the DISPLAY and DBUS environment variables - notifications from services can be tricky
6. Consider adding `tensortrap config` command to generate initial config file
