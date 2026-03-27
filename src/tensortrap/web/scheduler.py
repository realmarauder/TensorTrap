"""Asyncio-based daily scan scheduler for TensorTrap."""

import asyncio
import logging
from datetime import datetime, timedelta
from pathlib import Path

from tensortrap.config import (
    get_report_dir,
    get_report_formats,
    get_retain_days,
    load_config,
)
from tensortrap.output.reports import save_reports
from tensortrap.scanner.engine import collect_files, scan_files_with_progress

logger = logging.getLogger("tensortrap.scheduler")


class ScanScheduler:
    """Runs scheduled scans based on config."""

    def __init__(self):
        self._task: asyncio.Task | None = None
        self._running = False
        self.last_run: datetime | None = None
        self.next_run: datetime | None = None

    @property
    def is_running(self) -> bool:
        return bool(self._running)

    def status(self) -> dict:
        """Get scheduler status."""
        config = load_config()
        enabled = config.get("schedule", {}).get("enabled", False)
        return {
            "enabled": enabled,
            "running": self._running,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "scan_time": config.get("schedule", {}).get("scan_time", "03:00"),
        }

    async def start(self):
        """Start the scheduler loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Scheduler started")

    async def stop(self):
        """Stop the scheduler."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass
        self._task = None
        logger.info("Scheduler stopped")

    async def _loop(self):
        """Main scheduler loop."""
        while self._running:
            try:
                config = load_config()
                schedule = config.get("schedule", {})

                if not schedule.get("enabled", False):
                    self.next_run = None
                    await asyncio.sleep(60)
                    continue

                # Calculate next run time
                scan_time_str = schedule.get("scan_time", "03:00")
                sleep_seconds = self._seconds_until(scan_time_str)
                now = datetime.now()
                self.next_run = now + timedelta(seconds=sleep_seconds)

                logger.info(
                    "Next scan scheduled for %s (in %d seconds)",
                    self.next_run.strftime("%Y-%m-%d %H:%M"),
                    sleep_seconds,
                )

                await asyncio.sleep(sleep_seconds)

                if not self._running:
                    break

                # Reload config in case it changed during sleep
                config = load_config()
                schedule = config.get("schedule", {})

                if not schedule.get("enabled", False):
                    continue

                # Run the scan
                await asyncio.to_thread(self._run_scan, config)
                self.last_run = datetime.now()

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Scheduler error")
                await asyncio.sleep(60)

    def _run_scan(self, config: dict) -> None:
        """Execute a scheduled scan."""
        schedule = config.get("schedule", {})
        scan_paths = schedule.get("scan_paths", [])
        recursive = schedule.get("recursive", True)
        context_analysis = schedule.get("context_analysis", True)
        confidence_threshold = schedule.get("confidence_threshold", 0.5)

        if not scan_paths:
            logger.warning("No scan paths configured, skipping scheduled scan")
            return

        report_dir = get_report_dir(config)
        formats = get_report_formats(config)
        if "json" not in formats:
            formats = [*formats, "json"]
        retain_days = get_retain_days(config)

        for path_str in scan_paths:
            path = Path(path_str).expanduser()
            if not path.exists():
                logger.warning("Scan path does not exist: %s", path)
                continue

            logger.info("Scanning: %s", path)
            files = collect_files(path, recursive=recursive)

            if not files:
                logger.info("No model files found in %s", path)
                continue

            results = list(
                scan_files_with_progress(
                    files,
                    compute_hash=True,
                    use_context_analysis=context_analysis,
                    confidence_threshold=confidence_threshold,
                )
            )

            save_reports(
                results,
                scan_path=str(path),
                output_dir=report_dir,
                formats=formats,
                retain_days=retain_days,
            )

            safe = sum(1 for r in results if r.is_safe)
            logger.info(
                "Scan complete: %d files (%d safe, %d with issues)",
                len(results),
                safe,
                len(results) - safe,
            )

    @staticmethod
    def _seconds_until(time_str: str) -> int:
        """Calculate seconds until the next occurrence of time_str (HH:MM)."""
        try:
            parts = time_str.split(":")
            target_hour = int(parts[0])
            target_minute = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            target_hour = 3
            target_minute = 0

        now = datetime.now()
        target = now.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)

        if target <= now:
            target += timedelta(days=1)

        return int((target - now).total_seconds())


# Global scheduler instance
scheduler = ScanScheduler()
