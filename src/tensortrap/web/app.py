"""FastAPI application for TensorTrap Web UI."""

import asyncio
import json
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from tensortrap import __version__
from tensortrap.config import (
    DEFAULTS,
    get_report_dir,
    get_report_formats,
    get_retain_days,
    load_config,
    save_default_config,
    update_config_value,
)
from tensortrap.output.reports import save_reports
from tensortrap.scanner.engine import collect_files, scan_files_with_progress
from tensortrap.web.scheduler import scheduler

STATIC_DIR = Path(__file__).parent / "static"

# Active scan state
_scans: dict[str, dict] = {}
_start_time: datetime | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown."""
    global _start_time
    _start_time = datetime.now()
    await scheduler.start()
    yield
    await scheduler.stop()


app = FastAPI(
    title="TensorTrap",
    version=__version__,
    lifespan=lifespan,
)


# --- API Routes ---


@app.get("/api/status")
async def api_status():
    """Server health and status."""
    config = load_config()
    uptime = (datetime.now() - _start_time).total_seconds() if _start_time else 0
    return {
        "status": "running",
        "version": __version__,
        "uptime_seconds": int(uptime),
        "report_dir": str(get_report_dir(config)),
        "scheduler": scheduler.status(),
    }


@app.get("/api/reports")
async def api_list_reports():
    """List all available reports."""
    config = load_config()
    report_dir = get_report_dir(config)

    if not report_dir.exists():
        return []

    # Group report files by timestamp
    reports: dict[str, dict] = {}
    pattern = re.compile(r"^tensortrap_report_(\d{8}_\d{6})\.(\w+)$")

    for filepath in sorted(report_dir.iterdir(), reverse=True):
        match = pattern.match(filepath.name)
        if match:
            timestamp, fmt = match.groups()
            if timestamp not in reports:
                # Parse timestamp for display
                dt = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
                reports[timestamp] = {
                    "timestamp": timestamp,
                    "date": dt.isoformat(),
                    "date_display": dt.strftime("%B %d, %Y at %I:%M %p"),
                    "formats": [],
                    "summary": None,
                }
            reports[timestamp]["formats"].append(fmt)

    # Load summary from JSON report for each timestamp
    for timestamp, report in reports.items():
        if "json" in report["formats"]:
            json_path = report_dir / f"tensortrap_report_{timestamp}.json"
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
                report["summary"] = data.get("summary", {})
            except (json.JSONDecodeError, OSError):
                pass

    return list(reports.values())


@app.get("/api/reports/{timestamp}")
async def api_get_report(timestamp: str):
    """Get a specific report's JSON data."""
    config = load_config()
    report_dir = get_report_dir(config)
    json_path = report_dir / f"tensortrap_report_{timestamp}.json"

    if not json_path.exists():
        return JSONResponse({"error": "Report not found"}, status_code=404)

    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        return data
    except (json.JSONDecodeError, OSError) as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/reports/{timestamp}/html")
async def api_get_report_html(timestamp: str):
    """Serve the HTML report directly."""
    config = load_config()
    report_dir = get_report_dir(config)
    html_path = report_dir / f"tensortrap_report_{timestamp}.html"

    if not html_path.exists():
        return JSONResponse({"error": "HTML report not found"}, status_code=404)

    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.delete("/api/reports/{timestamp}")
async def api_delete_report(timestamp: str):
    """Delete all report files for a given timestamp."""
    config = load_config()
    report_dir = get_report_dir(config)
    deleted = []

    for ext in ["txt", "json", "html", "csv"]:
        filepath = report_dir / f"tensortrap_report_{timestamp}.{ext}"
        if filepath.exists():
            filepath.unlink()
            deleted.append(str(filepath))

    if not deleted:
        return JSONResponse({"error": "No reports found"}, status_code=404)

    return {"deleted": deleted}


@app.get("/api/browse")
async def api_browse(path: str = "~"):
    """List directories at a given path for the folder picker."""
    try:
        target = Path(path).expanduser().resolve()
    except (ValueError, OSError):
        return JSONResponse({"error": "Invalid path"}, status_code=400)

    if not target.exists():
        return JSONResponse({"error": "Path not found"}, status_code=404)

    if not target.is_dir():
        target = target.parent

    dirs = []
    try:
        for entry in sorted(target.iterdir()):
            if entry.is_dir() and not entry.name.startswith("."):
                dirs.append(entry.name)
    except PermissionError:
        pass

    return {
        "current": str(target),
        "parent": str(target.parent) if target != target.parent else None,
        "directories": dirs,
    }


@app.get("/api/config")
async def api_get_config():
    """Get current configuration."""
    return load_config()


@app.put("/api/config")
async def api_update_config(updates: dict):
    """Update configuration values."""
    errors = []
    for key, value in updates.items():
        try:
            update_config_value(key, str(value))
        except ValueError as e:
            errors.append({"key": key, "error": str(e)})

    if errors:
        return JSONResponse({"errors": errors}, status_code=400)

    return load_config()


@app.post("/api/config/reset")
async def api_reset_config():
    """Reset configuration to defaults."""
    save_default_config()
    return DEFAULTS


@app.post("/api/scan")
async def api_start_scan(request: dict):
    """Start a new scan. Returns scan_id for WebSocket tracking."""
    scan_id = str(uuid.uuid4())[:8]
    _scans[scan_id] = {
        "path": request.get("path", ""),
        "recursive": request.get("recursive", True),
        "context_analysis": request.get("context_analysis", True),
        "external_validation": request.get("external_validation", False),
        "confidence_threshold": request.get("confidence_threshold", 0.5),
        "entropy_threshold": request.get("entropy_threshold", 7.0),
        "status": "pending",
    }
    return {"scan_id": scan_id}


@app.websocket("/ws/scan/{scan_id}")
async def ws_scan(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for live scan progress."""
    await websocket.accept()

    if scan_id not in _scans:
        await websocket.send_json({"type": "error", "message": "Invalid scan ID"})
        await websocket.close()
        return

    scan_config = _scans[scan_id]
    scan_path = Path(scan_config["path"]).expanduser()
    cancelled = False

    if not scan_path.exists():
        await websocket.send_json(
            {
                "type": "error",
                "message": f"Path not found: {scan_path}",
            }
        )
        await websocket.close()
        return

    try:
        # Collecting files
        await websocket.send_json({"type": "collecting", "message": "Discovering model files..."})

        files = await asyncio.to_thread(
            collect_files, scan_path, recursive=scan_config["recursive"]
        )

        if not files:
            await websocket.send_json(
                {
                    "type": "complete",
                    "summary": {
                        "total_files": 0,
                        "safe_files": 0,
                        "unsafe_files": 0,
                        "message": "No model files found",
                    },
                }
            )
            await websocket.close()
            return

        await websocket.send_json({"type": "files_found", "total": len(files)})

        # Scan files with progress
        results = []
        current = 0

        def scan_generator():
            return list(
                scan_files_with_progress(
                    files,
                    compute_hash=True,
                    use_context_analysis=scan_config["context_analysis"],
                    use_external_validation=scan_config["external_validation"],
                    confidence_threshold=scan_config["confidence_threshold"],
                    entropy_threshold=scan_config["entropy_threshold"],
                )
            )

        # Run the scan in a thread and send progress
        # We need to iterate one at a time for progress, so we use a queue
        result_queue: asyncio.Queue = asyncio.Queue()

        def scan_with_queue():
            for result in scan_files_with_progress(
                files,
                compute_hash=True,
                use_context_analysis=scan_config["context_analysis"],
                use_external_validation=scan_config["external_validation"],
                confidence_threshold=scan_config["confidence_threshold"],
                entropy_threshold=scan_config["entropy_threshold"],
            ):
                result_queue.put_nowait(result)
            result_queue.put_nowait(None)  # Sentinel

        scan_task = asyncio.get_event_loop().run_in_executor(None, scan_with_queue)

        while True:
            try:
                result = await asyncio.wait_for(result_queue.get(), timeout=0.1)
            except asyncio.TimeoutError:
                # Check if websocket is still connected
                try:
                    await asyncio.wait_for(websocket.receive_text(), timeout=0.01)
                except asyncio.TimeoutError:
                    continue
                except WebSocketDisconnect:
                    cancelled = True
                    break
                continue

            if result is None:
                break

            results.append(result)
            current += 1

            filename = result.filepath.name
            if len(filename) > 40:
                filename = filename[:37] + "..."

            await websocket.send_json(
                {
                    "type": "progress",
                    "current": current,
                    "total": len(files),
                    "file": filename,
                    "percent": round(current / len(files) * 100, 1),
                }
            )

            await websocket.send_json(
                {
                    "type": "result",
                    "data": result.to_dict(),
                }
            )

        await scan_task

        if cancelled:
            return

        # Save reports
        config = load_config()
        report_dir = get_report_dir(config)
        formats = get_report_formats(config)
        # Always include JSON — the web UI needs it for report viewing
        if "json" not in formats:
            formats = [*formats, "json"]
        retain_days = get_retain_days(config)

        saved = await asyncio.to_thread(
            save_reports,
            results,
            str(scan_path),
            report_dir,
            formats,
            retain_days,
        )

        # Extract timestamp from saved file path
        report_timestamp = ""
        if saved:
            first_path = next(iter(saved.values()))
            match = re.search(r"(\d{8}_\d{6})", first_path.name)
            if match:
                report_timestamp = match.group(1)

        safe_count = sum(1 for r in results if r.is_safe)
        unsafe_count = len(results) - safe_count

        severity_counts: dict[str, int] = {}
        for r in results:
            for f in r.findings:
                sev = f.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        await websocket.send_json(
            {
                "type": "complete",
                "summary": {
                    "total_files": len(results),
                    "safe_files": safe_count,
                    "unsafe_files": unsafe_count,
                    "findings_by_severity": severity_counts,
                    "report_timestamp": report_timestamp,
                    "scan_time_ms": round(sum(r.scan_time_ms for r in results), 1),
                },
            }
        )

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        _scans.pop(scan_id, None)
        try:
            await websocket.close()
        except Exception:
            pass


# --- Static Files (must be last) ---

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
