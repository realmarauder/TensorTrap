"""Configuration management for TensorTrap."""

import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "tensortrap"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.toml"
DEFAULT_REPORT_DIR = Path.home() / ".local" / "share" / "tensortrap" / "reports"
DEFAULT_RETAIN_DAYS = 30
DEFAULT_REPORT_FORMATS = ["txt", "json", "html", "csv"]

DEFAULTS = {
    "reports": {
        "directory": str(DEFAULT_REPORT_DIR),
        "retain_days": DEFAULT_RETAIN_DAYS,
        "formats": DEFAULT_REPORT_FORMATS,
    },
}

DEFAULT_CONFIG_CONTENT = """\
# TensorTrap Configuration
# https://github.com/realmarauder/TensorTrap

[reports]
# Directory where scan reports are saved
directory = "{report_dir}"

# Number of days to keep reports (0 = keep forever)
retain_days = {retain_days}

# Report formats to generate: txt, json, html, csv
formats = [{formats}]
"""


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base, returning a new dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(config_path: Path | None = None) -> dict:
    """Load configuration from TOML file, merged with defaults.

    Args:
        config_path: Path to config file. Uses default if None.

    Returns:
        Configuration dictionary with all defaults filled in.
    """
    path = config_path or DEFAULT_CONFIG_PATH

    if path.exists():
        with open(path, "rb") as f:
            user_config = tomllib.load(f)
        return _deep_merge(DEFAULTS, user_config)

    return _deep_merge(DEFAULTS, {})


def get_report_dir(config: dict) -> Path:
    """Get the resolved report directory from config."""
    raw = config["reports"]["directory"]
    return Path(raw).expanduser()


def get_retain_days(config: dict) -> int:
    """Get report retention days from config."""
    return int(config["reports"]["retain_days"])


def get_report_formats(config: dict) -> list[str]:
    """Get report formats from config."""
    return list(config["reports"]["formats"])


def save_default_config(
    config_path: Path | None = None,
    formats: list[str] | None = None,
    retain_days: int | None = None,
) -> Path:
    """Create a default config file.

    Args:
        config_path: Path to write config. Uses default if None.
        formats: Report formats to save. Uses DEFAULT_REPORT_FORMATS if None.
        retain_days: Retention days to save. Uses DEFAULT_RETAIN_DAYS if None.

    Returns:
        Path to the created config file.
    """
    path = config_path or DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    chosen_formats = formats or DEFAULT_REPORT_FORMATS
    chosen_retain = retain_days if retain_days is not None else DEFAULT_RETAIN_DAYS
    formats_str = ", ".join(f'"{f}"' for f in chosen_formats)
    content = DEFAULT_CONFIG_CONTENT.format(
        report_dir=str(DEFAULT_REPORT_DIR),
        retain_days=chosen_retain,
        formats=formats_str,
    )

    path.write_text(content, encoding="utf-8")
    return path


def update_config_value(key: str, value: str, config_path: Path | None = None) -> None:
    """Update a single config value by rewriting the TOML file.

    Args:
        key: Dotted key like 'reports.retain_days'
        value: String value to set (will be parsed appropriately)
        config_path: Path to config file. Uses default if None.
    """
    path = config_path or DEFAULT_CONFIG_PATH

    if not path.exists():
        save_default_config(path)

    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()

    parts = key.split(".")
    if len(parts) != 2:
        raise ValueError(f"Key must be in 'section.name' format, got: {key}")

    section, name = parts
    parsed_value = _parse_value(value)

    in_section = False
    found = False
    new_lines = []

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped == f"[{section}]"

        if in_section and stripped.startswith(f"{name} =") or in_section and stripped.startswith(
            f"{name}="
        ):
            new_lines.append(f"{name} = {parsed_value}")
            found = True
        else:
            new_lines.append(line)

    if not found:
        # Add to the appropriate section or create it
        section_header = f"[{section}]"
        if section_header in [line.strip() for line in lines]:
            # Find the section and append
            final_lines = []
            added = False
            in_target = False
            for line in new_lines:
                final_lines.append(line)
                stripped = line.strip()
                if stripped == section_header:
                    in_target = True
                elif in_target and not added and (
                    stripped == "" or (stripped.startswith("[") and stripped.endswith("]"))
                ):
                    final_lines.insert(-1, f"{name} = {parsed_value}")
                    added = True
                    in_target = False
            if not added:
                final_lines.append(f"{name} = {parsed_value}")
            new_lines = final_lines
        else:
            new_lines.append("")
            new_lines.append(f"[{section}]")
            new_lines.append(f"{name} = {parsed_value}")

    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def _parse_value(value: str) -> str:
    """Parse a string value into TOML representation."""
    # Integer
    try:
        return str(int(value))
    except ValueError:
        pass

    # Float
    try:
        return str(float(value))
    except ValueError:
        pass

    # Boolean
    if value.lower() in ("true", "false"):
        return value.lower()

    # List (comma-separated)
    if "," in value:
        items = [item.strip() for item in value.split(",")]
        return "[" + ", ".join(f'"{item}"' for item in items) + "]"

    # Path-like or string — expand ~ for display but store as-is
    return f'"{value}"'
