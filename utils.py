"""
utils.py
Helper functions used across the SOC Log Analyzer project.
"""

import os
from datetime import datetime


def ensure_dir(path: str) -> None:
    """Create a directory if it doesn't already exist."""
    os.makedirs(path, exist_ok=True)


def read_lines(filepath: str):
    """Read a log file and return a list of non-empty lines."""
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Log file not found: {filepath}")

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def timestamp() -> str:
    """Return a human-readable timestamp for reports."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def severity_label(level: str) -> str:
    """Normalize severity labels."""
    return level.strip().upper()
