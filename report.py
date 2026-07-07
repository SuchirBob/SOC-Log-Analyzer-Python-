"""
report.py
Generates terminal-friendly and text-file security reports from alerts.
"""

from utils import timestamp, ensure_dir
import os

BANNER = "=" * 42
DIVIDER = "-" * 42


def format_alert(alert: dict) -> str:
    lines = [
        "",
        f"[{alert['severity']}]",
        "",
        alert["title"],
        "",
        "IP Address:",
        alert["ip"],
        "",
        alert["detail"],
        "",
        DIVIDER,
    ]
    return "\n".join(lines)


def build_report_text(alerts, source_files=None) -> str:
    lines = [
        BANNER,
        "SOC Log Analyzer",
        BANNER,
        "",
        f"Generated: {timestamp()}",
    ]

    if source_files:
        lines.append("Sources: " + ", ".join(source_files))

    if not alerts:
        lines.append("")
        lines.append("No suspicious activity detected.")
    else:
        for alert in alerts:
            lines.append(format_alert(alert))

    high = sum(1 for a in alerts if a["severity"] == "HIGH")
    medium = sum(1 for a in alerts if a["severity"] == "MEDIUM")
    low = sum(1 for a in alerts if a["severity"] == "LOW")

    lines += [
        "",
        "Summary",
        "",
        f"High Alerts   : {high}",
        f"Medium Alerts : {medium}",
        f"Low Alerts    : {low}",
        "",
    ]

    return "\n".join(lines)


def print_report(alerts, source_files=None) -> None:
    print(build_report_text(alerts, source_files))


def save_report(alerts, output_path="reports/report.txt", source_files=None) -> str:
    ensure_dir(os.path.dirname(output_path) or ".")
    text = build_report_text(alerts, source_files)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(text)
    return output_path
