"""
analyzer.py
Main entry point for the SOC Log Analyzer.

Usage:
    python analyzer.py --auth logs/auth.log --access logs/access.log
    python analyzer.py --auth logs/auth.log
    python analyzer.py --access logs/nginx.log --out reports/custom.txt
"""

import argparse
import sys

from parser import parse_auth_log, parse_access_log
from detector import run_all_detections
from report import print_report, save_report


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="SOC Log Analyzer - detect brute force, scanning, "
                    "and suspicious IP activity in log files."
    )
    p.add_argument("--auth", help="Path to a Linux auth.log / secure log file")
    p.add_argument("--access", help="Path to an Apache/Nginx access log file")
    p.add_argument(
        "--out", default="reports/report.txt",
        help="Path to save the generated report (default: reports/report.txt)"
    )
    p.add_argument(
        "--no-save", action="store_true",
        help="Only print the report to the terminal; don't save a file"
    )
    return p


def main():
    args = build_arg_parser().parse_args()

    if not args.auth and not args.access:
        print("Error: provide at least one of --auth or --access")
        sys.exit(1)

    auth_events = []
    access_events = []
    sources = []

    if args.auth:
        try:
            auth_events = parse_auth_log(args.auth)
            sources.append(args.auth)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)

    if args.access:
        try:
            access_events = parse_access_log(args.access)
            sources.append(args.access)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)

    alerts = run_all_detections(auth_events=auth_events, access_events=access_events)

    print_report(alerts, source_files=sources)

    if not args.no_save:
        path = save_report(alerts, output_path=args.out, source_files=sources)
        print(f"Report saved to:\n{path}")


if __name__ == "__main__":
    main()
