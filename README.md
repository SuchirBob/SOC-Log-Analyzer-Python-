# SOC Log Analyzer (Python)

> ⚠️ **Educational Purpose**
>
> This project is a Python-based SOC (Security Operations Center) log analyzer developed for educational purposes. It analyzes Linux authentication logs and web server logs to identify common security events such as brute-force attacks, repeated login failures, suspicious IP activity, and web scanning attempts.

---

## Overview

SOC analysts spend much of their time reviewing logs to detect malicious activity. This project automates the analysis of Linux and web server log files by identifying common Indicators of Compromise (IOCs) and generating a simple security report.

The project demonstrates fundamental blue-team skills including log analysis, event correlation, threat detection, and incident reporting.

---

## Features

- Analyze Linux authentication logs (`auth.log`)
- Analyze Apache/Nginx access logs
- Detect SSH brute-force attacks
- Detect repeated failed login attempts
- Detect suspicious IP addresses
- Detect repeated HTTP 404 requests
- Generate terminal-based security reports
- Export analysis results to a text report

---

## Project Structure

```text
SOC-Log-Analyzer/
│
├── analyzer.py          # Main analysis script
├── parser.py            # Log parsing functions
├── detector.py          # Detection logic
├── report.py            # Report generation
├── utils.py             # Helper functions
│
├── logs/                # Sample log files
│   ├── auth.log
│   ├── access.log
│   └── nginx.log
│
├── reports/             # Generated reports
│
├── requirements.txt
├── README.md
└── LICENSE
```

---

## Requirements

- Python 3.10+
- Linux (Recommended)
- Kali Linux (Optional)

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

```bash
# Analyze an auth log only
python analyzer.py --auth logs/auth.log

# Analyze a web access log only
python analyzer.py --access logs/access.log

# Analyze both at once
python analyzer.py --auth logs/auth.log --access logs/access.log

# Choose a custom report output path
python analyzer.py --auth logs/auth.log --out reports/custom_report.txt

# Print to terminal only, skip saving a report file
python analyzer.py --auth logs/auth.log --no-save
```

---

## Supported Log Types

### Linux Authentication Logs

Examples:

- `/var/log/auth.log`
- `/var/log/secure`

Detects:

- Failed SSH logins
- Successful logins
- Invalid usernames
- Brute-force attempts

---

### Web Server Logs

Supported:

- Apache Access Log
- Nginx Access Log

Detects:

- Repeated HTTP 404 errors
- Directory scanning
- Suspicious requests
- High request frequency from a single IP

---

## Detection Rules

### SSH Brute Force

Triggers when multiple failed login attempts are detected from the same IP address.

---

### Failed Login Detection

Counts authentication failures and identifies suspicious login activity.

---

### Web Scanning

Detects repeated requests for non-existent pages (404 errors), which may indicate automated scanning.

---

### Suspicious IP Detection

Highlights IP addresses responsible for a high number of authentication failures or web requests.

---

## Example Output

```text
==========================================
SOC Log Analyzer
==========================================

[HIGH]

SSH Brute Force Detected

IP Address:
192.168.1.15

Failed Attempts:
27

------------------------------------------

[MEDIUM]

Repeated 404 Requests

IP Address:
10.0.0.8

404 Errors:
41

------------------------------------------

Summary

High Alerts   : 1

Medium Alerts : 1

Low Alerts    : 0

Report saved to:

reports/report.txt
```

---

## Workflow

```text
Log File

↓

Parse Log Entries

↓

Extract Relevant Fields

↓

Apply Detection Rules

↓

Generate Alerts

↓

Display Results

↓

Save Report
```

---

## Technologies Used

- Python
- Regular Expressions (Regex)
- Collections
- Datetime
- File Handling

---

## Learning Objectives

This project helped me understand:

- Security Operations Center (SOC) workflows
- Linux authentication logs
- Apache and Nginx log formats
- Event correlation
- Threat detection
- Incident reporting
- Log parsing using Python

---

## Future Improvements

- Windows Event Log support
- JSON report export
- CSV report export
- Email alerts
- Risk scoring
- Command-line arguments
- Live log monitoring
- YARA rule integration

---

## Sample Log Sources

The project can analyze logs from:

- Linux `/var/log/auth.log`
- Apache `access.log`
- Nginx `access.log`
- Public sample log datasets

---

## Disclaimer

This project is intended for educational purposes only. It is designed to help students learn security log analysis and SOC workflows. Use only log files that you own or are authorized to analyze.

---

## License

This project is licensed under the MIT License.
