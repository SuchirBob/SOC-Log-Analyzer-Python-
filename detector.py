"""
detector.py
Detection logic for identifying suspicious activity in parsed log events.
"""

from collections import Counter, defaultdict

# --- Thresholds (tune as needed) ------------------------------------------

SSH_BRUTE_FORCE_THRESHOLD = 10     # failed logins from one IP
FAILED_LOGIN_THRESHOLD = 5         # generic failed-login alert
HTTP_404_THRESHOLD = 20            # repeated 404s from one IP
HIGH_REQUEST_THRESHOLD = 200       # total requests from one IP


def detect_ssh_brute_force(auth_events):
    """Detect SSH brute-force attempts: many failed logins from one IP."""
    failed_by_ip = Counter(
        e["ip"] for e in auth_events if e["type"] == "failed"
    )

    alerts = []
    for ip, count in failed_by_ip.items():
        if count >= SSH_BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "severity": "HIGH",
                "title": "SSH Brute Force Detected",
                "ip": ip,
                "detail": f"Failed Attempts: {count}",
            })
        elif count >= FAILED_LOGIN_THRESHOLD:
            alerts.append({
                "severity": "MEDIUM",
                "title": "Repeated Failed Login Attempts",
                "ip": ip,
                "detail": f"Failed Attempts: {count}",
            })
    return alerts


def detect_invalid_users(auth_events):
    """Detect repeated login attempts using invalid/non-existent usernames."""
    invalid_by_ip = defaultdict(set)
    for e in auth_events:
        if e["type"] in ("invalid_user", "failed"):
            invalid_by_ip[e["ip"]].add(e["user"])

    alerts = []
    for ip, users in invalid_by_ip.items():
        if len(users) >= 5:
            alerts.append({
                "severity": "MEDIUM",
                "title": "Multiple Invalid Usernames Attempted",
                "ip": ip,
                "detail": f"Distinct Usernames Tried: {len(users)}",
            })
    return alerts


def detect_web_scanning(access_events):
    """Detect web scanning behavior via repeated 404 responses."""
    not_found_by_ip = Counter(
        e["ip"] for e in access_events if e["status"] == 404
    )

    alerts = []
    for ip, count in not_found_by_ip.items():
        if count >= HTTP_404_THRESHOLD:
            alerts.append({
                "severity": "MEDIUM",
                "title": "Repeated 404 Requests",
                "ip": ip,
                "detail": f"404 Errors: {count}",
            })
    return alerts


def detect_high_frequency_ips(access_events):
    """Detect IPs making an unusually high number of requests overall."""
    total_by_ip = Counter(e["ip"] for e in access_events)

    alerts = []
    for ip, count in total_by_ip.items():
        if count >= HIGH_REQUEST_THRESHOLD:
            alerts.append({
                "severity": "LOW",
                "title": "High Request Frequency",
                "ip": ip,
                "detail": f"Total Requests: {count}",
            })
    return alerts


def run_all_detections(auth_events=None, access_events=None):
    """Run all detection rules and return a combined list of alerts."""
    alerts = []

    if auth_events:
        alerts.extend(detect_ssh_brute_force(auth_events))
        alerts.extend(detect_invalid_users(auth_events))

    if access_events:
        alerts.extend(detect_web_scanning(access_events))
        alerts.extend(detect_high_frequency_ips(access_events))

    # Sort so HIGH severity alerts show first
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: order.get(a["severity"], 3))
    return alerts
