import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_FILE = BASE_DIR / "data" / "auth_events.csv"
WINDOWS_DATA_FILE = BASE_DIR / "data" / "windows_auth_events.csv"
WINDOWS_REPORT_FILE = BASE_DIR / "reports" / "windows_alerts.json"
REPORT_FILE = BASE_DIR / "reports" / "alerts.json"

FAILURE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5

def load_events(file_path):
    """Load authentication events from a CSV file."""
    with open(file_path, "r", newline="", encoding="utf-8") as file:
        events = list(csv.DictReader(file))

    return events


def calculate_risk_score(failure_count):
    """Calculate a demonstration risk score."""

    if failure_count >= 10:
        return 100
    elif failure_count >= 7:
        return 75
    elif failure_count >= 5:
        return 50
    else:
        return 0


def get_severity(risk_score):
    """Convert a risk score into a severity label."""

    if risk_score >= 100:
        return "CRITICAL"
    elif risk_score >= 75:
        return "HIGH"
    elif risk_score >= 50:
        return "MEDIUM"
    else:
        return "LOW"

def detect_repeated_failures(events):
    """Detect repeated failed logins within a time window."""

    grouped_events = defaultdict(list)

    for event in events:
        if event["event_type"] == "failed_login":
            key = (event["username"], event["source_ip"])
            grouped_events[key].append(event)

    alerts = []

    for (username, source_ip), failures in grouped_events.items():
        failures.sort(key=lambda event: event["timestamp"])

        for start_index, first_event in enumerate(failures):
            start_time = datetime.fromisoformat(first_event["timestamp"])
            end_time = start_time + timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            matching_events = [
                event
                for event in failures[start_index:]
                if start_time
                <= datetime.fromisoformat(event["timestamp"])
                <= end_time
            ]

            if len(matching_events) >= FAILURE_THRESHOLD:
                alerts.append({
                    "username": username,
                    "source_ip": source_ip,
                    "failure_count": len(matching_events),
                    "first_seen": matching_events[0]["timestamp"],
                    "last_seen": matching_events[-1]["timestamp"],
                    "risk_score": calculate_risk_score(len(matching_events)),
                    "severity": get_severity(calculate_risk_score(len(matching_events))),
                    "rule": "Repeated Failed Logins",
                    "reason": (
                        "Repeated failed logins within "
                        f"{TIME_WINDOW_MINUTES} minutes."
                    ),
                })

                break

    return alerts

def detect_failure_then_success(events):
    """Detect repeated failures followed by a successful login."""

    grouped_events = defaultdict(list)

    for event in events:
        key = (event["username"], event["source_ip"])
        grouped_events[key].append(event)

    alerts = []

    for (username, source_ip), user_events in grouped_events.items():
        user_events.sort(key=lambda event: event["timestamp"])

        for index, event in enumerate(user_events):
            if event["event_type"] != "successful_login":
                continue

            success_time = datetime.fromisoformat(event["timestamp"])
            window_start = success_time - timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            previous_failures = [
                previous_event
                for previous_event in user_events[:index]
                if previous_event["event_type"] == "failed_login"
                and window_start
                <= datetime.fromisoformat(previous_event["timestamp"])
                <= success_time
            ]

            if len(previous_failures) >= FAILURE_THRESHOLD:
                risk_score = 100

                alerts.append({
                    "username": username,
                    "source_ip": source_ip,
                    "failure_count": len(previous_failures),
                    "successful_login": event["timestamp"],
                    "risk_score": risk_score,
                    "severity": get_severity(risk_score),
                    "rule": "Failed Logins Followed by Success",
                    "reason": (
                        "Repeated failed logins followed by a "
                        "successful login within 5 minutes."
                    ),
                })

                break

    return alerts

def detect_windows_failures(events):
    """Detect repeated Windows failed logons when account or IP data exists."""

    grouped_events = defaultdict(list)

    for event in events:
        if event.get("event_type") != "failed_login":
            continue

        username = event.get("username", "").strip()
        source_ip = event.get("source_ip", "").strip()

        # Do not group events when both identifiers are missing.
        if not username and not source_ip:
            continue

        key = (username, source_ip)
        grouped_events[key].append(event)

    alerts = []

    for (username, source_ip), failures in grouped_events.items():
        failures.sort(key=lambda event: event["timestamp"])

        for start_index, first_event in enumerate(failures):
            start_time = datetime.fromisoformat(
                first_event["timestamp"].replace("Z", "+00:00")
            )
            end_time = start_time + timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            matching_events = []

            for event in failures[start_index:]:
                event_time = datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )

                if start_time <= event_time <= end_time:
                    matching_events.append(event)

            if len(matching_events) >= FAILURE_THRESHOLD:
                count = len(matching_events)
                score = calculate_risk_score(count)

                alerts.append({
                    "username": username or "UNKNOWN",
                    "source_ip": source_ip or "UNKNOWN",
                    "failure_count": count,
                    "first_seen": matching_events[0]["timestamp"],
                    "last_seen": matching_events[-1]["timestamp"],
                    "risk_score": score,
                    "severity": get_severity(score),
                    "rule": "Windows Repeated Failed Logons",
                    "reason": (
                        f"{count} failed Windows logons within "
                        f"{TIME_WINDOW_MINUTES} minutes."
                    ),
                    "host": first_event.get("host", ""),
                    "logon_type": first_event.get("logon_type", ""),
                    "process_name": first_event.get("process_name", ""),
                    "subject_username": first_event.get("subject_username", ""),
                    "target_username": first_event.get("target_username", ""),
                    "status": first_event.get("status", ""),
                    "sub_status": first_event.get("sub_status", ""),
                })

                break

    return alerts

def analyze_windows_events():
    """Analyze collected Windows authentication events."""

    if not WINDOWS_DATA_FILE.exists():
        print(f"Windows dataset not found: {WINDOWS_DATA_FILE}")
        return

    windows_events = load_events(WINDOWS_DATA_FILE)

    alerts = detect_windows_failures(windows_events)

    WINDOWS_REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(WINDOWS_REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print("\n" + "=" * 50)
    print("SENTINELX - WINDOWS AUTHENTICATION ANALYSIS")
    print("=" * 50)

    print(f"Windows events analyzed: {len(windows_events)}")
    print(f"Windows alerts generated: {len(alerts)}")

    for number, alert in enumerate(alerts, start=1):
        print(f"\nWindows Alert #{number}")

        for key, value in alert.items():
            print(f"{key.replace('_', ' ').title()}: {value}")

    print(f"\nWindows report saved to: {WINDOWS_REPORT_FILE}")

def save_alerts(alerts):
    """Save detected alerts to a JSON report."""

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    print(f"\nReport saved to: {REPORT_FILE}")


def main():
    if not DATA_FILE.exists():
        print(f"Dataset not found: {DATA_FILE}")
        return

    events = load_events(DATA_FILE)
    alerts = detect_repeated_failures(events)
    alerts.extend(detect_failure_then_success(events))

    print("=" * 50)
    print("SENTINELX - AUTHENTICATION DETECTION")
    print("=" * 50)

    print(f"Events analyzed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    for number, alert in enumerate(alerts, start=1):
        print(f"\nAlert #{number}")

        for key, value in alert.items():
            print(f"{key.replace('_', ' ').title()}: {value}")

    save_alerts(alerts)


if __name__ == "__main__":
    main()
    analyze_windows_events()