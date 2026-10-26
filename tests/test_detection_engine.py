import sys
import unittest
from pathlib import Path

# Allow Python to import the project module.
PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR / "src"))

from detection_engine import (
    detect_repeated_failures,
    detect_failure_then_success,
    detect_windows_failures,
    calculate_risk_score,
    get_severity,
)

def create_event(timestamp, username="user1",
                 source_ip="192.0.2.25",
                 event_type="failed_login"):

    return {
        "timestamp": timestamp,
        "username": username,
        "source_ip": source_ip,
        "event_type": event_type,
        "host": "WORKSTATION-01",
    }


class TestDetectionEngine(unittest.TestCase):

    def test_five_failures_generate_alert(self):
        events = [
            create_event("2026-10-23T10:00:01"),
            create_event("2026-10-23T10:00:04"),
            create_event("2026-10-23T10:00:07"),
            create_event("2026-10-23T10:00:10"),
            create_event("2026-10-23T10:00:13"),
        ]

        alerts = detect_repeated_failures(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failure_count"], 5)

    def test_four_failures_do_not_generate_alert(self):
        events = [
            create_event("2026-10-23T10:00:01"),
            create_event("2026-10-23T10:00:04"),
            create_event("2026-10-23T10:00:07"),
            create_event("2026-10-23T10:00:10"),
        ]

        alerts = detect_repeated_failures(events)

        self.assertEqual(len(alerts), 0)

    def test_failures_outside_window_do_not_alert(self):
        events = [
            create_event("2026-10-23T10:00:00"),
            create_event("2026-10-23T10:10:00"),
            create_event("2026-10-23T10:20:00"),
            create_event("2026-10-23T10:30:00"),
            create_event("2026-10-23T10:40:00"),
        ]

        alerts = detect_repeated_failures(events)

        self.assertEqual(len(alerts), 0)

    def test_successful_logins_are_not_failed_logins(self):
        events = [
            create_event(
                f"2026-10-23T10:00:{second:02d}",
                event_type="successful_login"
            )
            for second in [1, 4, 7, 10, 13]
        ]

        alerts = detect_repeated_failures(events)

        self.assertEqual(len(alerts), 0)

    def test_risk_score_for_five_failures(self):
        self.assertEqual(calculate_risk_score(5), 50)

    def test_ten_failures_are_critical(self):
        score = calculate_risk_score(10)
        self.assertEqual(score, 100)
        self.assertEqual(get_severity(score), "CRITICAL")

    def test_failures_followed_by_success_generate_alert(self):
        events = [
            create_event("2026-10-23T10:00:00"),
            create_event("2026-10-23T10:00:10"),
            create_event("2026-10-23T10:00:20"),
            create_event("2026-10-23T10:00:30"),
            create_event("2026-10-23T10:00:40"),
            create_event(
                "2026-10-23T10:01:00",
                event_type="successful_login"
            ),
        ]

        alerts = detect_failure_then_success(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failure_count"], 5)
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    def test_windows_alert_contains_investigation_fields(self):
        events = [
            {
                "timestamp": f"2026-10-23T10:00:0{i}",
                "event_type": "failed_login",
                "username": "user1",
                "source_ip": "192.0.2.25",
                "subject_username": "SYSTEM",
                "target_username": "user1",
                "status": "0xc000006d",
                "sub_status": "0xc000006a",
                "logon_type": "2",
                "process_name": "test_process.exe",
                "host": "WORKSTATION-01",
            }
            for i in range(1, 6)
        ]

        alerts = detect_windows_failures(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["subject_username"], "SYSTEM")
        self.assertEqual(alerts[0]["target_username"], "user1")
        self.assertEqual(alerts[0]["status"], "0xc000006d")
        self.assertEqual(alerts[0]["sub_status"], "0xc000006a")
    
    def test_windows_events_without_username_and_ip_are_skipped(self):
        events = [
            {
                "timestamp": f"2026-10-23T10:00:0{i}",
                "event_type": "failed_login",
                "username": "",
                "source_ip": "",
                "subject_username": "vaibh",
                "target_username": "",
                "status": "0xc000006d",
                "sub_status": "0xc000006a",
                "logon_type": "2",
                "process_name": "msedgewebview2.exe",
                "host": "WORKSTATION-01",
            }
            for i in range(1, 6)
        ]

        alerts = detect_windows_failures(events)

        self.assertEqual(len(alerts), 0)

    def test_windows_repeated_failures_generate_one_alert(self):
        events = [
            {
                "timestamp": f"2026-10-23T10:00:0{i}",
                "event_type": "failed_login",
                "username": "user1",
                "source_ip": "192.0.2.25",
                "subject_username": "SYSTEM",
                "target_username": "user1",
                "status": "0xc000006d",
                "sub_status": "0xc000006a",
                "logon_type": "2",
                "process_name": "test_process.exe",
                "host": "WORKSTATION-01",
            }
            for i in range(1, 7)
        ]

        alerts = detect_windows_failures(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failure_count"], 6)

    def test_windows_alert_has_correct_risk_and_severity(self):
        events = [
            {
                "timestamp": f"2026-10-23T10:00:0{i}",
                "event_type": "failed_login",
                "username": "user1",
                "source_ip": "192.0.2.25",
                "subject_username": "SYSTEM",
                "target_username": "user1",
                "status": "0xc000006d",
                "sub_status": "0xc000006a",
                "logon_type": "2",
                "process_name": "test_process.exe",
                "host": "WORKSTATION-01",
            }
            for i in range(1, 6)
        ]

        alerts = detect_windows_failures(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["risk_score"], 50)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")

if __name__ == "__main__":
    unittest.main(verbosity=2)