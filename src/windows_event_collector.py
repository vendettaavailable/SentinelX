
import csv
import xml.etree.ElementTree as ET
from pathlib import Path

import win32evtlog

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_FILE = BASE_DIR / "data" / "windows_auth_events.csv"

NAMESPACE = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

QUERY = """
*[System[(EventID=4624 or EventID=4625)]]
"""


def parse_event(event_handle):
    """Render a Windows event as XML and extract authentication fields."""
    xml_text = win32evtlog.EvtRender(
        event_handle,
        win32evtlog.EvtRenderEventXml,
    )

    root = ET.fromstring(xml_text)
    system = root.find("e:System", NAMESPACE)

    event_id = int(
        system.findtext("e:EventID", default="0", namespaces=NAMESPACE)
    )

    event_data = {}

    for item in root.findall(".//e:EventData/e:Data", NAMESPACE):
        name = item.attrib.get("Name")
        if name:
            event_data[name] = item.text or ""

    time_node = system.find("e:TimeCreated", NAMESPACE)
    timestamp = (
        time_node.attrib.get("SystemTime", "")
        if time_node is not None
        else ""
    )

    def clean_value(value):
        """Convert missing Windows values to empty strings."""
        if value == "-":
            return ""
        return value

    subject_username = clean_value(
        event_data.get("SubjectUserName", "")
    )

    target_username = clean_value(
        event_data.get("TargetUserName", "")
    )

    source_ip = clean_value(
        event_data.get("IpAddress", "")
    )

    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "event_type": (
            "successful_login" if event_id == 4624 else "failed_login"
        ),
        "username": target_username,
        "subject_username": subject_username,
        "target_username": target_username,
        "source_ip": source_ip,
        "logon_type": event_data.get("LogonType", ""),
        "process_name": event_data.get("ProcessName", ""),
        "status": event_data.get("Status", ""),
        "sub_status": event_data.get("SubStatus", ""),
        "host": system.findtext(
            "e:Computer", default="", namespaces=NAMESPACE
        ),
    }

def collect_windows_events(max_events=200):
    """Collect the latest successful and failed logon events."""
    query_handle = win32evtlog.EvtQuery(
        "Security",
        win32evtlog.EvtQueryChannelPath
        | win32evtlog.EvtQueryReverseDirection,
        QUERY,
    )

    events = []

    while len(events) < max_events:
        batch = win32evtlog.EvtNext(
            query_handle,
            min(20, max_events - len(events)),
        )

        if not batch:
            break

        for event_handle in batch:
            try:
                events.append(parse_event(event_handle))
            finally:
                # Release the event handle after parsing.
                event_handle.Close()

    query_handle.Close()
    return events


def save_events(events):
    """Save collected authentication events to CSV."""
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    fields = [
    "timestamp",
    "event_id",
    "event_type",
    "username",
    "subject_username",
    "target_username",
    "source_ip",
    "logon_type",
    "process_name",
    "status",
    "sub_status",
    "host",
    ]

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(events)

    print(f"Windows events collected: {len(events)}")
    print(f"CSV saved to: {OUTPUT_FILE}")

    populated_usernames = sum(bool(e["username"]) for e in events)
    populated_ips = sum(bool(e["source_ip"]) for e in events)

    print(f"Events with username: {populated_usernames}")
    print(f"Events with source IP: {populated_ips}")


def main():
    try:
        events = collect_windows_events()
        save_events(events)
    except Exception as error:
        print(f"Collection failed: {error}")
        print(
            "Check that the Security log is accessible. "
            "If access is denied, run VS Code as administrator."
        )


if __name__ == "__main__":
    main()
