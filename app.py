
import json
from pathlib import Path

import pandas as pd
import streamlit as st

# --------------------------------------------------
# 1. PROJECT PATHS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

ALERTS_FILE = BASE_DIR / "reports" / "alerts.json"
WINDOWS_ALERTS_FILE = BASE_DIR / "reports" / "windows_alerts.json"
WINDOWS_EVENTS_FILE = BASE_DIR / "data" / "windows_auth_events.csv"


# --------------------------------------------------
# 2. PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SentinelX Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SentinelX")
st.subheader("Security Monitoring & Threat Detection Platform")

st.write(
    "Monitor authentication events, detect suspicious login patterns, "
    "and investigate security alerts."
)


# --------------------------------------------------
# 3. LOAD JSON ALERT REPORTS
# --------------------------------------------------

def load_alerts(file_path):
    """Load alerts from a JSON report safely."""

    if not file_path.exists():
        return []

    try:
        with file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, list):
            return [
                alert for alert in data
                if isinstance(alert, dict)
            ]

        st.warning(f"Unexpected report format: {file_path.name}")
        return []

    except (json.JSONDecodeError, OSError) as error:
        st.warning(f"Could not read {file_path.name}: {error}")
        return []


sample_alerts = load_alerts(ALERTS_FILE)
windows_alerts = load_alerts(WINDOWS_ALERTS_FILE)

all_alerts = [
    {**alert, "report_source": "Sample Authentication"}
    for alert in sample_alerts
] + [
    {**alert, "report_source": "Windows Authentication"}
    for alert in windows_alerts
]


# --------------------------------------------------
# 4. ALERT SUMMARY
# --------------------------------------------------

severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

total_alerts = len(all_alerts)

critical_alerts = sum(
    alert.get("severity") == "CRITICAL"
    for alert in all_alerts
)

high_alerts = sum(
    alert.get("severity") == "HIGH"
    for alert in all_alerts
)

medium_alerts = sum(
    alert.get("severity") == "MEDIUM"
    for alert in all_alerts
)

low_alerts = sum(
    alert.get("severity") == "LOW"
    for alert in all_alerts
)

st.divider()
st.subheader("📌 Alert Overview")

st.caption("Counts are based on the currently loaded JSON reports.")

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Alerts", total_alerts)
col2.metric("Critical", critical_alerts)
col3.metric("High", high_alerts)
col4.metric("Medium", medium_alerts)
col5.metric("Low", low_alerts)


# --------------------------------------------------
# 5. ALERT SEVERITY CHART
# --------------------------------------------------

st.divider()
st.subheader("📊 Alert Severity Distribution")

severity_counts = pd.DataFrame({
    "Severity": severity_order,
    "Alerts": [
        critical_alerts,
        high_alerts,
        medium_alerts,
        low_alerts,
    ],
})

st.bar_chart(severity_counts.set_index("Severity"))


# --------------------------------------------------
# 6. WINDOWS AUTHENTICATION STATISTICS
# --------------------------------------------------

st.divider()
st.subheader("🖥️ Windows Authentication Statistics")

windows_events = pd.DataFrame()

if WINDOWS_EVENTS_FILE.exists():
    try:
        windows_events = pd.read_csv(
            WINDOWS_EVENTS_FILE,
            dtype=str,
            keep_default_na=False,
        )

        total_events = len(windows_events)

        if "event_type" in windows_events.columns:
            successful_logins = (
                windows_events["event_type"] == "successful_login"
            ).sum()

            failed_logins = (
                windows_events["event_type"] == "failed_login"
            ).sum()
        else:
            successful_logins = 0
            failed_logins = 0

        col1, col2, col3 = st.columns(3)

        col1.metric("Windows Events", total_events)
        col2.metric("Successful Logins", int(successful_logins))
        col3.metric("Failed Logins", int(failed_logins))

        if "logon_type" in windows_events.columns:
            st.write("**Logon Type Distribution**")

            logon_types = (
                windows_events["logon_type"]
                .replace("", "Unknown")
                .replace("-", "Unknown")
                .value_counts()
            )

            if not logon_types.empty:
                st.bar_chart(logon_types)

    except (OSError, pd.errors.ParserError) as error:
        st.warning(f"Could not read Windows events: {error}")

else:
    st.info(
        "Windows event CSV not found. "
        "Run the Windows event collector first."
    )


# --------------------------------------------------
# 7. RECENT FAILED LOGIN EVENTS
# --------------------------------------------------

st.divider()
st.subheader("🔍 Recent Failed Logins")

if not windows_events.empty and "event_id" in windows_events.columns:

    failed_events = windows_events[
        windows_events["event_id"].astype(str) == "4625"
    ].copy()

    if not failed_events.empty:

        display_columns = [
            "timestamp",
            "username",
            "subject_username",
            "target_username",
            "source_ip",
            "status",
            "sub_status",
            "logon_type",
            "process_name",
            "host",
        ]

        display_columns = [
            column for column in display_columns
            if column in failed_events.columns
        ]

        st.caption(
            f"{len(failed_events)} failed-login events found in the CSV. "
            "A failed login does not automatically indicate an attack."
        )

        st.dataframe(
            failed_events[display_columns],
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info("No failed-login events found in the collected CSV.")

else:
    st.info("No Windows event data is available for investigation.")


# --------------------------------------------------
# 8. ALERT SEARCH AND FILTERS
# --------------------------------------------------

st.divider()
st.subheader("🔎 Alert Investigation")

search_text = st.text_input(
    "Search alerts",
    placeholder="Search username, IP, rule, process or host...",
)

selected_severities = st.multiselect(
    "Filter by severity",
    options=severity_order,
    default=severity_order,
)

source_options = [
    "Sample Authentication",
    "Windows Authentication",
]

selected_sources = st.multiselect(
    "Filter by report source",
    options=source_options,
    default=source_options,
)

filtered_alerts = []

for alert in all_alerts:

    if alert.get("severity", "LOW") not in selected_severities:
        continue

    if alert.get("report_source") not in selected_sources:
        continue

    searchable_text = " ".join(
        str(value)
        for key, value in alert.items()
        if key != "report_source"
    ).lower()

    if search_text.lower() not in searchable_text:
        continue

    filtered_alerts.append(alert)

st.caption(
    f"Showing {len(filtered_alerts)} of {total_alerts} alerts."
)


# --------------------------------------------------
# 9. ALERT TABLE AND SELECTABLE DETAILS
# --------------------------------------------------

if filtered_alerts:

    display_alerts = []

    for index, alert in enumerate(filtered_alerts, start=1):
        display_alerts.append({
            "Alert ID": index,
            "Source": alert.get("report_source", ""),
            "Severity": alert.get("severity", "UNKNOWN"),
            "Rule": alert.get("rule", "Unknown"),
            "Username": alert.get("username") or "UNKNOWN",
            "Source IP": alert.get("source_ip") or "UNKNOWN",
            "Risk Score": alert.get("risk_score", "N/A"),
            "Failure Count": alert.get("failure_count", "N/A"),
        })

    st.dataframe(
        pd.DataFrame(display_alerts),
        use_container_width=True,
        hide_index=True,
    )

    alert_choices = {
        (
            f'Alert {index} — '
            f'{alert.get("severity", "UNKNOWN")} — '
            f'{alert.get("rule", "Unknown")}'
        ): index - 1
        for index, alert in enumerate(filtered_alerts, start=1)
    }

    selected_alert_label = st.selectbox(
        "Select an alert to investigate",
        options=list(alert_choices.keys()),
    )

    selected_alert = filtered_alerts[
        alert_choices[selected_alert_label]
    ]

    st.markdown("### 🕵️ Alert Details")

    detail_col1, detail_col2, detail_col3 = st.columns(3)

    detail_col1.metric(
        "Severity",
        selected_alert.get("severity", "UNKNOWN"),
    )

    detail_col2.metric(
        "Risk Score",
        selected_alert.get("risk_score", "N/A"),
    )

    detail_col3.metric(
        "Failure Count",
        selected_alert.get("failure_count", "N/A"),
    )

    st.write(
        "**Detection Rule:**",
        selected_alert.get("rule", "N/A"),
    )

    st.write(
        "**Reason:**",
        selected_alert.get("reason", "N/A"),
    )

    st.write(
        "**Report Source:**",
        selected_alert.get("report_source", "N/A"),
    )

    st.write(
        "**Username:**",
        selected_alert.get("username") or "UNKNOWN",
    )

    st.write(
        "**Target Username:**",
        selected_alert.get("target_username") or "UNKNOWN",
    )

    st.write(
        "**Subject Username:**",
        selected_alert.get("subject_username") or "UNKNOWN",
    )

    st.write(
        "**Source IP:**",
        selected_alert.get("source_ip") or "UNKNOWN",
    )

    st.write(
        "**Host:**",
        selected_alert.get("host") or "N/A",
    )

    st.write(
        "**First Seen:**",
        selected_alert.get("first_seen", "N/A"),
    )

    st.write(
        "**Last Seen:**",
        selected_alert.get("last_seen", "N/A"),
    )

    st.write(
        "**Successful Login:**",
        selected_alert.get("successful_login", "N/A"),
    )

    st.write(
        "**Logon Type:**",
        selected_alert.get("logon_type") or "N/A",
    )

    st.write(
        "**Process:**",
        selected_alert.get("process_name") or "N/A",
    )

    st.write(
        "**Windows Status:**",
        selected_alert.get("status") or "N/A",
    )

    st.write(
        "**Windows Sub-status:**",
        selected_alert.get("sub_status") or "N/A",
    )

    with st.expander("View complete alert record"):
        st.json(selected_alert)

else:
    st.info("No alerts match the selected search and filters.")


# --------------------------------------------------
# 10. RELOAD REPORTS
# --------------------------------------------------

st.divider()

if st.button("🔄 Reload reports"):
    st.rerun()

st.caption(
    "SentinelX | Local security monitoring and alert investigation"
)
