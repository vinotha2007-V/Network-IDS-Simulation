
import pandas as pd


def detect_signature(row):
    """Apply simple defensive rules to synthetic network traffic."""

    alerts = []

    if row["connection_count"] >= 40:
        alerts.append({
            "rule_id": "IDS001",
            "alert_type": "HIGH_CONNECTION_RATE",
            "severity": "HIGH",
            "reason": "Unusually high connection count"
        })

    if row["failed_connection_count"] >= 10:
        alerts.append({
            "rule_id": "IDS002",
            "alert_type": "REPEATED_FAILED_CONNECTIONS",
            "severity": "MEDIUM",
            "reason": "Many failed connections in one flow"
        })

    if row["syn_count"] >= 30:
        alerts.append({
            "rule_id": "IDS003",
            "alert_type": "HIGH_SYN_ACTIVITY",
            "severity": "HIGH",
            "reason": "Unusually high SYN activity"
        })

    if row["byte_count"] >= 500000:
        alerts.append({
            "rule_id": "IDS004",
            "alert_type": "UNUSUAL_BYTE_VOLUME",
            "severity": "MEDIUM",
            "reason": "Unusually high byte volume"
        })

    if row["rst_count"] >= 30:
        alerts.append({
            "rule_id": "IDS005",
            "alert_type": "HIGH_RESET_ACTIVITY",
            "severity": "MEDIUM",
            "reason": "Unusually high TCP reset count"
        })

    return alerts


def analyze_dataset(csv_path="data/network_traffic.csv"):
    df = pd.read_csv(csv_path)
    all_alerts = []

    for _, row in df.iterrows():
        detected = detect_signature(row)

        for alert in detected:
            all_alerts.append({
                "flow_id": int(row["flow_id"]),
                "timestamp": row["timestamp"],
                "source_ip": row["source_ip"],
                "destination_ip": row["destination_ip"],
                **alert
            })

    alerts_df = pd.DataFrame(all_alerts)

    if alerts_df.empty:
        print("No rule matches found.")
        return alerts_df

    print("Signature detection completed!")
    print(f"Records analyzed: {len(df)}")
    print(f"Alerts generated: {len(alerts_df)}")
    print("\nAlert types:")
    print(alerts_df["alert_type"].value_counts())
    print("\nSample alerts:")
    print(alerts_df.head(10).to_string(index=False))

    return alerts_df


if __name__ == "__main__":
    alerts = analyze_dataset()
    if not alerts.empty:
        alerts.to_csv("data/signature_alerts.csv", index=False)
        print("\nAlerts saved to data/signature_alerts.csv")