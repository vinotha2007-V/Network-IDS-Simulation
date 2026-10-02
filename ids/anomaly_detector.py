
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = [
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
]


def detect_anomalies(csv_path="data/network_traffic.csv"):
    df = pd.read_csv(csv_path)

    # Learn normal-looking patterns from the synthetic feature data.
    scaler = StandardScaler()
    X = scaler.fit_transform(df[FEATURES])

    detector = IsolationForest(
        n_estimators=100,
        contamination=0.20,
        random_state=42,
    )

    predictions = detector.fit_predict(X)
    df["anomaly"] = predictions == -1

    # Normalize anomaly scores into a 0–100 range.
    raw_scores = -detector.score_samples(X)
    min_score = raw_scores.min()
    max_score = raw_scores.max()

    if max_score == min_score:
        df["anomaly_score"] = 0.0
    else:
        df["anomaly_score"] = (
            (raw_scores - min_score) /
            (max_score - min_score) * 100
        ).round(2)

    # Combine anomaly score with signature-rule matches.
    signature_alerts = pd.read_csv("data/signature_alerts.csv")
    matched_flows = set(signature_alerts["flow_id"].astype(int))

    df["signature_match"] = df["flow_id"].isin(matched_flows)

    df["risk_score"] = (
        0.6 * df["anomaly_score"]
        + 40 * df["signature_match"].astype(int)
    ).clip(0, 100).round(2)

    def get_severity(score):
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "INFO"

    df["severity"] = df["risk_score"].apply(get_severity)

    output_file = "data/anomaly_results.csv"
    df.to_csv(output_file, index=False)

    print("Anomaly detection completed!")
    print(f"Records analyzed: {len(df)}")
    print(f"Anomalies detected: {int(df['anomaly'].sum())}")
    print(f"Signature-matched flows: {int(df['signature_match'].sum())}")
    print("\nSeverity distribution:")
    print(df["severity"].value_counts())
    print(f"\nResults saved to {output_file}")

    return df


if __name__ == "__main__":
    detect_anomalies()