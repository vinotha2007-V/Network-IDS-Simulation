
import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

random.seed(42)

RECORD_COUNT = 5000
OUTPUT_FILE = Path("data/network_traffic.csv")

NORMAL_SCENARIOS = [
    "web_browsing",
    "file_transfer",
    "dns_queries",
    "video_streaming",
]

SUSPICIOUS_SCENARIOS = [
    "high_connection_rate",
    "repeated_failed_connections",
    "unusual_packet_volume",
    "repeated_syn_activity",
]


def generate_record(flow_id, start_time):
    suspicious = random.random() < 0.20

    if suspicious:
        scenario = random.choice(SUSPICIOUS_SCENARIOS)
        packet_count = random.randint(300, 1500)
        byte_count = random.randint(100000, 1500000)
        duration = round(random.uniform(0.1, 5.0), 2)
        connection_count = random.randint(40, 200)
        failed_count = random.randint(5, 50)
        syn_count = random.randint(30, 150)
        rst_count = random.randint(5, 60)
        label = "SUSPICIOUS"
    else:
        scenario = random.choice(NORMAL_SCENARIOS)
        packet_count = random.randint(5, 150)
        byte_count = random.randint(500, 80000)
        duration = round(random.uniform(1.0, 120.0), 2)
        connection_count = random.randint(1, 15)
        failed_count = random.randint(0, 2)
        syn_count = random.randint(0, 10)
        rst_count = random.randint(0, 3)
        label = "NORMAL"

    protocols = ["TCP", "UDP", "ICMP"]
    protocol = random.choice(protocols)

    # Reserved documentation IP ranges; no real hosts are targeted.
    source_ip = f"192.0.2.{random.randint(1, 254)}"
    destination_ip = f"198.51.100.{random.randint(1, 254)}"

    source_port = random.randint(1024, 65535)
    destination_port = random.choice(
        [53, 80, 443, 8080, 22, 123]
    )

    timestamp = start_time + timedelta(
        seconds=random.randint(0, 7 * 24 * 60 * 60)
    )

    average_packet_size = round(
        byte_count / max(packet_count, 1), 2
    )

    return {
        "flow_id": flow_id,
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": connection_count,
        "failed_connection_count": failed_count,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "average_packet_size": average_packet_size,
        "label": label,
        "scenario_type": scenario,
    }


def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    start_time = datetime(2026, 1, 1, 0, 0, 0)

    records = [
        generate_record(i + 1, start_time)
        for i in range(RECORD_COUNT)
    ]

    df = pd.DataFrame(records)
    df.to_csv(OUTPUT_FILE, index=False)

    print("Dataset generated successfully!")
    print(f"Total records: {len(df)}")
    print(f"Saved to: {OUTPUT_FILE}")
    print("\nLabel distribution:")
    print(df["label"].value_counts())
    print("\nFirst 5 records:")
    print(df.head().to_string(index=False))


if __name__ == "__main__":
    main()