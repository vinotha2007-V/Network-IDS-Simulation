
from pathlib import Path
import sqlite3

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = BASE_DIR / "data" / "anomaly_results.csv"
DB_FILE = BASE_DIR / "data" / "ids.db"

app = FastAPI(
    title="Network IDS Simulation API",
    description="Defensive IDS demo using synthetic network traffic.",
    version="1.0.0",
)

# CORS configuration for the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_connection():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                label TEXT,
                anomaly_score REAL,
                risk_score REAL,
                severity TEXT,
                scenario_type TEXT,
                status TEXT DEFAULT 'OPEN',
                analyst_note TEXT DEFAULT ''
            )
        """)


def import_results():
    if not DATA_FILE.exists():
        return

    df = pd.read_csv(DATA_FILE)

    with get_connection() as connection:
        connection.execute("DELETE FROM alerts")

        for _, row in df.iterrows():
            connection.execute("""
                INSERT INTO alerts (
                    flow_id, timestamp, source_ip, destination_ip,
                    protocol, label, anomaly_score, risk_score,
                    severity, scenario_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                int(row["flow_id"]),
                str(row["timestamp"]),
                str(row["source_ip"]),
                str(row["destination_ip"]),
                str(row["protocol"]),
                str(row["label"]),
                float(row["anomaly_score"]),
                float(row["risk_score"]),
                str(row["severity"]),
                str(row["scenario_type"]),
            ))


initialize_database()


@app.get("/")
def home():
    return {
        "message": "Network IDS Simulation API is running",
        "docs": "/docs",
    }


@app.post("/import-results")
def import_alerts():
    if not DATA_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="Run the anomaly detector first."
        )

    import_results()

    with get_connection() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

    return {
        "message": "Results imported",
        "records_imported": count
    }


@app.get("/alerts")
def list_alerts(
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=5000),
):
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())

    if status:
        query += " AND status = ?"
        params.append(status.upper())

    query += " ORDER BY risk_score DESC LIMIT ?"
    params.append(limit)

    with get_connection() as connection:
        rows = connection.execute(query, params).fetchall()

    return {
        "count": len(rows),
        "alerts": [dict(row) for row in rows]
    }


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,)
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return dict(row)


@app.patch("/alerts/{alert_id}/status")
def update_status(alert_id: int, status: str):
    allowed_statuses = {"OPEN", "INVESTIGATING", "RESOLVED"}

    if status.upper() not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Status must be OPEN, INVESTIGATING, or RESOLVED."
        )

    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (status.upper(), alert_id),
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

    return {
        "message": "Status updated",
        "status": status.upper()
    }


@app.patch("/alerts/{alert_id}/note")
def update_note(alert_id: int, note: str):
    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE alerts SET analyst_note = ? WHERE id = ?",
            (note, alert_id),
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404,
                detail="Alert not found"
            )

    return {"message": "Analyst note saved"}


@app.get("/analytics")
def analytics():
    with get_connection() as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        severity_rows = connection.execute("""
            SELECT severity, COUNT(*) AS count
            FROM alerts
            GROUP BY severity
        """).fetchall()

        status_rows = connection.execute("""
            SELECT status, COUNT(*) AS count
            FROM alerts
            GROUP BY status
        """).fetchall()

        suspicious = connection.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE label = 'SUSPICIOUS'
        """).fetchone()[0]

    return {
        "total_records": total,
        "suspicious_records": suspicious,
        "severity_distribution": {
            row["severity"]: row["count"]
            for row in severity_rows
        },
        "status_distribution": {
            row["status"]: row["count"]
            for row in status_rows
        },
    }