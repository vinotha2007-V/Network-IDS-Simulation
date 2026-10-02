# 🛡️ Network IDS Simulation

A **Network Intrusion Detection System (IDS) Simulation** built using Python, FastAPI, and React to simulate network traffic, detect suspicious activities, and visualize security alerts through an interactive dashboard.

## 📌 Project Overview

Network IDS Simulation is a cybersecurity project designed to demonstrate how network traffic can be monitored and analyzed to identify potentially suspicious activities. It combines simulated network traffic, signature-based detection, anomaly detection, and a web-based dashboard to display detection results.

## ✨ Key Features

* 📡 **Network Traffic Simulation** – Generate synthetic network traffic for analysis.
* 🔍 **Signature-Based Detection** – Identify traffic matching predefined suspicious activity patterns.
* 🤖 **Anomaly Detection** – Detect unusual traffic patterns using an anomaly detection module.
* 🚨 **Security Alerts** – View detected suspicious activities and their severity.
* 📊 **Interactive Dashboard** – Visualize network traffic and detection results.
* ⚡ **REST API** – Access detection data through a FastAPI backend.
* 💾 **Data Storage** – Store and analyze traffic records and detection results.
* 📈 **Severity Classification** – Organize alerts by severity levels.

## 🛠️ Technologies Used

| Technology            | Purpose                                |
| --------------------- | -------------------------------------- |
| Python                | Backend logic and detection modules    |
| FastAPI               | REST API development                   |
| React                 | Interactive frontend dashboard         |
| Vite                  | Frontend development and build tooling |
| Pandas                | Traffic data processing                |
| SQLite                | Local database storage                 |
| HTML, CSS, JavaScript | User interface development             |
| Git & GitHub          | Version control and project hosting    |

## 🏗️ Project Structure

```text
Network-IDS-Simulation/
├── backend/
│   └── main.py
├── data/
│   ├── network_traffic.csv
│   ├── anomaly_results.csv
│   ├── signature_alerts.csv
│   └── ids.db
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── ids/
│   ├── anomaly_detector.py
│   └── signature_detector.py
├── simulator/
│   └── generate_data.py
├── tests/
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## ⚙️ Installation and Setup

### Prerequisites

* Python 3.10 or later
* Node.js and npm
* Git

### 1. Clone the Repository

```bash
git clone https://github.com/vinotha2007-V/Network-IDS-Simulation.git
cd Network-IDS-Simulation
```

### 2. Set Up the Python Environment

```bash
python -m venv .venv
```

Activate the environment on Windows:

```cmd
.venv\Scripts\activate
```

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

### 3. Start the Backend

From the project root directory, run:

```bash
uvicorn backend.main:app --reload
```

Backend API:

`http://127.0.0.1:8000`

FastAPI interactive documentation:

`http://127.0.0.1:8000/docs`

### 4. Start the Frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local URL displayed by Vite, usually:

`http://localhost:5173`

## 🔬 Detection Modules

### Signature-Based Detection

Uses predefined patterns or rules to identify traffic that matches known suspicious activity.

### Anomaly Detection

Analyzes simulated traffic to identify unusual patterns that may require further investigation.

### Security Dashboard

Presents detection results and alert information through a web-based interface.

## 📊 Sample Data

The `data/` directory contains sample traffic records, anomaly detection results, signature alerts, and a local SQLite database.

**Note:** The project uses simulated or sample data for educational purposes. Detection results are not proof of an actual cyberattack.

## 🎯 Project Objectives

* Understand the fundamentals of Network Intrusion Detection Systems.
* Learn signature-based and anomaly-based detection concepts.
* Develop REST APIs using FastAPI.
* Build an interactive security dashboard using React.
* Practice network data analysis and local database integration.
* Understand how detection results can be visualized for security monitoring.

## 🔐 Security and Ethical Use

This project is intended for educational and defensive cybersecurity learning. It uses simulated or sample traffic and is not a replacement for a production-grade IDS.

* Use only authorized data and systems.
* Do not upload passwords, API keys, or other secrets.
* Keep virtual environments and cache files out of version control.
* Validate detection results before taking security actions.

## 🚀 Future Enhancements

* Live traffic ingestion from authorized sources.
* Advanced machine-learning-based anomaly detection.
* Real-time alert notifications.
* Downloadable security reports.
* Role-based access control.
* Cloud deployment and centralized monitoring.

## 👩‍💻 Author

**Vinotha**

GitHub: [vinotha2007-V](https://github.com/vinotha2007-V)

## 📄 License

This project is intended for educational and demonstration purposes. Add a license file if you want to specify terms for reuse and distribution.
