# IntelliSecure

AI-Powered Cybersecurity Threat Detection, Analysis, and Incident Response System

IntelliSecure is a comprehensive, end-to-end security platform designed to detect malicious activities, provide explainable AI insights, automatically recommend mitigation strategies, and generate executive reports.

## Features overview

- **Authentication & RBAC**: Secure JWT-based login with bcrypt password hashing and Role-Based Access Control (Admin, Analyst, User).
- **Multi-Source Log Collection**: Collects and correlates Login Logs, Network Logs, File Access Logs, Malware Logs, and USB Device events.
- **Real-Time Threat Detection**: Continuously monitors logs to detect Brute Force Attacks, Port Scans, Unauthorized Access, and more.
- **Explainable AI (XAI)**: Demystifies alerts by providing clear, human-readable explanations of threats, reasons, and impacts.
- **Machine Learning**: Uses a trained Isolation Forest model to detect anomalous activities that don't match standard baseline behavior.
- **Security Score Engine**: Computes an aggregate network health score out of 100 based on dynamic, weighted threat penalties.
- **Recommendation Engine**: Automatically prescribes specific, actionable mitigation strategies for active alerts.
- **LAN Monitoring**: Multithreaded ICMP sweeps paired with ARP lookups to map local networks and identify unknown endpoints.
- **Dashboard API Integration**: Exposes real-time bundled metrics (`/api/dashboard/metrics`) tailored for interactive Plotly charts.
- **Automated Reporting**: One-click generation of professional PDF Incident Reports and PPTX Security Summaries.
- **Educational Glossary**: Searchable repository mapping detected threats to MITRE ATT&CK techniques.

## Installation

1. **Clone the Repository** and navigate to the root directory.
2. **Set up a Virtual Environment**:
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Linux/Mac
   source venv/bin/activate
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r backend/requirements.txt
   ```
4. **Train the ML Model** (Initial Setup):
   ```bash
   python backend/ml/train_model.py
   ```

## Running the System

Start the backend FastAPI server:
```bash
cd backend
uvicorn main:app --reload
```
The server will start at `http://127.0.0.1:8000`.

## API Documentation

IntelliSecure is built on FastAPI, meaning interactive API documentation is automatically generated.
Once the server is running, you can access the docs at:
- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

## Development Roadmap

- **Phase 1**: Project Audit (Completed)
- **Phase 2**: Authentication System (Completed)
- **Phase 3**: Login Logging System (Completed)
- **Phase 4**: Multi-Source Log Collection (Completed)
- **Phase 5**: Real-Time Threat Monitoring (Completed)
- **Phase 6**: Threat Detection Engine (Completed)
- **Phase 7**: Explainable AI Module (Completed)
- **Phase 8**: Security Score Engine (Completed)
- **Phase 9**: Recommendation Engine (Completed)
- **Phase 10**: Machine Learning Module (Completed)
- **Phase 11**: LAN Monitoring (Completed)
- **Phase 12**: Dashboard Integration (Completed)
- **Phase 13**: Automated Reporting (Completed)
- **Phase 14**: Educational Module (Completed)
- **Phase 15**: Testing (Completed)
- **Phase 16**: Final Documentation (Completed)
