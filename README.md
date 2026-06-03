# 🛡️ IntelliSecure

<div align="center">
  <h3>AI-Powered Cybersecurity Threat Detection, Analysis, and Incident Response System</h3>
  <p>A comprehensive, end-to-end security platform designed to detect malicious activities, provide explainable AI insights, automatically recommend mitigation strategies, and generate executive reports.</p>
</div>

---

## ✨ Features

- **🔐 Authentication & RBAC**: Secure JWT-based login with bcrypt password hashing and Role-Based Access Control (Admin, Analyst, User).
- **📊 Multi-Source Log Collection**: Collects and correlates Login Logs, Network Logs, File Access Logs, Malware Logs, and USB Device events.
- **⚡ Real-Time Threat Detection**: Continuously monitors logs to detect Brute Force Attacks, Port Scans, Unauthorized Access, and more.
- **🧠 Explainable AI (XAI)**: Demystifies alerts by providing clear, human-readable explanations of threats, root causes, and impacts.
- **🤖 Machine Learning Anomalies**: Uses a trained Isolation Forest model to detect anomalous activities that don't match standard baseline behavior.
- **📈 Security Score Engine**: Computes an aggregate network health score out of 100 based on dynamic, weighted threat penalties.
- **💡 Recommendation Engine**: Automatically prescribes specific, actionable mitigation strategies for active alerts.
- **📡 LAN Monitoring**: Multithreaded ICMP sweeps paired with ARP lookups to map local networks and identify unknown endpoints.
- **📱 Dynamic Dashboard**: A stunning, responsive UI with real-time Plotly charts, dark/light modes, and live metric polling.
- **📄 Automated Reporting**: One-click generation of professional PDF Incident Reports and PPTX Security Summaries.
- **📚 Educational Glossary**: Searchable repository mapping detected threats to MITRE ATT&CK techniques.

---

## 🛠️ Technology Stack

### **Frontend**
- **HTML5 & CSS3**: Custom modern design with Glassmorphism, dynamic glowing elements, and responsive Flexbox/Grid layouts.
- **Vanilla JavaScript**: Pure JS for DOM manipulation, asynchronous API fetches, and SPA (Single Page Application) routing.
- **Charting Libraries**: 
  - **Plotly.js**: For interactive 3D surface charts and complex data visualizations.
  - **Chart.js**: For lightweight, responsive trend lines and radar charts.
- **FontAwesome**: Scalable vector icons for the UI.

### **Backend**
- **Python 3**: Core backend programming language.
- **FastAPI**: High-performance asynchronous web framework for building the RESTful API.
- **SQLAlchemy (SQLite)**: ORM for secure, relational database management.
- **PyJWT & Passlib**: For robust JSON Web Token authentication and password hashing.
- **Scikit-Learn**: Machine Learning library used to train the Isolation Forest anomaly detection model.
- **Pandas**: Used for robust dataset manipulation and training log ingestion.
- **ReportLab & python-pptx**: For generating downloadable PDF and PowerPoint reports.

---

## ⚙️ How It Works (Architecture)

1. **Data Ingestion**: The backend exposes endpoints to ingest logs from multiple vectors (Auth, Network, File Access). Simulated data can be injected using the `inject_data.py` script.
2. **Analysis Pipeline**:
   - **Rule-Based Engine**: Instantly flags known attack signatures (e.g., >5 failed logins = Brute Force).
   - **ML Engine**: Data is fed into the pre-trained Isolation Forest model to catch zero-day anomalies based on deviation from baselines.
3. **Scoring & Mitigation**: The `Security Score Engine` recalculates the system health, while the `Recommendation Engine` maps detected threats to predefined mitigation steps.
4. **Real-Time Presentation**: The vanilla JS frontend polls the `/api/dashboard/metrics` and `/api/realtime/` endpoints, updating the UI dynamically without page reloads.

---

## 🚀 Setup & Installation

Follow these steps to run IntelliSecure locally on your machine.

### 1. Prerequisites
- Python 3.8 or higher installed on your system.
- Git (optional, for cloning).

### 2. Clone the Repository
```bash
git clone https://github.com/yourusername/IntelliSecure.git
cd IntelliSecure
```

### 3. Set up a Virtual Environment
It is highly recommended to use a virtual environment to manage dependencies.
```bash
# Create virtual environment
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on macOS/Linux
source venv/bin/activate
```

### 4. Install Dependencies
Install all required Python packages.
```bash
pip install -r backend/requirements.txt
```

### 5. Train the Machine Learning Model
Before starting the server, train the Isolation Forest model using the provided training dataset.
```bash
python backend/ml/train_model.py
```
*(This will generate a `model.pkl` file inside the `backend/ml/` directory).*

### 6. Start the Backend Server
Start the FastAPI application using Uvicorn.
```bash
cd backend
uvicorn main:app --reload
```
The server will now be running at `http://127.0.0.1:8000`.

### 7. Access the Application
Open your web browser and navigate to:
**[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 📚 API Documentation

IntelliSecure features auto-generated, interactive API documentation provided by FastAPI. 
Once the backend server is running, you can explore and test the API endpoints at:

- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🧪 Simulating Threats

To see the dashboard light up with real-time data, you can run the data injection script in a separate terminal while the server is running:

```bash
# Open a new terminal window, activate the venv, and run:
python inject_data.py
```
This script will simulate Brute Force attacks, Port Scans, Malware Detections, and more, which will immediately reflect on the Live Threat Feed in the dashboard.
