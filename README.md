## INSIGHTGUARD - AI POWERED CYBERSECURITY SAAS PLATFORM

InsightGuard is a cybersecurity SaaS platform that combines Data Science, Machine Learning, Threat Intelligence, and Generative AI to automate security log analysis.
Users can upload system, firewall, or application logs and InsightGuard instantly:
- Extracts and summarizes key events<br>
- Detects anomalies using ML models<br>
- Performs threat intelligence on suspicious IPs/domains<br>
- Provides explanations and remediation advice through an AI security assistant<br>

The platform simplifies complex cybersecurity workflows and empowers even non-experts to understand system threats using an intuitive dashboard and chatbot interface.

## Project Structure

```
insightguard/
├── run.py                 # 🚀 Replit startup script (runs the FastAPI app)
├── app/                   # 📁 Main application directory
│   ├── main.py           # 🔧 FastAPI application & routes
│   ├── api/              # 🌐 API endpoints
│   │   ├── logs.py       # 📊 Log upload & retrieval
│   │   └── incidents.py  # 🚨 Incident management
│   ├── models/           # 📋 Data models
│   │   ├── model.py      # 🗄️ SQLAlchemy database models
│   │   └── event.py      # 📝 Pydantic event schemas
│   ├── detection/        # 🧠 ML & rule-based detection
│   │   └── rules.py      # ⚡ Anomaly detection engine
│   ├── ingestion/        # 📥 Log parsing & processing
│   │   ├── parser.py     # 🔍 Multi-format log parser
│   │   └── normalizer.py # 🧹 Data normalization
│   ├── services/         # 🔧 Business logic services
│   ├── storage/          # 💾 Database configuration
│   │   └── database.py   # 🗃️ SQLAlchemy setup
│   └── Frontend/         # 🎨 Static web files
│       └── index.html    # 🌐 Dashboard UI
├── requirements.txt      # 📦 Python dependencies
└── README.md            # 📖 This file
```

## Quick Start

### For Replit Deployment:
1. The `run.py` script automatically starts the FastAPI server
2. Frontend is served at `/dashboard`
3. API endpoints are available at `/logs`, `/logs/upload`, etc.

### For Local Development:
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```
