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
├── start.py              # 🚀 Local development startup script
├── app/                  # 📁 Main application directory
│   ├── main.py          # 🔧 FastAPI application & routes
│   ├── api/             # 🌐 API endpoints
│   │   ├── logs.py      # 📊 Log upload & retrieval
│   │   └── incidents.py # 🚨 Incident management
│   ├── models/          # 📋 Data models
│   │   ├── model.py     # 🗄️ SQLAlchemy database models
│   │   └── event.py     # 📝 Pydantic event schemas
│   ├── detection/       # 🧠 ML & rule-based detection
│   │   └── rules.py     # ⚡ Anomaly detection engine
│   ├── ingestion/       # 📥 Log parsing & processing
│   │   ├── parser.py    # 🔍 Multi-format log parser
│   │   └── normalizer.py# 🧹 Data normalization
│   ├── services/        # 🔧 Business logic services
│   ├── storage/         # 💾 Database configuration
│   │   └── database.py  # 🗃️ SQLAlchemy setup
│   └── Frontend/        # 🎨 Static web files
│       └── index.html   # 🌐 Dashboard UI
├── requirements.txt     # 📦 Python dependencies
└── README.md           # 📖 This file
```

## Quick Start

### Local Development Setup:

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up PostgreSQL Database:**
   - Make sure PostgreSQL is running locally
   - Create database: `InsightGuard`
   - Update connection string in `app/storage/database.py` if needed

3. **Run the Application:**
   ```bash
   uvicorn app.main:app --reload
   ```

4. **Access the Application:**
   - **API**: http://127.0.0.1:8000
   - **Dashboard**: http://127.0.0.1:8000/dashboard
   - **Health Check**: http://127.0.0.1:8000

### Features:
- Upload log files (.log, .txt, .csv)
- Real-time threat analysis and anomaly detection
- Interactive dashboard with charts and metrics
- AI-powered security assistant chat
- Threat intelligence correlation
