# AI DevOps Copilot - Backend API Server

The backend of the **AI DevOps Copilot** platform is a production-grade FastAPI application built to handle high-performance telemetry tracking, automated SRE log analysis, incident tracking, cost optimizations, and AI-driven troubleshooting recommendations.

---

## 🛠️ Tech Stack & Features

- **Framework**: FastAPI (Python 3.12)
- **Database**: SQLite (local) / PostgreSQL-ready via SQLAlchemy ORM
- **Authentication**: Stateful JWT Bearer Token validation using `python-jose` and password hashing with `bcrypt`
- **Telemetry & Metrics**: Instrumented with `prometheus-client` to expose `/metrics` for scraper systems
- **AI Engine**: Gemini API (`gemini-2.5-flash`) integration with robust rules-engine fallback mechanism for offline compatibility

---

## 📂 Project Structure

```text
backend/
├── app/
│   ├── api/
│   │   └── routers/      # Endpoint routes (/auth, /logs, /incidents, /alerts, /recommendations, /metrics, /chat)
│   ├── core/             # DB settings, security helper functions, config initialization
│   ├── models/           # SQLAlchemy database schemas
│   ├── schemas/          # Pydantic data validation & serialization schemas
│   ├── services/         # Gemini AI interface & prompt correlation service
│   └── main.py           # FastAPI entrypoint, database creator, and seeder
├── tests/                # Unit test suites (Pytest)
├── Dockerfile            # Container deployment image
├── requirements.txt      # Dependency specification
└── devops_copilot.db     # SQLite Database (seeded automatically on startup)
```

---

## 🚀 Setup & Local Execution

### 1. Prerequisites
- Python 3.12+
- Gemini API Key (optional; automatically falls back to offline rules mode if empty)

### 2. Install Dependencies
Create a virtual environment and install the required modules:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Configuration
Copy or create a `.env` file in the `backend/` directory:
```env
SECRET_KEY=super-secret-key-for-ai-devops-copilot-1234567890
DATABASE_URL=sqlite:///./devops_copilot.db
GEMINI_API_KEY=your_gemini_api_key_here
```

### 4. Running the Dev Server
Run the Uvicorn application:
```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```
- **API Base URL**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **Prometheus Metrics Endpoints**: `http://localhost:8000/metrics`

---

## 🧪 Testing and Linting

The backend is fully instrumented with standard unit testing and formatting tools to ensure high code quality.

### 1. Run Unit Tests (Pytest)
```powershell
python -m pytest
```

### 2. Linting (Flake8)
Ensure there are no critical syntax errors or style deviations:
```powershell
flake8 app --count --select=E9,F63,F7,F82 --show-source --statistics
```

### 3. Formatting (Black)
The python codebase is fully formatted to PEP 8 standards with Black:
```powershell
black --check app --line-length=100
```
*(To auto-format files, run `black app --line-length=100`)*
