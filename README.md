# AgentShieldAI — Gemini-Powered AI Agent Security Platform
> **DETECT · EXPLAIN · PREVENT**

**AgentShieldAI** is a production-oriented, full-stack AI Agent Security Platform combining a Google Gemini-inspired conversational assistant experience with an enterprise Central Security Gateway that monitors, detects, explains, and prevents unsafe or unauthorized AI agent actions in real time.

---

## 🛡️ Core Highlights

- **Gemini-Level Conversational Interface**: Responsive streaming assistant, multi-turn context retention, suggested prompts, markdown rendering, syntax highlighting, and conversation history.
- **Central Security Gateway (The Core Feature)**: Every tool proposal passes through centralized server-side inspection *before* any execution occurs.
- **Strict 10 Lifecycle States**: Deterministically tracks each operation through `OBSERVED`, `SUSPICIOUS`, `DETECTED`, `BLOCKED`, `PENDING_APPROVAL`, `MITIGATION_IN_PROGRESS`, `PREVENTION_VERIFIED`, `VERIFICATION_FAILED`, `TASK_COMPLETED`, and `TASK_FAILED`.
- **4 Operational AI Agents**:
  1. **Research Agent**: Web search & source extraction with indirect prompt injection scanning.
  2. **File Agent**: Document QA, text extraction (PDF, TXT, CSV, MD) with path traversal & ownership enforcement.
  3. **Data Analysis Agent**: Tabular dataset schema inspection, statistics, bounded computation.
  4. **Mail Agent**: Communication drafting with human-in-the-loop approval gating for outbound transmission.
- **Zero Fabricated Telemetry**: Every metric card, chart, incident alert, and activity log originates from live database aggregates.
- **Real-Time Monitoring**: Live WebSocket event streaming for instant alert popups and human approval notices.

---

## 🏛️ Architecture & Processing Flow

```
[ User Browser / React Frontend ]
           │
           ▼
[ FastAPI Backend / Routing & Auth ]
           │
           ├── (1) Evaluates Input Prompt for Direct Injection
           │
           ├── (2) Sends Context to Google Gemini Model (streaming)
           │
           ▼
[ Model Proposes Tool Call ] ──────────┐
                                       ▼
                    [ CENTRAL SECURITY GATEWAY ]
                                       │
     ┌─────────────────────────────────┴─────────────────────────────────┐
     │                                                                   │
     ▼                                 ▼                                 ▼
[ Threat / Policy Match ]    [ Sensitive Operation ]            [ Verification Passed ]
     │                                 │                                 │
     ├── Lifecycle: BLOCKED            ├── Lifecycle: PENDING_APPROVAL   ├── Lifecycle: COMPLETED
     ├── PREVENTION_VERIFIED           ├── Wait for Human Approval       ├── Execute in Sandbox
     └── Record Alert in DB            └── Operator Decides & Audits     └── Return Truthful Output
```

---

## 🛠️ Technology Stack

### Frontend
- **React 19** with **TypeScript** & **Vite**
- **Tailwind CSS v4** (Modern cybersecurity dark mode)
- **React Router v7** (Persistent application shell)
- **Lucide React** (State-of-the-art icon system)
- **Recharts** (Real database metric visualizations)
- **React Markdown** & **Remark GFM** (Rich text & table rendering)
- **Server-Sent Events (SSE)** & **WebSockets** (Real-time telemetry)

### Backend
- **Python 3.9+ / 3.11** with **FastAPI**
- **Official Google Gen AI SDK** (`google-generativeai` / `google-genai`)
- **SQLAlchemy 2.0** & **Alembic** (Database schema migrations)
- **PostgreSQL** (Production database with SQLite local fallback)
- **Pydantic v2** & **Pydantic Settings** (Strict schema validation)
- **Passlib & Bcrypt** (Secure credential hashing with JWT authentication)
- **Pandas & PyPDF** (Tabular analysis & PDF text extraction)

---

## 🚀 Quickstart (Local Development)

### Prerequisites
- Python 3.9 or higher
- Node.js 18+ and npm

### 1. Clone & Set Up Backend

```bash
# Navigate to project root
cd ShieldAI

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
# source .venv/bin/activate

# Install backend dependencies
pip install -r backend/requirements.txt

# Create local environment file
cp .env.example .env
```

Edit `.env` to configure your Gemini API key (optional for local testing; platform functions with complete security enforcement even if unconfigured):
```env
GEMINI_API_KEY=your_google_ai_studio_api_key
GEMINI_MODEL=gemini-1.5-flash
```

### 2. Initialize Database & Seed Default Records

```bash
python -c "import sys; sys.path.insert(0, 'backend'); from app.database.session import Base, engine, SessionLocal; from app.database.seed import seed_database; Base.metadata.create_all(bind=engine); seed_database(SessionLocal()); print('Database ready!')"
```

### 3. Run Backend Server

```bash
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

The backend API and Swagger documentation will be live at:
- API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- Health Check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

### 4. Run Frontend

In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```

Open your browser at: **`http://localhost:5173`**

### Instant Demo Accounts
For frictionless evaluation, click the quick-login buttons on the sign-in screen:
- **Admin**: `admin@agentshield.ai` / `Admin@123456`
- **SOC Analyst**: `analyst@agentshield.ai` / `Analyst@123456`

---

## 🐳 Docker Deployment

A full production stack with PostgreSQL 16, FastAPI backend, and Nginx-powered React frontend is ready via Docker Compose:

```bash
# Build and run containers
docker-compose up --build -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

Services will be exposed on:
- Frontend: `http://localhost:5173` or `http://localhost:80`
- Backend API: `http://localhost:8000`
- PostgreSQL: `localhost:5432`

> 📘 For cloud hosting on **Vercel, Render, Railway, AWS EC2, or Linux Bare-Metal**, see the comprehensive **[Production Deployment & Hosting Guide](file:///c:/Users/Q/Desktop/M.Tech/ShieldAI/DEPLOYMENT.md)**.


---

## 🧪 Automated Testing

AgentShieldAI includes comprehensive test suites covering security policies, lifecycle state transitions, unauthorized tool detection, and full API integration:

```bash
# Run backend pytest suite
.\.venv\Scripts\pytest backend\tests -v

# Run end-to-end platform verification script
.\.venv\Scripts\python scripts\verify_platform.py

# Verify frontend build
cd frontend && npm run build
```

---

## 🔒 Security Threat Coverage

| Threat Category | Enforcement Mechanism | Lifecycle Outcome |
| :--- | :--- | :--- |
| **Direct Prompt Injection** | Deterministic heuristic & regex boundary inspection | `DETECTED` &rarr; `BLOCKED` &rarr; `PREVENTION_VERIFIED` |
| **Indirect Prompt Injection** | Real-time payload sanitization on external HTML/PDFs | `SUSPICIOUS` &rarr; Content Redacted & Logged |
| **Unauthorized Tool Invocation** | Agent RBAC whitelist verification | `BLOCKED` &rarr; `PREVENTION_VERIFIED` |
| **Cross-User File Access** | Strict tenant ownership check (`UploadedFile.user_id`) | `BLOCKED` &rarr; Access Denied Alert |
| **Path Traversal Attacks** | Strict file path validation (`../`, `%2e%2e`, system dirs) | `BLOCKED` &rarr; `PREVENTION_VERIFIED` |
| **Sensitive Data / PII Leakage** | Regex detection for credit cards, SSNs, API keys | `BLOCKED` &rarr; Data Exfiltration Prevented |
| **Unapproved Email Dispatch** | Human-in-the-loop authorization engine | `PENDING_APPROVAL` &rarr; Operator Decision |

---

## 📄 License
MIT License. Built for enterprise AI agent security.
