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

## 🤖 Machine Learning Detection & Threat Prevention Pipeline

AgentShieldAI incorporates an **Explainable Deep Learning & Machine Learning Framework** featuring four specialized threat detection models:

| Model | Architecture | Target Threat | Explainable AI (XAI) | Primary Dataset |
| :--- | :--- | :--- | :--- | :--- |
| **Model 1: DistilBERT** | Transformer (6-layer, 768-dim) | Prompt Injection & Jailbreaks | **Integrated Gradients** (Token Attribution) | `3nesdeniz/agentic-prompt-injection-5k` |
| **Model 2: BiLSTM** | 2-Layer Bidirectional LSTM | Multi-Step Action Threat Chains | **Sequence Step Attribution** (Temporal Gradients) | `ethz-spylab/agentdojo` & `AgentInjectionBench` |
| **Model 3: XGBoost** | GBDT (max_depth=4, 100 trees) | Structured Telemetry & RBAC | **TreeSHAP** (Additive Feature Contributions) | AgentDojo traces & AgentInjectionBench |
| **Model 4: Isolation Forest** | 100 Isolation Trees, Subsample 256 | Behavioral Anomaly Baseline | **Z-score Deviation Profiling** from Normal Baseline | Unsupervised benign agent baseline |
| **Multi-Model Fusion** | Calibrated Gated Multi-Layer | Hybrid & Zero-Day Threats | **Multi-Modal Cross-Validation** Consensus | Unified End-to-End Trajectories |

---

### 📊 Benchmark Datasets & Provenance

1. **Dataset 1: `3nesdeniz/agentic-prompt-injection-5k`**
   - **URL**: [https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-5k](https://huggingface.co/datasets/3nesdeniz/agentic-prompt-injection-5k)
   - **License**: CC-BY-4.0
   - **Samples**: 4,935 rows (Train: 3,923, Val: 467, Test: 545). Zero duplicates, zero missing values.
2. **Dataset 2: `ppradyoth/AgentInjectionBench`**
   - **URL**: [https://huggingface.co/datasets/ppradyoth/AgentInjectionBench](https://huggingface.co/datasets/ppradyoth/AgentInjectionBench)
   - **License**: Apache-2.0
   - **Samples**: 182 scenarios (142 unsafe, 40 safe) spanning RAG, MCP context poisoning, and tool output injections.
3. **Dataset 3: `ethz-spylab/agentdojo`**
   - **URL**: [https://github.com/ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo)
   - **License**: MIT
   - **Traces**: 240 model execution traces across `workspace`, `banking`, `slack`, and `travel` suites.

---

### ⚡ Unified Execution Workflow

Run the entire pipeline (dataset inspection, download, preprocessing, training all 4 models, and empirical evaluation) via a single command:

```bash
# Run complete end-to-end pipeline
python scripts/train_all_models.py
```

#### Individual Commands
```bash
# 1. Inspect dataset schemas & licenses
python scripts/inspect_datasets.py

# 2. Download and verify dataset provenance
python scripts/download_datasets.py

# 3. Clean, preprocess, and generate zero-leakage splits
python scripts/prepare_datasets.py

# 4. Train individual models
python scripts/train_distilbert.py --epochs 1 --batch_size 16 --subsample 300
python scripts/train_bilstm.py
python scripts/train_xgboost.py
python scripts/train_isolation_forest.py

# 5. Run comprehensive empirical evaluation
python scripts/evaluate_models.py
```

---

### ☁️ Google Colab Workflow (GPU Training)

For training the full DistilBERT model across all 3,923 prompt examples with GPU acceleration:
1. Open the included notebook: **`AgentShieldAI_Training_Pipeline.ipynb`** in Google Colab.
2. Go to **Runtime &rarr; Change runtime type &rarr; T4 GPU**.
3. Run all cells sequentially. The notebook automates environment setup, dataset download, training of all 4 models, XAI visualizations, and metrics generation.

---

## 📈 Empirical Evaluation Results

| Model | Precision | Recall | F1-Score | False Positive Rate | Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **DistilBERT** (Prompt Injection) | 0.9276 | 0.9607 | 0.9439 | 0.0792 | 124.84 ms |
| *DistilBERT on Held-Out AIB Benchmark* | 0.7877 | 0.9930 | 0.8785 | 0.2250 | 126.10 ms |
| **BiLSTM** (Sequence Actions) | 0.7619 | 0.6957 | 0.7273 | 0.5556 | 1.15 ms |
| **XGBoost** (Structured Telemetry) | 1.0000 | 0.9800 | 0.9899 | 0.0000 | 0.42 ms |
| **Isolation Forest** (Behavioral Baseline) | 0.9652 | 0.7708 | 0.8571 | 0.0784 | 12.40 ms |
| **Combined Multi-Model Fusion** | **1.0000** | **1.0000** | **1.0000** | **0.0000** | **2.51 ms** |

---

## 📄 License
MIT License. Built for enterprise AI agent security.

