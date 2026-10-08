# AI-Powered Security Intelligence Platform

> **Protect what you type. Secure what you ship. Fix what's broken.**

Guardion is a full-stack cybersecurity SaaS platform that protects developers across three critical surfaces:

1. **AI Prompt Security** — Intercepts and scans prompts sent to ChatGPT, Claude & Gemini for leaked secrets, PII, and prompt injection attacks
2. **Repository Vulnerability Scanning** — Scans GitHub repos for vulnerable dependencies via OSV/NVD databases with AI-powered remediation
3. **Static Code Analysis** — Detects hardcoded credentials, command injection, SQL injection, weak cryptography, and more — with AI-powered fix suggestions

Built with **FastAPI**, **React 18**, **MongoDB Atlas**, **Google Gemini AI**, a custom **ML classifier**, and a **Chrome Extension**.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **3-Stage Prompt Analysis** | Regex (17 patterns) → Custom ML model → Gemini AI contextual analysis |
| **Chrome Extension** | Manifest V3 — intercepts prompts in real-time on ChatGPT, Claude & Gemini |
| **Repo Vulnerability Scanner** | Clones repos, parses dependencies, queries OSV API, enriches with NVD CVSS scores |
| **Static Code Analyzer** | 8 vulnerability categories with security scoring (0–100) |
| **AI Fix Code** | Gemini generates production-ready fixes for vulnerable code — copyable & exportable |
| **Security Pipeline** | Unified 3-stage flow: Repo Scanner → Static Analyzer → AI Fix Suggestion |
| **OWASP Top 10 Mapping** | Vulnerabilities auto-classified into OWASP 2021 categories |
| **ML Model Comparison** | Side-by-side local ML vs Gemini AI classification with confidence scores |
| **Multi-User SaaS** | JWT authentication, bcrypt password hashing, role-based access (user/admin) |
| **Admin Dashboard** | Platform-wide analytics: all users, scan logs, prompt logs, system stats |
| **Economy Mode** | LRU cache (500 entries, 1h TTL), rate limiter (10 RPM), fallback model chain |
| **Advanced Analytics** | 4-panel dashboard: donut chart, gradient bars, score trend area chart, security posture gauge |

---

## 🏗️ Architecture

```
┌──────────────────────────┐       ┌──────────────────────────────────────┐
│   Chrome Extension       │──────▶│   FastAPI Backend (Python)           │
│   (Manifest V3)          │       │                                      │
│   Intercepts prompts on: │       │  ┌──────────────────────────────┐    │
│   • ChatGPT              │       │  │ Prompt Analyzer              │    │
│   • Claude               │       │  │  • 17 regex patterns         │    │
│   • Gemini               │       │  │  • ML classifier (MiniLM)    │    │
│                          │       │  │  • Gemini AI analysis        │    │
└──────────────────────────┘       │  ├──────────────────────────────┤    │
                                   │  │ Repo Scanner                 │    │──▶ OSV API
┌──────────────────────────┐       │  │  • Dependency parser         │    │──▶ NVD API
│   React Dashboard        │──────▶│  │  • CVE lookup & enrichment   │    │──▶ Gemini API
│   (Vite + Tailwind CSS)  │       │  ├──────────────────────────────┤    │
│   • Security metrics     │       │  │ Static Code Analyzer         │    │
│   • Prompt tester        │       │  │  • 8 vuln categories         │    │
│   • Security pipeline    │       │  │  • Security scoring 0–100    │    │
│   • 4-panel analytics    │       │  ├──────────────────────────────┤    │
│   • Admin panel          │       │  │ AI Fix Code (Gemini)         │    │
└──────────────────────────┘       │  │  • Context-aware fixes       │    │
                                   │  │  • Copy & export             │    │
                                   │  ├──────────────────────────────┤    │
                                   │  │ Auth (JWT + bcrypt)          │    │
                                   │  │  • User / Admin roles        │    │
                                   │  └──────────────────────────────┘    │
                                   │          MongoDB Atlas               │
                                   └──────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+**
- **Node.js 18+**
- **MongoDB Atlas** account (or local MongoDB)
- **Google Gemini API Key** — [Get one free](https://aistudio.google.com/apikey)

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # Fill in your API keys
python -m app.main
```

API runs at **http://localhost:8000** — Swagger docs at **http://localhost:8000/docs**

### 2. Frontend Dashboard

```bash
cd frontend
npm install
npm run dev
```

Dashboard opens at **http://localhost:5173**

### 3. Chrome Extension

1. Open `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select the `extension/` folder
4. Visit ChatGPT / Claude / Gemini — Guardion is now active

### 4. ML Model Training (Optional)

```bash
cd backend
python -m guardion_ai_model.dataset_generator   # Generate ~500 labeled prompts
python -m guardion_ai_model.train_model          # Train classifier
```

---

## ⚙️ Environment Variables

Create `backend/.env`:

```env
GEMINI_API_KEY=your_gemini_api_key_here
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net
MONGO_DB_NAME=guardion
JWT_SECRET=your_jwt_secret_here
NVD_API_KEY=your_nvd_api_key_here          # Optional — enriches CVE data
HOST=0.0.0.0
PORT=8000
CORS_ORIGINS=http://localhost:3000,http://localhost:5173,chrome-extension://*
GEMINI_MODEL=gemini-2.5-flash-lite         # Default model
ECONOMY_MODE=true                          # Quota-safe mode
GEMINI_RPM_LIMIT=10                        # Rate limit
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=1440
```

---

## 📡 API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/signup` | Register a new user |
| `POST` | `/auth/login` | Login & receive JWT |
| `GET` | `/auth/me` | Get current user profile |

### Core Security

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze_prompt` | Analyze prompt for sensitive data & injection attacks |
| `POST` | `/api/ml_compare` | Side-by-side ML vs Gemini classification |
| `GET` | `/api/quota_status` | Check Gemini API quota |
| `POST` | `/api/scan_repo` | Scan GitHub repo for vulnerable dependencies |
| `POST` | `/api/remediate` | AI-powered fix for a specific CVE |
| `GET` | `/api/owasp_trending` | OWASP Top 10 trending categories |
| `POST` | `/api/scan_code` | Static code analysis (paste or file upload) |
| `POST` | `/api/fix_code` | AI-generated code fix via Gemini |
| `GET` | `/api/dashboard` | User-scoped metrics & recent activity |

### Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/users` | All registered users |
| `GET` | `/admin/stats` | Platform-wide statistics |
| `GET` | `/admin/prompt_logs` | All prompt analysis logs |
| `GET` | `/admin/repo_scans` | All repository scan logs |
| `GET` | `/admin/code_scans` | All code scan logs |

### Example: Analyze a Prompt

```bash
curl -X POST http://localhost:8000/api/analyze_prompt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"prompt": "My API key is sk-abc123def456ghi789jkl012mno345"}'
```

```json
{
  "risk_score": 0.9,
  "decision": "block",
  "detected_categories": ["api_key"],
  "sanitized_prompt": "My API key is [REDACTED_API_KEY]",
  "reason": "API key detected in prompt"
}
```

---

## 🔍 Detection Engine

### Three-Stage Prompt Analysis

```
User Prompt
     │
     ▼
┌─────────────────────┐
│  Stage 1: Regex     │  17 pattern categories — fast, deterministic
│  (0.3ms avg)        │  Catches known secret formats
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Stage 2: ML Model  │  all-MiniLM-L6-v2 embeddings → Logistic Regression
│  (sentence-transformers) │  5 categories: safe, pii, credential, financial, secret
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Stage 3: Gemini AI │  Context-aware analysis (gemini-2.5-flash)
│  (with caching)     │  Catches obfuscated/novel leaks & prompt injection
└─────────┬───────────┘
          │
          ▼
┌─────────────────────┐
│  Merge Results      │  Stricter decision wins
│  • max(risk_score)  │  Categories unioned
│  • union(categories)│  Gemini reason included
└─────────────────────┘
```

### Risk Scoring

| Score Range | Decision | Meaning |
|-------------|----------|---------|
| 0.00 – 0.29 | ✅ **ALLOW** | No sensitive data or threats detected |
| 0.30 – 0.69 | ⚠️ **WARN** | Possibly sensitive, needs review |
| 0.70 – 1.00 | 🚫 **BLOCK** | Contains secrets, credentials, or attack patterns |

### Detection Categories

**Sensitive Data (14 patterns):**

| Category | Weight | What It Catches |
|----------|--------|----------------|
| `aws_key` | 1.0 | AWS access keys (`AKIA…`, `ASIA…`) |
| `private_key` | 1.0 | PEM/SSH/PGP private keys |
| `database_url` | 0.95 | PostgreSQL, MongoDB, MySQL, Redis connection strings |
| `credit_card` | 0.95 | Visa, MasterCard, Amex card numbers |
| `ssn` | 0.95 | Social Security Numbers (XXX-XX-XXXX) |
| `api_key` | 0.9 | Generic API keys, `sk-…` prefixed keys |
| `auth_token` | 0.9 | Bearer tokens, OAuth tokens |
| `github_token` | 0.9 | GitHub PATs (`ghp_…`, `gho_…`) |
| `password` | 0.85 | Password assignments (`password=…`) |
| `jwt` | 0.85 | JSON Web Tokens (`eyJ…`) |
| `slack_token` | 0.8 | Slack bot/user tokens (`xox…`) |
| `generic_secret` | 0.75 | `client_secret=…`, `encryption_key=…` |
| `email` | 0.3 | Email addresses |
| `phone_number` | 0.3 | US/international phone numbers |

**Prompt Injection (3 patterns):**

| Category | Weight | What It Catches |
|----------|--------|----------------|
| `jailbreak_attempt` | 1.0 | DAN prompts, "do anything now", bypass safety |
| `role_manipulation` | 0.95 | "Ignore previous instructions", "debugging mode" |
| `prompt_injection` | 0.9 | "Reveal system prompt", "show hidden instructions" |

### Static Code Analysis (8 categories)

| Category | What It Detects |
|----------|----------------|
| Hardcoded Credentials | Passwords, API keys, tokens embedded in source code |
| Private Keys | PEM, SSH, PGP keys in code files |
| Command Injection | `os.system()`, `subprocess.call()` with user input |
| Eval / Code Execution | `eval()`, `exec()`, `Function()` with dynamic input |
| SQL Injection | String-concatenated SQL queries |
| Insecure Deserialization | `pickle.loads()`, `yaml.load()` without safe loader |
| Path Traversal | Unsanitized file path construction (`../`) |
| Weak Cryptography | MD5, SHA1, DES, RC4, ECB mode usage |

---

## 🧩 Project Structure

```
Guardion/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── auth_routes.py         # Signup, login, user profile
│   │   │   ├── prompt_routes.py       # Prompt analysis & ML comparison
│   │   │   ├── repo_routes.py         # Repo scanning & AI remediation
│   │   │   ├── code_scan_routes.py    # Static analysis & AI fix code
│   │   │   ├── dashboard_routes.py    # User-scoped dashboard metrics
│   │   │   └── admin_routes.py        # Admin platform analytics
│   │   ├── services/
│   │   │   ├── prompt_analyzer.py     # Regex + ML + Gemini pipeline
│   │   │   ├── gemini_integration.py  # Gemini AI analysis & code fixing
│   │   │   ├── gemini_service.py      # AI vulnerability remediation
│   │   │   ├── gemini_cache.py        # LRU cache + rate limiter
│   │   │   ├── repo_scanner.py        # Git clone, dep parsing, OSV queries
│   │   │   ├── code_scanner.py        # Static code analysis engine
│   │   │   ├── nvd_service.py         # NVD API enrichment + caching
│   │   │   ├── owasp_service.py       # OWASP Top 10 classification
│   │   │   └── auth_service.py        # JWT + bcrypt + role guards
│   │   ├── db/
│   │   │   └── mongodb.py             # MongoDB Atlas connection
│   │   ├── config.py                  # Environment settings
│   │   └── main.py                    # FastAPI entry point
│   ├── guardion_ai_model/
│   │   ├── dataset_generator.py       # Synthetic training data (~500 samples)
│   │   ├── train_model.py             # ML model training pipeline
│   │   ├── inference.py               # Model inference & classification
│   │   └── gemini_compare.py          # ML vs Gemini comparison
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Landing.jsx            # Animated SaaS landing page
│   │   │   ├── Login.jsx              # User login
│   │   │   ├── Signup.jsx             # User registration
│   │   │   ├── Dashboard.jsx          # Main dashboard (3 tabs)
│   │   │   └── AdminDashboard.jsx     # Admin-only analytics
│   │   ├── components/
│   │   │   ├── SecurityPipeline.jsx   # 3-stage security pipeline UI
│   │   │   ├── Charts.jsx             # 4-panel analytics (Recharts)
│   │   │   ├── MetricsCards.jsx       # 8 security metric cards
│   │   │   ├── PromptTester.jsx       # Interactive prompt tester
│   │   │   ├── SecureCodePanel.jsx    # Code scanner + AI fix
│   │   │   ├── RepoScanner.jsx        # Repo scan interface
│   │   │   ├── OwaspTrending.jsx      # OWASP Top 10 hover widget
│   │   │   ├── RecentActivity.jsx     # Activity feed
│   │   │   ├── Header.jsx             # Dashboard header
│   │   │   └── Navbar.jsx             # Landing page navbar
│   │   ├── api.js                     # API client
│   │   ├── App.jsx                    # Root + routing
│   │   └── main.jsx                   # Entry point
│   ├── package.json
│   └── vite.config.js
├── extension/
│   ├── manifest.json                  # Manifest V3 config
│   ├── background.js                  # Service worker
│   ├── content.js                     # AI chat page interceptor
│   ├── popup.html / popup.js          # Extension popup UI
│   └── guardion.css                   # Overlay styles
└── README.md
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.10+, FastAPI 0.104, Uvicorn, Pydantic 2.5 |
| **Database** | MongoDB Atlas (PyMongo 4.6+) |
| **AI Engine** | Google Gemini 2.5 Flash (google-genai async SDK, thinking disabled, JSON mode) |
| **ML Model** | sentence-transformers (all-MiniLM-L6-v2) + scikit-learn |
| **Auth** | JWT (python-jose) + bcrypt (passlib) |
| **Vuln APIs** | OSV API, NVD API v2.0 |
| **Frontend** | React 18.2, Vite 7.3, Tailwind CSS 3.4, Framer Motion 12 |
| **Charts** | Recharts 2.10 (Pie, Bar, Area, RadialBar) |
| **Extension** | Chrome Manifest V3 |
| **Languages Scanned** | Python, JavaScript/Node.js, Java (Maven), Go |

---

## 🔒 How the Chrome Extension Works

1. **Content script** (`content.js`) is injected into ChatGPT, Claude, and Gemini pages
2. When you type a prompt and press send, the extension **intercepts** the text
3. It sends the prompt to the Guardion backend (`POST /api/analyze_prompt`)
4. If **BLOCKED** — a warning overlay prevents the prompt from being sent
5. If **WARNED** — a notice appears but you can choose to proceed
6. If **ALLOWED** — the prompt goes through normally
7. The extension popup shows your real-time protection stats

---

## 📊 Dashboard

The dashboard has three main tabs:

### Overview
- **Welcome Banner** with OWASP Top 10 hover widget
- **8 Metric Cards** — Prompts analyzed/blocked/warned, credential leaks, repos scanned, vulnerabilities, critical/high counts
- **4 Chart Panels:**
  - Prompt Risk Distribution (donut with center stats + glow effect)
  - Vulnerability Severity (gradient bar chart)
  - Security Score Trend (area chart from recent scans)
  - Security Posture Gauge (radial gauge with Strong/Moderate/At Risk)
- **Recent Activity Feed** — latest prompts and scans

### Prompt Security
- **Interactive Prompt Tester** — paste any prompt and see real-time analysis
- **ML vs Gemini Comparison** — side-by-side classification results with confidence scores
- **Preset Examples** — quick-test with known attack patterns

### Security Pipeline
- **Stage 1: Repository Scanner** — paste GitHub URL → scans dependencies via OSV
- **Stage 2: Static Code Analyzer** — paste code or upload files → 8 vuln categories, scored 0–100
- **Stage 3: AI Fix Suggestion** — Gemini generates context-aware production-ready fixes, copyable & exportable

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is open source under the [MIT License](LICENSE).

---

<p align="center">
  Built with ❤️ for safer AI interactions
</p>
