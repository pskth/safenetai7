<div align="center">

<h1>🛡️ SafeNet AI</h1>

**An AI-powered cybersecurity platform to detect phishing links, scam emails, and malicious documents — built for the real world.**

[![Next.js](https://img.shields.io/badge/Next.js-15-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python)](https://python.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-4169E1?style=for-the-badge&logo=postgresql)](https://supabase.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-F7931E?style=for-the-badge&logo=scikit-learn)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](./LICENSE)

</div>

---

## 📌 Overview

**SafeNet AI** is a full-stack, production-grade cybersecurity intelligence platform that uses **machine learning** to detect and flag phishing threats across multiple attack vectors — URLs, emails, documents, and offer scams.

It is built as a command center for individuals and administrators to actively scan suspicious content, report scams to a community feed, track their threat-detection history, and learn about online safety — all from one sleek, dark-mode dashboard.

> **Ideal for:** Final year engineering project, security hackathons, placement interviews, or real-world deployment as a college/institutional scam-awareness tool.

---

## ✨ Key Features

### 🔍 Detection Lab
| Scanner | What It Does |
|---|---|
| **Link Scanner** | Scans URLs using a trained ML classifier to predict phishing vs. legitimate |
| **Domain Age Checker** | Queries the IP2WHOIS API to assess how old a domain is — newly created domains are flagged |
| **Email Scanner** | Analyzes email body text for fee demands, urgency language, pressure tactics, and suspicious links |
| **Document Scanner** | Accepts PDF/DOCX/TXT uploads and scans for scam indicators using NLP |

### 📊 Impact Board
- **Recharts-powered analytics** — bar charts, pie charts, and area graphs
- Personal scan history and activity timeline
- Admin-only global scan statistics and risk distribution

### 🚨 Community Reports
- **Self-reporting system** — any user can submit a scam with evidence uploads
- Public real-time feed with search, filter by type, and sort by date/evidence
- Report trend graphs (7-day rolling window)
- Admin moderation panel to approve/reject reports

### 🎓 Edu Hub
- Interactive phishing awareness quiz
- XP, levels, streaks, and achievement badges
- Gamified security education to keep users engaged

### 🛠️ Admin Studio
- Full overview of platform scans and reports
- AI-assisted moderation with Gemini API
- Support copilot chatbot for drafting user safety replies

---

## 🏗️ Architecture

```
safenetai7/
│
├── safenetai/              # Next.js 15 Frontend + tRPC Backend
│   ├── src/
│   │   ├── app/            # Next.js App Router (pages, layouts)
│   │   ├── components/     # UI components (dashboard, scan cards, charts)
│   │   ├── server/api/     # tRPC routers (scan, report, admin)
│   │   ├── lib/            # Utilities (security helpers, keyword extraction)
│   │   └── styles/         # Global CSS (glassmorphism, custom theme)
│   ├── prisma/             # Prisma schema + migrations
│   └── generated/          # Auto-generated Prisma client
│
├── mlmodel/                # Python FastAPI ML Backend
│   ├── app/
│   │   ├── routers/        # API endpoints (email, link, doc, offer, unified)
│   │   ├── models/         # Trained .pkl model files
│   │   ├── services/       # Business logic
│   │   └── utils/          # Shared helpers
│   ├── train/              # Model training scripts
│   └── datasets/           # Training data
│
└── whatsapp-bot/           # Optional WhatsApp integration
```

### Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | Next.js 15 (App Router), React 19, Tailwind CSS v4, shadcn/ui |
| **API Layer** | tRPC v11 with React Query — end-to-end typesafe |
| **Auth** | NextAuth v5 (credentials-based, bcrypt) |
| **Database** | PostgreSQL via Supabase + Prisma ORM |
| **ML Backend** | Python FastAPI, Scikit-Learn, joblib, PyMuPDF |
| **Charts** | Recharts (Bar, Line, Area, Pie) |
| **Deployment** | Vercel (frontend) · Render via Docker (ML backend) |

---

## 🤖 Machine Learning Models

The `mlmodel/` backend exposes 5 ML-powered scan endpoints:

| Endpoint | Model | Task |
|---|---|---|
| `POST /scan/link/` | Logistic Regression + TF-IDF | Phishing URL detection |
| `POST /scan/email/` | Random Forest + TF-IDF + custom features | Scam email detection (fee demands, urgency, WhatsApp-only) |
| `POST /scan/doc/` | Rule-based NLP + heuristics | Malicious document detection from PDF/DOCX |
| `POST /scan/offer/` | Random Forest + 18 hand-crafted features | Fake job/internship offer detection |
| `POST /scan/unified/` | Ensemble combining above models | Comprehensive risk scoring |

**Custom Features Engineered:**
- `has_fee_demand` — payment language pattern matching
- `urgency_score` — urgency/pressure language detection
- `whatsapp_only_score` — "contact only on WhatsApp" patterns
- `too_good_score` — "guaranteed placement, no experience needed" red flags
- `credential_score` — Aadhaar, PAN, OTP request detection
- `legit_score` — verified corporate email domain matching

---

## 🚀 Getting Started

### Prerequisites

- Node.js 20+
- Python 3.11+
- PostgreSQL (or a Supabase project)

---

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/safenetai7.git
cd safenetai7
```

---

### 2. Setup the Frontend (`safenetai/`)

```bash
cd safenetai
npm install
```

Create a `.env` file in `safenetai/`:

```env
# Database (Supabase recommended)
DATABASE_URL="postgresql://user:password@host:6543/postgres?pgbouncer=true"
DIRECT_URL="postgresql://user:password@host:5432/postgres"

# Auth
AUTH_SECRET="your-random-secret-string"

# ML Backend URL
BACKEND_API_URL="http://127.0.0.1:8000"

# External APIs
GEMINI_API_KEY="your-gemini-api-key"
IP2WHOIS_API_KEY="your-ip2whois-api-key"
```

Run database migrations and start the dev server:

```bash
npm run db:push       # Push schema to database
npm run dev           # Start Next.js dev server at http://localhost:3000
```

---

### 3. Setup the ML Backend (`mlmodel/`)

```bash
cd mlmodel
pip install -r requirements.txt
```

> **Important:** Make sure trained model `.pkl` files are present in `mlmodel/app/models/`. Run the training scripts in `mlmodel/train/` if they are missing.

Start the FastAPI backend:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be live at `http://localhost:8000`. View the interactive Swagger docs at `http://localhost:8000/docs`.

---

### 4. (Optional) Docker Deployment for ML Backend

The ML backend is Docker-ready and configured for Render:

```bash
cd mlmodel
docker build -t safenet-api .
docker run -p 8000:8000 safenet-api
```

---

## 🗃️ Database Schema

```
User         — email auth, scans, reports, file uploads
Scan         — stores every scan result (type, status, riskScore, rawResponse)
Report       — community scam reports with moderation status
FileUpload   — base64 evidence files attached to reports
```

---

## 📡 API Reference

### Scan Endpoints (tRPC)

| Mutation | Input | Returns |
|---|---|---|
| `scan.scanLink` | `{ url }` | `{ prediction, confidence, riskScore, status, keywords }` |
| `scan.checkDomainAge` | `{ domain }` | `{ domain, createdAt, ageYears, riskScore, status }` |
| `scan.scanEmail` | `{ emailText, senderDomain? }` | `{ prediction, confidence, riskScore, status, explanation }` |
| `scan.scanDocument` | `{ fileName, mimeType, base64Data }` | `{ riskScore, status, verdict, warnings, indicators }` |
| `scan.history` | *(authenticated)* | Array of past scans |

### Risk Status Mapping

| Risk Score | Status |
|---|---|
| 0 – 39 | ✅ `safe` |
| 40 – 69 | ⚠️ `suspicious` |
| 70 – 100 | 🚨 `dangerous` |

---

## 🔑 Environment Variables Reference

| Variable | Description |
|---|---|
| `DATABASE_URL` | Pooled PostgreSQL connection string |
| `DIRECT_URL` | Direct PostgreSQL connection (for migrations) |
| `AUTH_SECRET` | NextAuth session secret |
| `BACKEND_API_URL` | URL of the Python FastAPI ML backend |
| `GEMINI_API_KEY` | Google Gemini API key (for admin AI moderation) |
| `IP2WHOIS_API_KEY` | IP2WHOIS API key (for domain age lookup) |

---

## 📸 Screenshots

> Dashboard features a cyber/glassmorphism dark aesthetic with neon accents, animated panels, and real-time risk visualization.

| Detection Lab | Community Reports | Admin Studio |
|---|---|---|
| Link, Email, Document & Domain scanners | Community scam feed with evidence uploads | Global analytics, AI moderation, support copilot |

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change. For feature additions:

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push and open a PR

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](./LICENSE) file for details.

---

<div align="center">

Built with 💙 by **Hariharanath** · Department of Computer Science & Engineering

*SafeNet AI — Protecting people one scan at a time.*

</div>
