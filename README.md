<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://img.shields.io/badge/%F0%9F%9B%A1%EF%B8%8F_PhishGuard-6366f1?style=for-the-badge&labelColor=0d0d14">
  <img alt="PhishGuard" src="https://img.shields.io/badge/%F0%9F%9B%A1%EF%B8%8F_PhishGuard-6366f1?style=for-the-badge&labelColor=111827">
</picture>

# PhishGuard

**A multi-layered cybersecurity platform combining machine learning, real-time Gmail analysis, and community intelligence to detect phishing across URLs, emails, documents, and messaging platforms.**

[![Next.js](https://img.shields.io/badge/Next.js_15-black?style=flat-square&logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python_3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://supabase.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](./LICENSE)

</div>

---

## Overview

PhishGuard is built as four independent but interconnected modules that together form a complete anti-phishing ecosystem:

| Module | Purpose |
|---|---|
| **`safenetai/`** | Next.js 15 web dashboard — scan, report, analyse, learn |
| **`mlmodel/`** | Python FastAPI backend — five ML-powered scan endpoints |
| **`email/`** | Gmail security pipeline — Pub/Sub webhook with SPF/DKIM/DMARC, heuristic rules, NLP classifier, and VirusTotal threat intel via MCP |
| **`whatsapp-bot/`** | Twilio-based WhatsApp bot — forwards messages to the ML backend for real-time scam analysis |

A Chrome extension (`safenetai/extension-build/`) connects the browser to the dashboard, providing in-context protection across Gmail, WhatsApp Web, and LinkedIn.

---

## Architecture

```
safenetai7/
│
├── safenetai/                    Next.js 15 + tRPC + Prisma
│   ├── src/app/                  App Router pages (landing, dashboard, auth, extension)
│   ├── src/components/safenet/   Dashboard client (Detection Lab, Impact Board, Community Reports, Edu Hub, Admin Studio)
│   ├── src/server/api/routers/   tRPC routers — scan, report, admin, auth
│   ├── prisma/schema.prisma      User, Scan, Report, FileUpload models
│   └── extension-build/          Chrome extension (Manifest V3)
│
├── mlmodel/                      Python FastAPI ML Backend
│   ├── app/routers/              link_scan, email_scan, doc_scan, offer_scan, unified_scan
│   ├── app/models/               Trained .pkl classifiers and vectorisers
│   ├── train/                    Training scripts for each model
│   └── datasets/                 Training data (CSVs)
│
├── email/                        Gmail Security Pipeline (FastAPI)
│   ├── main.py                   Pub/Sub webhook + orchestration
│   ├── gmail_client.py           OAuth 2.0 Gmail API client
│   ├── label_manager.py          Gmail label management ([PhishGuard], Suspicious, Phishing)
│   ├── watch_manager.py          Gmail Pub/Sub inbox watch registration
│   ├── pipeline/
│   │   ├── email_parser.py       MIME → EmailContext dataclass
│   │   ├── l1_authentication.py  SPF / DKIM / DMARC / display-name spoofing
│   │   ├── l2_heuristics.py      9 deterministic regex rules
│   │   ├── l2_nlp.py             TF-IDF + Logistic Regression classifier
│   │   ├── l3_threat_intel.py    VirusTotal MCP — URL, domain, file hash checks
│   │   ├── mcp_client.py         MCP stdio JSON-RPC client (VT subprocess)
│   │   ├── scoring.py            SCL score aggregation (0–10)
│   │   ├── orchestrator.py       Master pipeline coordinator
│   │   └── warning_composer.py   HTML warning draft builder (Phase 2.5)
│   └── frontend/                 React + Vite dashboard for email module
│
└── whatsapp-bot/                 Node.js WhatsApp Integration
    ├── server.js                 Twilio webhook (Express, port 5000)
    └── backend.js                ML backend proxy (port 4000)
```

### System Diagram

```mermaid
graph TB
    subgraph User["User Surfaces"]
        Browser["Browser\n(localhost:3000)"]
        WhatsApp["WhatsApp"]
        Gmail["Gmail Inbox"]
        Ext["Chrome Extension\n(Manifest V3)"]
    end

    subgraph SafeNet["safenetai/ — Next.js 15 + tRPC"]
        Landing["Landing Page"]
        Dashboard["Dashboard\n(Detection Lab | Impact Board\nCommunity Reports | Edu Hub\nAdmin Studio)"]
        Auth["NextAuth v5\n(Credentials + bcrypt)"]
        tRPC["tRPC Routers\n(scan | report | admin)"]
    end

    subgraph ML["mlmodel/ — Python FastAPI :8000"]
        LinkScan["/scan/link/\nLogistic Regression"]
        EmailScan["/scan/email/\nRandom Forest"]
        DocScan["/scan/doc/\nRule-based NLP"]
        OfferScan["/scan/offer/\nRandom Forest + 18 features"]
        UnifiedScan["/scan/unified/\nEnsemble"]
    end

    subgraph EmailPipeline["email/ — Gmail Security Pipeline :8080"]
        Webhook["POST /webhook/gmail"]
        L1["L1: Authentication\n(SPF / DKIM / DMARC)"]
        L2H["L2: Heuristics\n(9 regex rules)"]
        L2N["L2: NLP\n(TF-IDF + LogReg)"]
        L3["L3: Threat Intel\n(VirusTotal MCP)"]
        Scoring["SCL Scoring\n(0-10 verdict)"]
    end

    subgraph WA["whatsapp-bot/ — Node.js"]
        WAServer["server.js\nTwilio Webhook :5000"]
        WABackend["backend.js\nML Proxy :4000"]
    end

    subgraph External["External Services"]
        Supabase[("PostgreSQL\n(Supabase)")]
        VT["VirusTotal API"]
        Twilio["Twilio API"]
        GeminiAPI["Gemini API"]
        PubSub["Google Pub/Sub"]
        IP2W["IP2WHOIS API"]
    end

    Browser --> Landing
    Browser --> Dashboard
    Ext --> Dashboard
    Ext -->|"content scripts"| Gmail
    Ext -->|"content scripts"| WhatsApp

    Dashboard --> Auth
    Dashboard --> tRPC
    tRPC --> ML
    tRPC --> Supabase
    tRPC --> GeminiAPI
    tRPC --> IP2W

    Gmail -->|"new email"| PubSub
    PubSub -->|"push notification"| Webhook
    Webhook --> L1 --> L2H --> L2N --> L3 --> Scoring
    L3 --> VT
    Scoring -->|"apply labels"| Gmail

    WhatsApp --> Twilio
    Twilio -->|"webhook"| WAServer
    WAServer --> WABackend
    WABackend --> ML

    LinkScan -.-> UnifiedScan
    EmailScan -.-> UnifiedScan
    DocScan -.-> UnifiedScan
    OfferScan -.-> UnifiedScan

    style User fill:#1e1b4b,stroke:#6366f1,color:#e4e4f0
    style SafeNet fill:#111827,stroke:#818cf8,color:#e4e4f0
    style ML fill:#0f172a,stroke:#22d3ee,color:#e4e4f0
    style EmailPipeline fill:#0f172a,stroke:#f59e0b,color:#e4e4f0
    style WA fill:#0f172a,stroke:#22c55e,color:#e4e4f0
    style External fill:#18181b,stroke:#71717a,color:#a1a1aa
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15 (App Router), React 19, Tailwind CSS v4, shadcn/ui |
| API | tRPC v11 with SuperJSON — end-to-end typesafe |
| Auth | NextAuth v5 (credentials, bcrypt) |
| Database | PostgreSQL via Supabase + Prisma ORM |
| ML Backend | Python FastAPI, Scikit-Learn, joblib, PyMuPDF |
| Email Pipeline | FastAPI, Google Gmail API, Pub/Sub, VirusTotal MCP, dnspython |
| WhatsApp | Node.js, Express, Twilio API |
| Charts | Recharts (Bar, Line, Area, Pie) |
| Extension | Chrome Manifest V3, DeclarativeNetRequest |

---

## Dashboard Sections

The web dashboard at `safenetai/` is a single-page application with five sections:

### Detection Lab

Four scanner cards, each backed by a dedicated ML endpoint:

| Scanner | Input | Backend Endpoint |
|---|---|---|
| Link Scanner | URL | `POST /scan/link/` — Logistic Regression + TF-IDF |
| Domain Age Checker | Domain name | IP2WHOIS API — flags newly registered domains |
| Email Scanner | Email body text | `POST /scan/email/` — Random Forest + custom features |
| Document Scanner | PDF / DOCX upload | `POST /scan/doc/` — rule-based NLP + heuristics |

Each scan returns a risk score mapped to a status:

| Risk Score | Status |
|---|---|
| 0 – 39 | `safe` |
| 40 – 69 | `suspicious` |
| 70 – 100 | `dangerous` |

### Impact Board

Recharts-powered analytics — personal scan history, scan-type distribution, risk breakdown pie chart. Admins see global platform statistics.

### Community Reports

Users submit scam reports with evidence file uploads. A live feed displays all reports with search, type filtering, and date sorting. Report trend graphs show a 7-day rolling window.

### Edu Hub

Interactive phishing awareness quiz with XP, levels, streaks, and achievement badges. Gamified security education.

### Admin Studio

Admin-only section with moderation queue (approve/reject reports), AI-assisted verdict generation via Gemini API, and a support copilot chatbot.

<!-- Screenshot placeholder: Dashboard -->
<!-- ![Dashboard Overview](screenshots/dashboard.png) -->

---

## Gmail Security Pipeline

The `email/` module implements a production-grade, multi-stage email security pipeline that mirrors enterprise systems like Microsoft EOP.

### How It Works

```
Gmail Inbox
    |   (new email arrives)
    v
Gmail API --> Pub/Sub Topic (phishguard-inbound)
    |   (push notification)
    v
POST /webhook/gmail  (FastAPI, exposed via ngrok)
    |
    |-- Decode Pub/Sub envelope --> extract historyId
    |-- history.list --> new message IDs
    v
messages.get(format="raw") --> raw MIME bytes
    |
    v
pipeline/orchestrator.py::run_pipeline()
    |
    |-- L1: Authentication    SPF/DKIM/DMARC/spoofing         max +4 pts
    |-- L2: Heuristics        9 deterministic regex rules      max +4 pts
    |-- L2: NLP               TF-IDF + LogReg classifier       max +3 pts
    |-- L3: Threat Intel      VirusTotal MCP (async)           max +3 pts
    |       |-- scan_url()        per URL in body
    |       |-- scan_domain()     sender domain
    |       |-- scan_file_hash()  suspicious attachments
    v
scoring.py --> PipelineResult (SCL 0-10, verdict)
    |
    |-- CLEAN (0-3)        no action
    |-- SUSPICIOUS (4-6)   [PhishGuard] Suspicious label
    |-- LIKELY_PHISH (7-8) [PhishGuard] Phishing label
    |-- PHISH (9-10)       [PhishGuard] Phishing label + move to Spam
```

### SCL Scoring Model

The pipeline aggregates scores from all stages into a Spam Confidence Level (SCL) score capped at 10:

| SCL | Verdict | Action |
|---|---|---|
| 0 – 3 | `CLEAN` | No action |
| 4 – 6 | `SUSPICIOUS` | Apply `[PhishGuard] Suspicious` label |
| 7 – 8 | `LIKELY_PHISH` | Apply `[PhishGuard] Phishing` label |
| 9 – 10 | `PHISH` | Apply `[PhishGuard] Phishing` label + move to Spam |

### Heuristic Rules (L2)

| Rule | Trigger | Score |
|---|---|---|
| Reply-To mismatch | Reply-To domain differs from From domain | +2 |
| Pivot to external | WhatsApp/Telegram/external handle detected | +2 |
| Urgency language | "act now", "account suspended", "verify immediately" | +1 |
| Credential harvesting | "click here to verify", "confirm your password" | +2 |
| Blank body + attachment | Body under 30 chars with attachment | +3 |
| Suspicious sender pattern | `no-reply-`/`security-` prefix + free email domain | +1 |
| Free domain impersonation | Free provider + institutional display name | +2 |
| Excessive URLs | More than 5 URLs in body | +1 |
| High-entropy domain | Shannon entropy of domain name above 3.5 | +1 |

### VirusTotal MCP Integration (L3)

PhishGuard submits every extracted URL and attachment hash to VirusTotal's aggregated intelligence network via the Model Context Protocol (MCP). The MCP client spawns a persistent subprocess communicating over stdio JSON-RPC, with a token-bucket rate limiter (4 req/min free tier) and in-memory cache.

<!-- Screenshot placeholder: Email Pipeline -->
<!-- ![Gmail Pipeline](screenshots/email-pipeline.png) -->

---

## ML Models

The `mlmodel/` backend exposes five endpoints, each backed by trained classifiers:

| Endpoint | Model | Features |
|---|---|---|
| `POST /scan/link/` | Logistic Regression + TF-IDF | URL token analysis |
| `POST /scan/email/` | Random Forest + TF-IDF + custom | Fee demands, urgency, WhatsApp-only patterns |
| `POST /scan/doc/` | Rule-based NLP + heuristics | PDF/DOCX content analysis via PyMuPDF |
| `POST /scan/offer/` | Random Forest + 18 features | Fake internship/job offer detection |
| `POST /scan/unified/` | Ensemble of above models | Combined risk scoring |

### Custom Feature Engineering (Offer Scanner)

| Feature | What It Detects |
|---|---|
| `has_fee_demand` | Payment language patterns |
| `urgency_score` | Pressure and urgency language |
| `whatsapp_only_score` | "Contact only on WhatsApp" patterns |
| `too_good_score` | "Guaranteed placement, no experience" red flags |
| `credential_score` | Aadhaar, PAN, OTP request detection |
| `legit_score` | Verified corporate email domain matching |

---

## Chrome Extension

The extension (`safenetai/extension-build/`) is a Manifest V3 Chrome extension that provides:

- **Link Guard** — content script on all pages, intercepts known phishing domains via DeclarativeNetRequest rules
- **Gmail content script** — in-context scam warnings inside Gmail
- **WhatsApp Web content script** — message scanning overlay
- **LinkedIn content script** — messaging protection
- **Popup** — shadcn-styled interface linking to the dashboard

<!-- Screenshot placeholder: Extension popup -->
<!-- ![Extension](screenshots/extension.png) -->

---

## WhatsApp Bot

The `whatsapp-bot/` module provides a Twilio-powered WhatsApp interface:

- `server.js` — Express webhook (port 5000) receives messages from Twilio, sends immediate "Please wait..." reply, then processes asynchronously
- `backend.js` — proxy server (port 4000) routes messages to the ML backend for scam analysis and returns formatted results

---

## Getting Started

### Prerequisites

- Node.js 20+
- Python 3.11+
- PostgreSQL (Supabase recommended)

### 1. Clone

```bash
git clone https://github.com/pskth/safenetai7.git
cd safenetai7
```

### 2. Web Dashboard (`safenetai/`)

```bash
cd safenetai
npm install
```

Create `safenetai/.env`:

```env
DATABASE_URL="postgresql://user:password@host:6543/postgres?pgbouncer=true"
DIRECT_URL="postgresql://user:password@host:5432/postgres"
AUTH_SECRET="your-random-secret"
BACKEND_API_URL="http://127.0.0.1:8000"
GEMINI_API_KEY="your-gemini-api-key"
IP2WHOIS_API_KEY="your-ip2whois-api-key"
```

```bash
npm run db:push
npm run dev              # http://localhost:3000
```

### 3. ML Backend (`mlmodel/`)

```bash
cd mlmodel
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Train models (one-time, if `.pkl` files are missing):

```bash
python train/train_link_model.py
python train/train_email_model.py
python train/train_doc_model.py
python train/train_offer_model.py
```

Start the API:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Swagger docs at `http://localhost:8000/docs`.

### 4. Gmail Pipeline (`email/`)

```bash
cd email
pip install -r requirements.txt
```

Create `email/.env` with Google OAuth credentials, Pub/Sub topic, VirusTotal API key. See `email/agents.md` for full variable reference.

```bash
uvicorn main:app --reload --port 8080
ngrok http 8080        # update Pub/Sub push endpoint
```

### 5. WhatsApp Bot (`whatsapp-bot/`)

```bash
cd whatsapp-bot
npm install
```

Create `whatsapp-bot/.env`:

```env
TWILIO_ACCOUNT_SID=your_sid
TWILIO_AUTH_TOKEN=your_token
TWILIO_WHATSAPP_NUMBER=whatsapp:+14155238886
```

```bash
node server.js         # port 5000
node backend.js        # port 4000
```

### 6. Chrome Extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `safenetai/extension-build/` folder

---

## Database Schema

```
User         email auth, scans, reports, file uploads
Scan         type (link|email|document|domain), status (safe|suspicious|dangerous), riskScore, rawResponse
Report       community scam reports with moderation status, evidence uploads
FileUpload   base64 evidence files attached to reports
```

---

## Environment Variables

| Variable | Module | Description |
|---|---|---|
| `DATABASE_URL` | safenetai | Pooled PostgreSQL connection |
| `DIRECT_URL` | safenetai | Direct PostgreSQL (migrations) |
| `AUTH_SECRET` | safenetai | NextAuth session secret |
| `BACKEND_API_URL` | safenetai | ML backend URL |
| `GEMINI_API_KEY` | safenetai | Gemini API (admin moderation) |
| `IP2WHOIS_API_KEY` | safenetai | Domain age lookup |
| `VIRUSTOTAL_API_KEY` | email | VirusTotal threat intel |
| `VT_MCP_SERVER_COMMAND` | email | MCP server command (`npx`) |
| `GOOGLE_CLIENT_CREDENTIALS_PATH` | email | OAuth credentials file path |
| `PUBSUB_TOPIC_NAME` | email | Google Pub/Sub topic |
| `TWILIO_ACCOUNT_SID` | whatsapp-bot | Twilio account SID |
| `TWILIO_AUTH_TOKEN` | whatsapp-bot | Twilio auth token |

---

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.

---

<div align="center">

*PhishGuard — Protecting people one scan at a time.*

</div>
