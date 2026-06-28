# HexShield AI

**A Multi-Layered Forensic Engine for Malicious Streams and Manipulated Media**

---

## Overview

HexShield AI is a production-grade digital forensics platform developed as a
capstone research project addressing two critical cybersecurity problems in Kenya:
the proliferation of obfuscated malware delivered through MIME-spoofed file streams,
and the rapid growth of AI-generated deepfake media used in fraud, blackmail, and
manipulation of criminal evidence.

The system integrates three forensic layers into a unified investigative platform:

**Layer 1 — Hex-Level Binary Triage Engine**
Analyzes raw file byte streams, verifies magic byte signatures against a knowledge
base of known formats, and calculates Shannon Entropy to detect packing, encryption,
and obfuscation. Detects MIME-type spoofing by comparing declared MIME types against
magic-byte-detected formats.

**Layer 2 — Multimodal AI Media Engine**
Applies deep learning and classical signal processing to detect synthetic manipulation
in images (ELA, noise analysis, compression artifacts), video (temporal consistency,
frame-level anomaly scoring), and audio (MFCC analysis, voice synthesis detection).

**Layer 3 — Forensic Preservation and Reporting Module**
Generates SHA-256 and SHA-512 cryptographic hashes at ingestion, maintains an
ISO/IEC 27037 compliant chain of custody in a Neon cloud PostgreSQL database, and
produces court-ready PDF and machine-readable JSON forensic reports.

---

## Legal and Compliance Context

- **ISO/IEC 27037:2012** — Digital evidence identification, collection, and preservation
- **Computer Misuse and Cybercrimes Act, 2018 (Kenya)** — Digital evidence admissibility
- **Evidence Act (Kenya)** — Documentary and electronic evidence requirements

Chain-of-custody records are immutable at the database level. All forensic artifacts
carry cryptographic integrity proofs. Reports include SHA-256 hashes for court verification.

---

## Technology Stack

| Component         | Technology                                      |
|-------------------|-------------------------------------------------|
| Frontend          | Next.js 16, React 19, TypeScript, Tailwind CSS  |
| Backend API       | Python 3.12, FastAPI, Uvicorn                   |
| Database          | PostgreSQL 16 (Neon Serverless, London)         |
| ORM               | SQLAlchemy 2.0, psycopg2                        |
| AI / ML           | PyTorch, TorchVision, OpenCV, librosa           |
| Forensic Hashing  | hashlib (SHA-256, SHA-512)                      |
| Binary Analysis   | python-magic, pefile, olefile                   |
| Report Generation | ReportLab (PDF), JSON                           |
| Authentication    | JWT (python-jose), passlib                      |

---

## Project Structure

hexshield_ai/

├── backend/

│   ├── app/

│   │   ├── main.py                    # FastAPI application entry point

│   │   ├── config.py                  # Settings from .env

│   │   ├── database.py                # SQLAlchemy engine and session

│   │   ├── models/                    # ORM models (Step 8)

│   │   ├── routers/

│   │   │   ├── health.py              # Health check endpoints

│   │   │   ├── investigators.py       # Investigator management

│   │   │   ├── cases.py               # Case management

│   │   │   ├── submissions.py         # File ingestion and evidence

│   │   │   ├── analysis.py            # Hex and AI analysis triggers

│   │   │   └── reports.py             # Report generation and download

│   │   └── services/

│   │       ├── hex_engine/

│   │       │   ├── magic_bytes_db.py  # Magic byte signatures database

│   │       │   ├── entropy.py         # Shannon Entropy calculator

│   │       │   └── triage_engine.py   # Layer 1 core orchestrator

│   │       ├── ai_engine/

│   │       │   ├── model_base.py      # Abstract base analyzer

│   │       │   ├── image_analyzer.py  # ELA, noise, compression analysis

│   │       │   ├── video_analyzer.py  # Frame extraction, temporal analysis

│   │       │   ├── audio_analyzer.py  # MFCC, spectral, voice synthesis

│   │       │   └── ai_engine.py       # Layer 2 orchestrator

│   │       └── forensic_reporting/

│   │           ├── report_generator.py # Data assembly and utilities

│   │           ├── json_report.py      # JSON report generator

│   │           └── pdf_report.py       # PDF report generator

│   ├── database/

│   │   └── migrations/

│   │       └── 001_initial_schema.sql # Complete PostgreSQL schema

│   ├── scripts/

│   │   ├── run_migration.py           # Database migration runner

│   │   └── test_ai_engine.py          # AI engine smoke test

│   ├── tests/

│   │   ├── generate_test_files.py     # Simulated malicious file generator

│   │   └── test_hex_engine.py         # 38 unit tests for Layer 1

│   ├── .env.example                   # Environment variable template

│   └── requirements.txt               # Python dependencies

│

├── frontend/

│   ├── app/

│   │   ├── layout.tsx                 # Root layout

│   │   ├── page.tsx                   # Root redirect

│   │   └── dashboard/

│   │       ├── layout.tsx             # Dashboard layout with sidebar

│   │       ├── page.tsx               # Dashboard home

│   │       ├── cases/                 # Case management pages

│   │       ├── submit/                # Evidence submission page

│   │       ├── analysis/              # Analysis queue and detail pages

│   │       ├── reports/               # Reports page

│   │       ├── investigators/         # Investigator management

│   │       └── health/                # System health page

│   └── src/

│       ├── components/

│       │   └── layout/

│       │       └── Sidebar.tsx        # Navigation sidebar

│       ├── services/

│       │   └── api.ts                 # Backend API client

│       └── types/

│           └── index.ts               # Shared TypeScript types

│

├── docs/                              # Project documentation

├── .gitignore

└── README.md

---

## Database Schema

The relational schema consists of 11 tables organized into four functional groups:

**Core Entities:** `investigators`, `cases`

**Evidence Management:** `file_submissions`

**Reference Data:** `magic_byte_signatures`

**Analysis Layers:** `hex_analysis_results`, `ai_media_analysis_results`,
`ai_analysis_frame_details`

**Forensic Compliance:** `chain_of_custody_events` (INSERT ONLY),
`forensic_reports`, `system_audit_log` (INSERT ONLY), `schema_migrations`

---

## Setup and Installation

### Prerequisites

- Python 3.11+
- Node.js 18+
- A Neon PostgreSQL account (https://neon.tech)

### Backend Setup

```bash
cd backend
python -m venv venv --without-pip
source venv/bin/activate  # Windows: .\venv\Scripts\Activate.ps1
python -m ensurepip --upgrade
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your Neon DATABASE_URL and SECRET_KEY

python scripts/run_migration.py
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install
# Edit .env.local with NEXT_PUBLIC_API_URL=http://localhost:8000
npm run dev
```

### API Documentation

Once the backend is running, visit:
http://localhost:8000/api/docs

---

## Testing

```bash
cd backend

# Generate simulated malicious test files
python tests/generate_test_files.py

# Run Layer 1 unit tests (38 tests)
python -m pytest tests/test_hex_engine.py -v
```

---

## Forensic Workflow

1. **Register Investigator** — Create analyst account with badge number and role
2. **Open Case** — Create forensic case with jurisdiction and applicable law
3. **Submit Evidence** — Upload file; SHA-256 and SHA-512 computed at ingestion
4. **Run Hex Triage** — Magic byte verification, entropy analysis, MIME spoofing detection
5. **Run AI Analysis** — Deepfake detection for images, video, and audio
6. **Generate Report** — Court-ready PDF or machine-readable JSON with chain of custody
7. **Certify Report** — Senior investigator marks report as court-ready

---

## Key Forensic Features

- SHA-256 and SHA-512 hashes computed at ingestion and verified at every custody event
- MIME spoofing detection comparing declared vs magic-byte-detected file types
- Shannon Entropy analysis detecting encrypted, packed, or obfuscated payloads
- Per-frame video analysis for temporal deepfake detection
- ISO/IEC 27037 chain-of-custody events immutable at database level
- Court-ready PDF reports with legal disclaimer and hash verification
- Machine-readable JSON reports for SIEM integration

---

## Stakeholders

- Directorate of Criminal Investigations (DCI)
- Office of the Director of Public Prosecutions (ODPP)
- National Police Service
- Judiciary of Kenya
- Financial institutions and media organizations

---

## Development Team

Capstone research project — Open university of Kenya

---

## License

Developed as an academic capstone project under ISO/IEC 27037 forensic standards.
All forensic methodologies are based on published standards and peer-reviewed literature.
