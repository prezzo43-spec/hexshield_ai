# HexShield AI

HexShield AI is a digital forensic investigation platform designed to analyze suspicious file artifacts, detect manipulation in media content, and preserve evidence integrity through a formal chain-of-custody workflow. The repository combines a FastAPI backend, a Next.js dashboard, and a PostgreSQL-backed evidence model to support forensic triage, AI-assisted media analysis, and report generation.

---

## Executive Summary

This project addresses two important cyber-forensic problems:

- malicious content delivered through disguised or engineered binary streams
- synthetic or manipulated media used to deceive investigators, victims, or judicial systems

The system is organized into three layers:

1. Hex-level binary triage
2. Multimodal AI media analysis
3. Forensic reporting and evidence preservation

The result is a full-stack prototype for evidence intake, case management, forensic analysis, and reporting within a single workflow.

---

## System Overview

HexShield AI supports the following operational pipeline:

1. Investigators authenticate and access a protected dashboard.
2. A case is created for a forensic investigation.
3. Evidence is uploaded and stored with generated cryptographic hashes.
4. File metadata and binary structure are analyzed for anomalies.
5. Image, audio, and video files are assessed for manipulated content.
6. Case evidence is correlated and summarized into forensic reports.
7. Reports are stored, exported, and tied back to the chain-of-custody record.

This repository currently contains the core application logic, database migration scripts, frontend dashboard views, and the forensic analysis services required for the workflow.

---

## Technology Stack

### Backend
- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Pydantic + pydantic-settings
- JWT-based authentication
- bcrypt password hashing
- hashlib for integrity checks

### Frontend
- Next.js
- React
- TypeScript
- Tailwind CSS
- Axios for API requests

### Forensic and AI Components
- Shannon entropy analysis
- Magic byte signature comparison
- MIME verification and spoof detection
- AI media analyzers for image, video, and audio
- JSON and PDF forensic report generation

---

## Architecture

The application follows a layered architecture:

### 1. Presentation Layer
The frontend is built with Next.js App Router and provides investigator-facing screens for:
- login and authentication
- password changes
- dashboard overview
- case management
- evidence submission
- analysis review
- report retrieval
- investigator administration
- health monitoring

### 2. API Layer
The backend exposes a FastAPI application with routers for:
- health monitoring
- authentication and session management
- investigators
- cases
- evidence submissions
- analysis execution
- report generation

### 3. Service Layer
The backend service layer includes:
- authentication and authorization logic
- hex triage and entropy analysis
- AI media analysis orchestration
- forensic reporting utilities
- evidence validation and storage handling

### 4. Persistence Layer
The database layer uses PostgreSQL with migration scripts for:
- investigators
- case records
- evidence submissions
- magic-byte references
- forensic analysis results
- chain-of-custody events
- audit logs
- forensic reports

---

## Core Features

### Authentication and Access Control
- investigator login and refresh-token flow
- password hashing using bcrypt
- role-aware dashboard navigation
- first-login password change enforcement
- account lockout and audit logging

### Case and Evidence Workflow
- creation and tracking of forensic cases
- evidence intake and upload handling
- file hashing at ingestion
- metadata persistence for evidence records
- audit and custody event tracking

### Hex and Binary Analysis
- magic-byte signature evaluation
- entropy-based suspiciousness checks
- file MIME and extension validation logic
- comparison of declared vs detected formats
- preliminary triage for obfuscation and malware indicators

### AI Media Analysis
The AI engine is organized for multimodal inspection:
- image analysis for manipulation artifacts and compression anomalies
- video analysis for frame-level patterns and temporal inconsistencies
- audio analysis for spectral and voice synthesis indicators

### Forensic Reporting
- structured JSON report output
- PDF report generation for court-facing documentation
- integrity verification via cryptographic hashes
- chain-of-custody linkage
- reported findings tied to the underlying evidence record

---

## Repository Structure

```text
hexshield_ai/
├── README.md
├── render.yaml
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── main.py
│   │   ├── models/
│   │   ├── routers/
│   │   │   ├── analysis.py
│   │   │   ├── auth.py
│   │   │   ├── cases.py
│   │   │   ├── health.py
│   │   │   ├── investigators.py
│   │   │   ├── reports.py
│   │   │   └── submissions.py
│   │   ├── schemas/
│   │   ├── services/
│   │   │   ├── ai_engine/
│   │   │   │   ├── ai_engine.py
│   │   │   │   ├── audio_analyzer.py
│   │   │   │   ├── consensus_engine.py
│   │   │   │   ├── huggingface_analyzer.py
│   │   │   │   ├── image_analyzer.py
│   │   │   │   ├── model_base.py
│   │   │   │   ├── model_validation.py
│   │   │   │   └── video_analyzer.py
│   │   │   ├── auth.py
│   │   │   ├── hex_engine/
│   │   │   └── forensic_reporting/
│   │   └── utils/
│   ├── database/
│   │   └── migrations/
│   │       ├── 001_initial_schema.sql
│   │       └── 002_add_authentication.sql
│   ├── docs/
│   ├── logs/
│   ├── scripts/
│   │   ├── clean_demo_data.py
│   │   ├── create_admin.py
│   │   ├── run_migration.py
│   │   └── test_ai_engine.py
│   ├── storage/
│   │   ├── reports/
│   │   └── uploads/
│   ├── tests/
│   │   ├── evaluation.py
│   │   ├── generate_test_files.py
│   │   ├── test_hex_engine.py
│   │   └── test_files/
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   ├── requirements.lock.txt
│   ├── Procfile
│   ├── runtime.txt
│   └── pip_audit_results.json
├── frontend/
│   ├── app/
│   ├── public/
│   ├── src/
│   ├── package.json
│   ├── eslint.config.mjs
│   ├── next.config.ts
│   ├── tsconfig.json
│   └── README.md
├── docs/
└── temp_pip_download/
```

---

## Database Schema Highlights

The database includes the following key entities:

- investigators
- cases
- file_submissions
- magic_byte_signatures
- hex_analysis_results
- ai_media_analysis_results
- ai_analysis_frame_details
- chain_of_custody_events
- forensic_reports
- system_audit_log
- schema_migrations

The schema is designed for evidence integrity, auditability, and traceability. Chain-of-custody and audit entries are treated as append-only evidence of who handled a file and when.

---

## Forensic Workflow

The platform is built around a structured forensic process:

1. Investigator registration and secure login
2. Case setup and investigation context creation
3. Evidence submission and hashing
4. File-level triage and integrity checks
5. AI media analysis for manipulation detection
6. Aggregation of findings into forensic results
7. Report generation and export
8. Chain-of-custody and audit preservation

This supports both technical investigation and legal documentation needs.

---

## Key Security and Integrity Considerations

The project implements several important safeguards:

- cryptographic hashing for evidence integrity
- JWT-based authentication and refresh handling
- bcrypt password hashing
- host validation and security headers in the FastAPI app
- immutable chain-of-custody and audit records in the database
- evidence storage under controlled directories

It also contains areas that are suitable for future hardening in production environments, such as stricter endpoint-level authorization enforcement, more comprehensive validation around uploaded files, and additional model verification controls.

---

## Setup Instructions

### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL instance or compatible database service
- Access to environment variables for backend configuration

### Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in the backend root with the required values, including:
- DATABASE_URL
- SECRET_KEY
- APP_ENV
- ALLOWED_ORIGINS
- ALLOWED_HOSTS

Then initialize the database and run the app:

```bash
python scripts/run_migration.py
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The frontend communicates with the backend through the configured API base URL.

---

## API Access

Once the backend is running, the API documentation is available at:

- http://localhost:8000/api/docs

---

## Testing

The repository includes testing utilities for forensic validation and engine checks.

```bash
cd backend
python tests/generate_test_files.py
python -m pytest tests/test_hex_engine.py -v
```

Additional project scripts are available for migration and admin setup.

---

## Current Project Status

This repository is structured as a functional capstone-grade forensic platform prototype, with implementations spanning:

- backend API services
- database schema and migrations
- frontend dashboard workflows
- evidence lifecycle management
- forensic analysis logic
- report generation

The project is suitable for academic demonstration, technical walkthroughs, and extension into a production-grade digital forensics platform.

---

## Academic and Research Context

HexShield AI is designed to model a modern forensic investigation environment where binary analysis and AI-based media assessment are brought together under a legal and evidentiary workflow. It aligns with investigations involving suspicious file artifacts, manipulated media, cybercrime evidence handling, and contemporary digital forensic reporting practices.

---

## License

This project is intended for academic and research use. Please review repository-specific licensing and environment constraints before deploying it in operational or commercial environments.
