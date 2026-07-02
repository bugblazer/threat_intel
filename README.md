# Cybersecurity Threat Intelligence Database

Full-stack security intelligence platform · React + Node.js + PostgreSQL

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Node.js | ≥ 18 | https://nodejs.org |
| npm | ≥ 9 | bundled with Node |
| PostgreSQL | ≥ 14 | https://www.postgresql.org/download/ |

---

## Quick Start

### 1. Clone and install dependencies

```bash
git clone https://github.com/bugblazer/threat_intel
cd threat-intel
npm install          # installs both server/ and client/ workspaces
```

### 2. Configure environment

```bash
cp .env.example .env
# Open .env and set your passwords and API keys
```

### 3. Bootstrap the database

Make sure PostgreSQL is running, then:

```bash
bash scripts/setup-db.sh
```

This will:
- Create three PostgreSQL roles (`threat_admin`, `threat_readonly`, `threat_contributor`)
- Create the `threat_intel` database
- Run all six Knex migrations (tables → views → indexes → triggers → access control)

### 4. Run the dev server

```bash
npm run dev:server   # Express API on http://localhost:3001
npm run dev:client   # React app on http://localhost:5173
```

---

## Database Migrations

```bash
npm run migrate           # run pending migrations
npm run migrate:rollback  # roll back last batch
```

Migration order and what each one does:

| # | File | DB Concept |
|---|------|-----------|
| 001 | `roles_and_extensions` | Setup: pg_trgm, unaccent, PG roles |
| 002 | `core_tables` | Schema: techniques, cves, iocs, threat_actors, users |
| 003 | `views` | **Views**: high_severity_cves, active_iocs, technique_frequency |
| 004 | `indexes` | **Indexing**: B-tree, GIN, GiST across all tables |
| 005 | `fulltext_triggers` | **Full-Text Search**: tsvector triggers on cves + threat_actors |
| 006 | `access_control` | **Access Control**: GRANT/REVOKE + RLS on users table |

---

## Project Structure

```
threat-intel/
├── .env.example          ← copy to .env
├── scripts/
│   └── setup-db.sh       ← one-time DB bootstrap
├── server/
│   └── src/
│       ├── db/
│       │   ├── knexfile.js        ← Knex config (dev/prod)
│       │   ├── db.js              ← role-aware connection pools
│       │   ├── migrations/        ← 001–006
│       │   └── seeds/             ← (coming soon)
│       ├── routes/                ← Express route handlers
│       ├── middleware/            ← JWT auth middleware
│       └── ingestion/             ← data feed scripts
└── client/                        ← React app
```

---

## Data Sources

| Source | What it provides | Auth |
|--------|-----------------|------|
| MITRE ATT&CK | Tactics, techniques, sub-techniques | None (public JSON) |
| NVD CVE Feed (NIST) | CVEs with CVSS scores and affected products | API key (free) |
| Abuse.ch | Malware hashes, C2 URLs, botnet IOCs | API key (free) |
| AlienVault OTX | Community threat pulses with ATT&CK mappings | API key (free) |
