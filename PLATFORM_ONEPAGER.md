# ThreatIntel Platform — One-Page Summary

A self-hosted threat intelligence platform that aggregates public feeds, links
vulnerabilities to attacker behaviour, and adds a **detection-coverage layer** so a team
sees not just what threats exist but whether they could detect them.

**Stack:** Node/Express · PostgreSQL · React.
**Sources (all public):** MITRE ATT&CK, NVD (CVEs), Abuse.ch (IOCs), AlienVault OTX (actors).

## What it's for
- **SOC triage / IOC enrichment** — search or bulk-check indicators (with defang handling) against all feeds in one place.
- **Threat-informed patching** — rank CVEs by linked ATT&CK techniques + IOCs, weighting vulnerabilities that map to techniques you *can't detect*.
- **Detection gap analysis** — mark each ATT&CK technique Detected/Partial/None with notes; the matrix becomes a "where are we blind?" map.
- **Threat-actor research** — pivot from an actor to their techniques, CVEs, and IOCs.
- **Situational awareness** — dashboard of threat landscape + the team's own detection posture.

## Key features
- **CVE Explorer:** severity/score/CWE filters, full-text search, threat + "blind-coverage" signals, coverage-weighted sort.
- **IOC Search:** trigram + exact search, bulk lookup (≤500), auto refang/defang, copy.
- **ATT&CK Matrix:** frequency heatmap + detection-coverage overlay with in-place status/notes editor.
- **Detection coverage:** per-technique status + notes + attribution; drives CVE prioritization and a dashboard coverage %.
- **Access control (DB-enforced):** three roles (readonly/contributor/admin) via PostgreSQL roles, GRANT/REVOKE, and row-level security — not just app code. JWT auth, bcrypt-12.
- **Self-service:** public read-only signup; contributor role-request → admin approve/decline with live role refresh.
- **Auditing:** activity log of signups, role changes, request decisions, ingestion, and coverage edits (before → after).
- **Ingestion:** scheduled + manual runs from all four feeds.

## Known limitations (for review)
Free/public feeds only · single-tenant · no auth rate-limiting · JWTs in localStorage (8h, no refresh) · ingestion status in-memory · no automated tests · no KEV flag / exports / alerting.

## Questions for the expert
Is coverage-weighted prioritization realistic for a real SOC? · Is DB-enforced RBAC (roles + RLS) the right layer or overkill? · Highest-value missing capability for daily analyst workflow? · Data-quality concerns linking CVEs to ATT&CK from these free feeds?
