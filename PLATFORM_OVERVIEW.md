# ThreatIntel Platform — Use Cases & Features

A self-hosted threat intelligence aggregation platform. It ingests data from public
cybersecurity feeds, links vulnerabilities to attacker behaviour, and adds a
detection-coverage layer so a team can see not just *what* threats exist but *whether
they could detect them*.

**Stack:** Node.js / Express API, PostgreSQL, React (Vite) frontend.
**Data sources:** MITRE ATT&CK (techniques), NVD (CVEs), Abuse.ch — MalwareBazaar /
URLhaus / ThreatFox (IOCs), AlienVault OTX (threat actors & pulses). All public feeds.

---

## Practical use cases

### 1. SOC triage & IOC enrichment
An analyst investigating an alert can check indicators (IPs, hashes, domains, URLs)
against everything ingested — malware family, source feed, confidence, first/last seen —
in one lookup instead of pivoting across multiple vendor sites.
- **Single search** with fuzzy (trigram) and exact-match modes.
- **Bulk lookup:** paste a block of indicators from an alert or email and get a
  found/clean verdict for each at once.
- **Defang handling:** accepts defanged indicators (`1[.]2[.]3[.]4`, `hxxp://`,
  `evil(dot)com`) and can display/copy results defanged for safe pasting into tickets.

### 2. Threat-informed vulnerability prioritization
Rather than patching purely by CVSS, the platform ranks vulnerabilities by real-world
threat context: how many ATT&CK techniques a CVE maps to, and how many known IOCs
reference it.
- **Coverage-weighted priority:** a CVE that exploits a technique the team *cannot
  detect* is weighted higher — surfaced with a "blind" flag — because it's the one you
  won't see coming.
- Filter to "with threat intel only"; sort by severity, threat-informed priority, or
  newest.

### 3. Detection engineering & ATT&CK gap analysis
The ATT&CK matrix doubles as a live coverage map. A team marks each technique as
**Detected / Partial / None**, with free-text notes explaining gaps ("no EDR on Linux
hosts", "rule pending review"). This turns the matrix into a "where are we blind?" tool
and feeds directly into vulnerability prioritization above.

### 4. Threat actor research
Look up an actor's aliases, country, motivation, and associated techniques, and pivot to
their linked CVEs and IOCs.

### 5. Reporting & situational awareness
A dashboard gives a team lead / CISO a quick read on the threat landscape and the team's
own detection posture without running queries — total and critical CVE counts, active
IOCs, technique count, and a **detection-coverage percentage** with a breakdown of
detected / partial / blind.

---

## Feature inventory

### Data & ingestion
- Multi-source ingestion from MITRE ATT&CK, NVD, Abuse.ch, and AlienVault OTX.
- Scheduled ingestion (cron) plus on-demand manual runs.
- The analytical join table (`cve_technique_map`) linking each CVE to the ATT&CK
  technique used to exploit it.

### CVE Explorer
- Filter by severity, CVSS score, CWE, publication date.
- Full-text search (PostgreSQL `tsvector`) with relevance ranking.
- Threat signal per CVE: linked-technique count, linked-IOC count, and a "N blind" badge
  for techniques with no detection coverage.
- Sort modes: severity, threat-informed (coverage-weighted), newest.
- CVE detail view with linked techniques.

### IOC Search
- Filter by type and source feed.
- Trigram fuzzy search and exact-match lookup.
- Bulk lookup (up to 500 indicators) with automatic refang and defanged output.
- Copy-to-clipboard for indicators.

### ATT&CK Matrix
- Frequency heatmap (cell intensity = combined IOC + CVE co-occurrence).
- Detection-coverage overlay (colour = Detected / Partial / None).
- In-place coverage editor (status + notes) for contributors and admins.
- Hover tooltip showing frequency, coverage status, last editor, and notes.
- Technique detail page with linked CVEs, IOCs, sub-techniques, and a coverage panel.

### Detection coverage layer
- Per-technique status: none / partial / detected.
- Free-text coverage notes.
- Attribution: who last set the coverage and when.
- Dashboard coverage KPI (partial counts as half) plus a stacked detected/partial/blind
  breakdown.
- Coverage feeds vulnerability prioritization (blind techniques weighted double).

### Dashboard
- KPI cards: total CVEs, critical CVEs, active IOCs, ATT&CK techniques, detection
  coverage %.
- CVE severity distribution (donut) and IOCs-by-type breakdown.
- "Hottest techniques" by frequency; recent CVEs and IOCs feeds.

### Access control (database-enforced)
- Three roles: **readonly** (analysts — view only), **contributor** (view + write threat
  data + trigger ingestion), **admin** (full control incl. user management).
- Enforced at the database layer via distinct PostgreSQL roles, table-level GRANT/REVOKE,
  and row-level security on the users table — not just in application code. Each API
  request runs on the connection pool matching the caller's role.
- JWT authentication; passwords hashed with bcrypt (cost 12); 8-hour token expiry.
- Public self-registration as a read-only user.
- Contributor role-request workflow: a read-only user requests an upgrade, an admin
  approves or declines; approval promotes the user. Live role refresh means the change
  takes effect on the user's next page load without a manual re-login.
- Admin protections: admin accounts cannot be deactivated (own or others').

### Auditing & accountability
- Audit log of privileged and lifecycle actions: signups, role changes,
  activations/deactivations, role-request submissions and decisions, ingestion triggers,
  and detection-coverage changes (with before → after).
- Admin "Activity Log" view of the full trail.
- Per-technique detection-coverage attribution.

### Admin & operations
- User management (list, create, change role, activate/deactivate).
- Role-request review with pending queue and resolved history.
- Manual ingestion controls (available to contributors and admins).

---

## Scope & known limitations (for reviewer context)

Deliberately called out so feedback can be targeted:

- **Data sources are all free/public feeds** — no commercial/premium intel.
- **Single-tenant** — no organisation/team separation; detection coverage is one shared
  team-wide value.
- **No rate limiting** on authentication endpoints (`/login`, `/signup`) yet.
- **JWTs stored in browser localStorage**; 8-hour expiry, no refresh-token flow. Role and
  deactivation changes propagate on next page load / token refresh, not instantly.
- **Ingestion run status is in-memory** (lost on server restart); not yet persisted to a
  history table.
- **No automated test suite** yet — including for the access-control model, which is the
  platform's core.
- **No CVE "known-exploited/KEV" flag**, alerting, exports (CSV/PDF), or scheduled
  digests.

---

## Questions worth asking the expert

- Does the coverage-weighted prioritization model (blind techniques weighted double)
  reflect how a real SOC would triage, or is that oversimplified?
- Is database-enforced RBAC (PostgreSQL roles + RLS) the right layer for access control
  here, or overkill versus application-layer checks?
- What's the highest-value missing capability for an analyst's day-to-day workflow?
- Are there data-quality or correlation concerns with linking CVEs to ATT&CK techniques
  from these particular free feeds?
