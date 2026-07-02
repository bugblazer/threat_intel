#!/usr/bin/env bash
# setup-db.sh — Run once to bootstrap the database from scratch.
# Usage: bash scripts/setup-db.sh
#
# Prerequisites:
#   • PostgreSQL 14+ installed and running
#   • psql available on PATH
#   • .env file present at project root (copy from .env.example)

set -euo pipefail

# ── Load .env ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/../.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo ".env not found. Copy .env.example → .env and fill in values."
  exit 1
fi

source <(grep -v '^#' "$ENV_FILE" | grep -v '^\s*$' | sed 's/ #.*//')

DB="${PG_DATABASE:-threat_intel}"
ADMIN_USER="${PG_USER:-threat_admin}"
ADMIN_PASS="${PG_PASSWORD:-changeme}"
READONLY_USER="${PG_READONLY_USER:-threat_readonly}"
READONLY_PASS="${PG_READONLY_PASSWORD:-changeme_readonly}"
CONTRIB_USER="${PG_CONTRIBUTOR_USER:-threat_contributor}"
CONTRIB_PASS="${PG_CONTRIBUTOR_PASSWORD:-changeme_contributor}"

echo "Setting up PostgreSQL database: $DB"

# ── Create login users (with passwords) ─────────────────────────────────────
psql -U postgres -v ON_ERROR_STOP=1 postgres <<SQL
-- Admin/owner
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$ADMIN_USER') THEN
    CREATE ROLE "$ADMIN_USER" LOGIN PASSWORD '$ADMIN_PASS' CREATEDB BYPASSRLS;
    RAISE NOTICE 'Created role $ADMIN_USER';
  ELSE
    ALTER ROLE "$ADMIN_USER" LOGIN PASSWORD '$ADMIN_PASS' BYPASSRLS;
    RAISE NOTICE 'Updated role $ADMIN_USER';
  END IF;
END
\$\$;

-- Readonly analyst
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$READONLY_USER') THEN
    CREATE ROLE "$READONLY_USER" LOGIN PASSWORD '$READONLY_PASS';
    RAISE NOTICE 'Created role $READONLY_USER';
  ELSE
    ALTER ROLE "$READONLY_USER" LOGIN PASSWORD '$READONLY_PASS';
  END IF;
END
\$\$;

-- Ingestion contributor
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$CONTRIB_USER') THEN
    CREATE ROLE "$CONTRIB_USER" LOGIN PASSWORD '$CONTRIB_PASS';
    RAISE NOTICE 'Created role $CONTRIB_USER';
  ELSE
    ALTER ROLE "$CONTRIB_USER" LOGIN PASSWORD '$CONTRIB_PASS';
  END IF;
END
\$\$;

-- Create database owned by admin
SELECT 'CREATE DATABASE "$DB" OWNER "$ADMIN_USER"'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB')\gexec
SQL

echo "✅  Roles and database created."

# ── Run Knex migrations ──────────────────────────────────────────────────────
echo "Running migrations..."
cd "$SCRIPT_DIR/../server"
npm run migrate

echo ""
echo "Database setup complete!"
echo ""
echo "Connection strings for reference:"
echo "  Admin:       postgres://$ADMIN_USER:***@localhost:5432/$DB"
echo "  Readonly:    postgres://$READONLY_USER:***@localhost:5432/$DB"
echo "  Contributor: postgres://$CONTRIB_USER:***@localhost:5432/$DB"
