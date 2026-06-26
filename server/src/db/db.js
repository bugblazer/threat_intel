const knex = require('knex');
require('dotenv').config({ path: require('path').resolve(__dirname, '../../../.env') });

/**
 * db.js — Role-aware connection pools
 *
 * Usage in route handlers:
 *   const { getPool } = require('../db/db');
 *   const db = getPool(req.user.role);   // req.user set by JWT middleware
 *   const rows = await db('cves').where({ cve_id: id });
 */

function makePool(user, password) {
  return knex({
    client: 'pg',
    connection: {
      host:     process.env.PG_HOST     || 'localhost',
      port:     Number(process.env.PG_PORT) || 5432,
      database: process.env.PG_DATABASE || 'threat_intel',
      user,
      password,
    },
    pool: { min: 1, max: 10 },
  });
}

const pools = {
  admin:       makePool(process.env.PG_USER,             process.env.PG_PASSWORD),
  contributor: makePool(process.env.PG_CONTRIBUTOR_USER, process.env.PG_CONTRIBUTOR_PASSWORD),
  readonly:    makePool(process.env.PG_READONLY_USER,    process.env.PG_READONLY_PASSWORD),
};

/**
 * Returns the correct Knex pool for a given JWT role.
 * Falls back to readonly for any unrecognised role — safe default.
 */
function getPool(role) {
  return pools[role] ?? pools.readonly;
}

module.exports = { getPool, pools };
