require('dotenv').config({ path: require('path').resolve(__dirname, '../../../.env') });

/**
 * Knex configuration.
 * Three connection pools — one per PostgreSQL role — are exported so the API
 * layer can attach the right role to each request based on the JWT claim.
 *
 * The `admin` pool is used exclusively by migrations and seeding.
 * The `contributor` pool is used by ingestion scripts.
 * The `readonly` pool is used by analyst-facing read endpoints.
 */

const base = {
  client: 'pg',
  pool: { min: 2, max: 10 },
  migrations: {
    directory: './migrations',
    tableName:  'knex_migrations',
  },
  seeds: {
    directory: './seeds',
  },
};

module.exports = {
  // ── Default (used by `knex migrate:latest`) ────────────
  development: {
    ...base,
    connection: {
      host:     process.env.PG_HOST     || 'localhost',
      port:     process.env.PG_PORT     || 5432,
      database: process.env.PG_DATABASE || 'threat_intel',
      user:     process.env.PG_USER     || 'threat_admin',
      password: process.env.PG_PASSWORD,
    },
  },

  production: {
    ...base,
    connection: {
      host:     process.env.PG_HOST,
      port:     process.env.PG_PORT,
      database: process.env.PG_DATABASE,
      user:     process.env.PG_USER,
      password: process.env.PG_PASSWORD,
      ssl:      { rejectUnauthorized: false },
    },
    pool: { min: 2, max: 20 },
  },
};
