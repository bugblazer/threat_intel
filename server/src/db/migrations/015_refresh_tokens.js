/**
 * Migration 015 — Refresh tokens
 *
 * Sessions used to be a single 8-hour JWT kept in localStorage, readable by any
 * script on the page and impossible to revoke. Now the API issues a 15-minute
 * access token (kept in memory by the client) plus a refresh token in an
 * httpOnly cookie.
 *
 * Only a SHA-256 hash of each refresh token is stored. Tokens rotate on every
 * use; `family_id` groups the chain from one login, so if an old (already
 * rotated) token is ever presented again, the whole family is revoked: someone
 * copied it. `family_expires_at` caps a session at 30 days no matter how often
 * it is refreshed.
 *
 * Only the admin pool touches this table (like `users`).
 */

exports.up = async function (knex) {
  await knex.schema.createTable('refresh_tokens', (t) => {
    t.increments('id');
    t.integer('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    t.string('token_hash', 64).notNullable().unique();
    t.uuid('family_id').notNullable();
    t.timestamp('expires_at').notNullable();
    t.timestamp('family_expires_at').notNullable();
    t.timestamp('created_at').notNullable().defaultTo(knex.fn.now());
    t.timestamp('revoked_at');
    t.string('user_agent', 255);
  });

  await knex.raw(`
    CREATE INDEX refresh_tokens_user_idx   ON refresh_tokens (user_id);
    CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

    GRANT ALL ON refresh_tokens TO threat_admin;
    GRANT USAGE, SELECT ON SEQUENCE refresh_tokens_id_seq TO threat_admin;
  `);
};

exports.down = async function (knex) {
  await knex.schema.dropTableIfExists('refresh_tokens');
};
