/**
 * Migration 007 — Role Requests
 *
 * DB Concept: Access Control (self-service privilege escalation with approval)
 *
 * Read-only users can request an upgrade to the `contributor` role. Each
 * request is recorded here as a pending row; an admin then approves or
 * declines it. On approval the API bumps the user's `role` to contributor.
 *
 * One open (pending) request per user is enforced with a partial unique index.
 */

exports.up = async function (knex) {
  await knex.schema.createTable('role_requests', (t) => {
    t.increments('id');
    t.integer('user_id')
      .notNullable()
      .references('id').inTable('users').onDelete('CASCADE');
    t.enu('requested_role', ['contributor']).notNullable().defaultTo('contributor');
    t.enu('status', ['pending', 'approved', 'declined']).notNullable().defaultTo('pending');
    t.string('decided_by', 255);          // admin email that resolved the request
    t.timestamp('decided_at');
    t.timestamps(true, true);             // created_at, updated_at
  });

  // At most one pending request per user.
  await knex.raw(`
    CREATE UNIQUE INDEX role_requests_one_pending_per_user
      ON role_requests (user_id)
      WHERE status = 'pending';
  `);

  // The admin role owns and manages this table; align grants with migration 006.
  await knex.raw(`
    GRANT ALL ON role_requests TO threat_admin;
    GRANT USAGE, SELECT ON SEQUENCE role_requests_id_seq TO threat_admin;
  `);
};

exports.down = async function (knex) {
  await knex.schema.dropTableIfExists('role_requests');
};
