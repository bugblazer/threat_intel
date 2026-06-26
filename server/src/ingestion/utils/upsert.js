/**
 * upsert.js
 *
 * Generic batch upsert using Knex + PostgreSQL ON CONFLICT DO UPDATE.
 * All ingestion scripts use this so we never insert duplicates on re-runs.
 *
 * Usage:
 *   await batchUpsert(db, 'cves', rows, ['cve_id'], logger);
 *
 * @param {import('knex').Knex} db          - Knex instance (contributor pool)
 * @param {string}              table        - Target table name
 * @param {object[]}            rows         - Array of row objects
 * @param {string[]}            conflictCols - Columns that form the unique key
 * @param {object}              [log]        - Logger instance
 * @param {number}              [chunkSize]  - Rows per INSERT (default 500)
 */
async function batchUpsert(db, table, rows, conflictCols, log, chunkSize = 500) {
  if (!rows.length) {
    log?.info(`  upsert skipped — no rows for ${table}`);
    return { inserted: 0, updated: 0 };
  }

  let total = 0;

  for (let i = 0; i < rows.length; i += chunkSize) {
    const chunk = rows.slice(i, i + chunkSize);

    // Get all column names from the first row
    const allCols = Object.keys(chunk[0]);

    // Columns to update on conflict (everything except the conflict key)
    const updateCols = allCols.filter(c => !conflictCols.includes(c));

    await db(table)
      .insert(chunk)
      .onConflict(conflictCols)
      .merge(updateCols.length ? updateCols : undefined);

    total += chunk.length;
    log?.info(`  upserted ${total}/${rows.length} rows into ${table}`);
  }

  return { total };
}

module.exports = { batchUpsert };
