/**
 * audit.js — Write entries to the audit_log table.
 *
 * Auditing must never break the action being audited, so failures here are
 * logged and swallowed rather than thrown.
 *
 * Usage (inside an admin route, where `db = getPool('admin')`):
 *   await logAudit(db, req, {
 *     action: 'user.role_changed',
 *     targetType: 'user',
 *     targetId: userId,
 *     detail: { from: 'readonly', to: 'contributor' },
 *   });
 */

async function logAudit(db, req, { action, targetType, targetId, detail = {} }) {
  try {
    await db('audit_log').insert({
      actor_id:    req?.user?.id ?? null,
      actor_email: req?.user?.email ?? null,
      action,
      target_type: targetType ?? null,
      target_id:   targetId != null ? String(targetId) : null,
      detail:      JSON.stringify(detail),
    });
  } catch (err) {
    console.error(`[audit] failed to record "${action}":`, err.message);
  }
}

module.exports = { logAudit };
