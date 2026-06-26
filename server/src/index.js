/**
 * index.js — Express Server Entry Point
 *
 * Boots the API server and registers all routes under /api/v1.
 * Also starts the ingestion scheduler so feeds run on a cron.
 *
 * Start with: node src/index.js  (or: npm run dev)
 */

require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });

const express = require('express');
const cors    = require('cors');

const { errorHandler } = require('./middleware/common');
const { startScheduler } = require('./ingestion/scheduler');

// ── Route modules ─────────────────────────────────────────────────────────────
const authRoutes         = require('./routes/auth.routes');
const cveRoutes          = require('./routes/cves.routes');
const techniqueRoutes    = require('./routes/techniques.routes');
const iocRoutes          = require('./routes/iocs.routes');
const threatActorRoutes  = require('./routes/threatActors.routes');
const dashboardRoutes    = require('./routes/dashboard.routes');
const adminRoutes        = require('./routes/admin.routes');

// ── App setup ─────────────────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3001;

app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:5173',
  credentials: true,
}));
app.use(express.json());

// ── Health check (unauthenticated) ────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ status: 'ok', ts: new Date() }));

// ── API routes ────────────────────────────────────────────────────────────────
app.use('/api/v1/auth',          authRoutes);
app.use('/api/v1/dashboard',     dashboardRoutes);
app.use('/api/v1/cves',          cveRoutes);
app.use('/api/v1/techniques',    techniqueRoutes);
app.use('/api/v1/iocs',          iocRoutes);
app.use('/api/v1/threat-actors', threatActorRoutes);
app.use('/api/v1/admin',         adminRoutes);

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));

// ── Global error handler (must be last) ───────────────────────────────────────
app.use(errorHandler);

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[${new Date().toISOString()}] API server running on http://localhost:${PORT}`);
  console.log(`[${new Date().toISOString()}] Environment: ${process.env.NODE_ENV || 'development'}`);

  // Start ingestion cron (only in non-test environments)
  if (process.env.NODE_ENV !== 'test') {
    startScheduler();
  }
});

module.exports = app; // for testing
