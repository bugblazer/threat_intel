/**
 * logger.js — Minimal structured logger for ingestion scripts.
 * Prefixes every line with a timestamp and the source feed name
 * so interleaved output from parallel runs stays readable.
 */

function makeLogger(source) {
  const prefix = () => `[${new Date().toISOString()}] [${source}]`;
  return {
    info:  (...args) => console.log(prefix(), ...args),
    warn:  (...args) => console.warn(prefix(), '⚠', ...args),
    error: (...args) => console.error(prefix(), '✖', ...args),
    done:  (...args) => console.log(prefix(), '✔', ...args),
  };
}

module.exports = { makeLogger };
