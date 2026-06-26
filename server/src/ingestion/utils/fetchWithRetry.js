/**
 * fetchWithRetry.js
 *
 * Wraps node-fetch with:
 *   - Configurable timeout (default 30s)
 *   - Exponential backoff retry (default 3 attempts)
 *   - Non-2xx response → thrown Error with status code
 */

const fetch = (...args) =>
  import('node-fetch').then(({ default: f }) => f(...args));

/**
 * @param {string} url
 * @param {object} [options]
 * @param {Record<string,string>} [options.headers]
 * @param {number} [options.timeoutMs=30000]
 * @param {number} [options.retries=3]
 * @param {number} [options.backoffMs=1000]   base delay; doubles each attempt
 * @returns {Promise<Response>}
 */
async function fetchWithRetry(url, {
  headers    = {},
  timeoutMs  = 30_000,
  retries    = 3,
  backoffMs  = 1_000,
} = {}) {
  let lastError;

  for (let attempt = 1; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(url, { headers, signal: controller.signal });
      clearTimeout(timer);

      if (!res.ok) {
        throw new Error(`HTTP ${res.status} ${res.statusText} — ${url}`);
      }
      return res;
    } catch (err) {
      clearTimeout(timer);
      lastError = err;

      if (attempt < retries) {
        const delay = backoffMs * 2 ** (attempt - 1);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }

  throw lastError;
}

module.exports = { fetchWithRetry };
