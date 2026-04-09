const BLOCKED_HOSTS = ['localhost', '127.0.0.1', '[::1]', '0.0.0.0', '0', '[::ffff:127.0.0.1]'];
const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^fc00:/i,
  /^fe80:/i,
  /^::ffff:/i,
  /^::1$/,
  /^0\./,
  /^127\./,
];

/**
 * Check if a hostname looks like an IP address (decimal, hex, or IPv6).
 * Blocks numeric-only hostnames (e.g., 2130706433 = 127.0.0.1 in decimal).
 */
function isNumericHost(hostname: string): boolean {
  return /^\d+$/.test(hostname) || /^0x[0-9a-f]+$/i.test(hostname) || /^0[0-7]+$/.test(hostname);
}

export function isUrlSafe(urlString: string): boolean {
  try {
    const url = new URL(urlString);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    if (BLOCKED_HOSTS.includes(hostname)) return false;
    if (PRIVATE_RANGES.some(r => r.test(hostname))) return false;
    if (hostname.endsWith('.internal') || hostname.endsWith('.local')) return false;
    if (isNumericHost(hostname)) return false;
    if (url.port && !['80', '443', ''].includes(url.port)) return false;
    return true;
  } catch {
    return false;
  }
}
