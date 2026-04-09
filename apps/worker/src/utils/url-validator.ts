const BLOCKED_HOSTS = ['localhost', '127.0.0.1', '[::1]', '0.0.0.0'];
const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^fc00:/i,
  /^fe80:/i,
];

export function isUrlSafe(urlString: string): boolean {
  try {
    const url = new URL(urlString);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return false;
    const hostname = url.hostname.replace(/^\[|\]$/g, '');
    if (BLOCKED_HOSTS.includes(hostname)) return false;
    if (PRIVATE_RANGES.some(r => r.test(hostname))) return false;
    if (hostname.endsWith('.internal') || hostname.endsWith('.local')) return false;
    return true;
  } catch {
    return false;
  }
}
