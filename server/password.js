import { randomBytes, hkdfSync } from 'node:crypto';
export const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*?';
export async function quantumBytes(apiKey, fetchFn = fetch) {
  if (!apiKey) return { bytes: null, source: 'csprng-only' };
  try {
    const response = await fetchFn('https://api.quantumnumbers.anu.edu.au/?length=64&type=uint8', {
      headers: { 'x-api-key': apiKey }, signal: AbortSignal.timeout(3500), redirect: 'error'
    });
    if (!response.ok) throw new Error();
    const json = await response.json();
    if (json.success !== true || !Array.isArray(json.data) || json.data.length !== 64 || !json.data.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) throw new Error();
    return { bytes: Buffer.from(json.data), source: 'csprng+anu-qrng' };
  } catch { return { bytes: null, source: 'csprng-only-fallback' }; }
}
export async function generatePassword({ apiKey, fetchFn, random = randomBytes } = {}) {
  const quantum = await quantumBytes(apiKey, fetchFn);
  const local = random(64);
  const mixed = Buffer.from(local);
  if (quantum.bytes) for (let i = 0; i < mixed.length; i++) mixed[i] ^= quantum.bytes[i];
  const limit = Math.floor(256 / CHARSET.length) * CHARSET.length;
  for (let counter = 0; counter < 10000; counter++) {
    const stream = Buffer.from(hkdfSync('sha256', mixed, Buffer.from('HCADS-password-v2'), Buffer.from(`password:${counter}`), 128));
    let password = '';
    for (const b of stream) { if (b < limit) password += CHARSET[b % CHARSET.length]; if (password.length === 16) break; }
    if (password.length === 16 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password) && /[!@#$%&*?]/.test(password)) {
      local.fill(0); mixed.fill(0); quantum.bytes?.fill(0);
      return { password, source: quantum.source };
    }
  }
  throw new Error('Password generation failed');
}
