import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
const derive = promisify(scrypt);
// OWASP's 32 MiB scrypt configuration. Bound expensive concurrent jobs.
export const SCRYPT = Object.freeze({ N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 });
let active = 0;
const waiting = [];
export class HashCapacityError extends Error {
  constructor() { super('Password service busy. Try again shortly.'); this.name = 'HashCapacityError'; }
}
async function job(password, salt) {
  if (active >= 2) {
    if (waiting.length >= 8) throw new HashCapacityError();
    await new Promise(resolve => waiting.push(resolve));
  } else active++;
  try { return await derive(password, salt, 32, SCRYPT); }
  finally { const next = waiting.shift(); if (next) next(); else active--; }
}
function passwordBytes(password) {
  if (typeof password !== 'string' || Buffer.byteLength(password,'utf8') > 1024) throw new Error('Invalid password');
  return Buffer.from(password,'utf8');
}
export async function hashPassword(password) {
  const input = passwordBytes(password), salt = randomBytes(16);
  try {
    const hash = await job(input,salt);
    return `scrypt$32768$8$3$${salt.toString('hex')}$${hash.toString('hex')}`;
  } finally { input.fill(0); }
}
export async function verifyPassword(password, encoded) {
  if (typeof encoded !== 'string' || !/^scrypt\$32768\$8\$3\$[a-f0-9]{32}\$[a-f0-9]{64}$/.test(encoded)) return false;
  const parts = encoded.split('$'), input = passwordBytes(password);
  try {
    const expected = Buffer.from(parts[5],'hex'), actual = await job(input,Buffer.from(parts[4],'hex'));
    return timingSafeEqual(actual,expected);
  } finally { input.fill(0); }
}
