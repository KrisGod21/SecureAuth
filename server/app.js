import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { randomBytes, generateKeyPairSync, createPublicKey, diffieHellman, hkdfSync, timingSafeEqual, createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import hcads from '../shared/hcads.cjs';
import { prepareDatabase } from './db.js';
import { generatePassword } from './password.js';
import { hashPassword, verifyPassword, HashCapacityError } from './password-hash.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const token = () => randomBytes(32).toString('base64url');
const tokenHash = s => createHash('sha256').update(s).digest('hex');
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); };
const fields = ['stdid', 'name', 'div', 'branch'];
export async function createApp({ storageKey, dbPath = path.join(root, 'data', 'students.sqlite'), origin = 'http://localhost:3000', production = false, apiKey, passwordGenerator = generatePassword, clock = Date.now } = {}) {
  if (!/^[a-fA-F0-9]{64}$/.test(storageKey || '')) throw new Error('Set STORAGE_KEY to a random 64-character hexadecimal key. Run npm run setup.');
  const configured = new URL(origin);
  if (production && configured.protocol !== 'https:') throw new Error('Production requires an HTTPS APP_ORIGIN.');
  if (!production && !['localhost', '127.0.0.1', '[::1]'].includes(configured.hostname)) throw new Error('HTTP development is restricted to loopback. Configure production HTTPS for remote use.');
  const db = await prepareDatabase(dbPath,storageKey), app = express();
  const dummyPasswordHash = await hashPassword(randomBytes(32).toString('hex'));
  const channels = new Map(), sessions = new Map(), accountAttempts = new Map();
  const cookieOptions = { httpOnly: true, secure: production, sameSite: 'strict', path: '/' };
  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'data:'],
    connectSrc: ["'self'"], fontSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'none'"], frameAncestors: ["'none'"],
    formAction: ["'self'"], upgradeInsecureRequests: production ? [] : null
  } }, strictTransportSecurity: production ? undefined : false, crossOriginEmbedderPolicy: false }));
  // Do not trust arbitrary proxy headers. Configure a known reverse proxy separately for production.
  app.use((req, res, next) => {
    if (req.headers.host !== configured.host) return res.status(403).json({ error: 'Untrusted host.' });
    next();
  });
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.get('sec-fetch-site') === 'cross-site') return res.status(403).json({ error: 'Request rejected.' });
    if (req.method !== 'GET' && req.get('origin') !== configured.origin) return res.status(403).json({ error: 'Request rejected.' });
    if (req.method === 'POST' && !req.is('application/json')) return res.status(415).json({ error: 'JSON required.' });
    next();
  });
  app.use('/api', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many requests. Try again shortly.' } }));
  app.use(express.json({ limit: '16kb', strict: true }));
  app.use(cookieParser());
  const authLimit = rateLimit({ windowMs: 15 * 60_000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many attempts. Please wait 15 minutes.' } });
  function cleanup() {
    const now = clock();
    for (const [id, c] of channels) if (c.expires <= now) { c.key = ''; channels.delete(id); }
    for (const [id, s] of sessions) if (s.expires <= now) sessions.delete(id);
    for (const [id, s] of accountAttempts) if (s.expires <= now) accountAttempts.delete(id);
  }
  const timer = setInterval(cleanup, 30_000); timer.unref();
  function channel(req, res, next) {
    cleanup();
    const c = channels.get(tokenHash(req.cookies.ac_channel || ''));
    if (!c || c.expires <= clock()) return res.status(401).json({ error: 'Secure channel expired. Refresh the page.' });
    req.channel = c; next();
  }
  function challenge(req, action) {
    const c = req.channel, nonce = req.body?.challenge;
    const saved = c.challenges.get(nonce);
    // Consume before cryptographic processing, including failed requests.
    c.challenges.delete(nonce);
    if (!saved || saved.action !== action || saved.expires <= clock()) throw new Error('Invalid request');
    return nonce;
  }
  function read(req, nonce, action, names) {
    if (!req.body.fields || Object.keys(req.body.fields).sort().join(',') !== names.slice().sort().join(',')) throw new Error();
    const values = {};
    for (const name of names) {
      const label = `request:${action}:${nonce}:${name}`;
      values[name] = hcads.open(req.body.fields[name], label, req.channel.key);
      if (!same(hcads.hash(hcads.encrypt(values[name], label, req.channel.key)), req.body.fields[name].digest)) throw new Error();
    }
    return values;
  }
  function normalize(v) {
    const out = {
      stdid: v.stdid.trim().toUpperCase(), name: v.name.trim().normalize('NFC'),
      div: v.div.trim().toUpperCase(), branch: v.branch.trim().toUpperCase()
    };
    if (!/^[A-Z0-9][A-Z0-9_-]{2,31}$/.test(out.stdid) || out.name.length < 2 || out.name.length > 80 || /[\p{Cc}\p{Cf}]/u.test(out.name) || !/^[A-Z0-9-]{1,8}$/.test(out.div) || !['CSE','IT','ECE','EEE','MECH','CIVIL','AI-DS'].includes(out.branch)) throw new Error('validation');
    return out;
  }
  app.get('/api/health', (req, res) => res.json({ status: 'ok', algorithm: 'HC-ADS v2', passwordStorage: 'salted-scrypt', database: 'sqlite', mode: 'educational', quantumConfigured: Boolean(apiKey) }));
  app.post('/api/channel', authLimit, (req, res) => {
    try {
      cleanup(); if (channels.size >= 1000) return res.status(503).json({ error: 'Capacity reached. Try again later.' });
      const jwk = req.body.publicKey;
      if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.d || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') throw new Error();
      const peer = createPublicKey({ key: jwk, format: 'jwk' });
      const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const salt = token(), cookie = token();
      const secret = diffieHellman({ privateKey, publicKey: peer });
      const key = Buffer.from(hkdfSync('sha256', secret, Buffer.from(salt), Buffer.from('AC-channel-v2'), 32)).toString('hex');
      secret.fill(0);
      const previous = tokenHash(req.cookies.ac_channel || '');
      channels.delete(previous);
      channels.set(tokenHash(cookie), { key, challenges: new Map(), expires: clock() + 10 * 60_000 });
      res.cookie('ac_channel', cookie, { ...cookieOptions, maxAge: 10 * 60_000 });
      res.json({ publicKey: publicKey.export({ format: 'jwk' }), salt, expiresIn: 600 });
    } catch { res.status(400).json({ error: 'Channel setup failed.' }); }
  });
  app.post('/api/challenge', channel, (req, res) => {
    const action = req.body.action;
    if (!['register', 'login', 'profile', 'logout'].includes(action)) return res.status(400).json({ error: 'Invalid action.' });
    const c = req.channel;
    for (const [nonce, s] of c.challenges) if (s.expires <= clock()) c.challenges.delete(nonce);
    if (c.challenges.size >= 8) return res.status(429).json({ error: 'Too many pending requests.' });
    const nonce = token(); c.challenges.set(nonce, { action, expires: clock() + 60_000 });
    res.json({ challenge: nonce, expiresIn: 60 });
  });
  app.post('/api/register', authLimit, channel, async (req, res) => {
    try {
      const nonce = challenge(req, 'register'), v = normalize(read(req, nonce, 'register', fields));
      const stdid_ct = hcads.encrypt(v.stdid, 'store:stdid', storageKey);
      if (db.find(v.stdid)) return res.status(409).json({ error: 'Registration could not be completed. If you already registered, sign in.' });
      if (db.count() >= 1000) return res.status(503).json({ error: 'This lab has reached its 1000 account limit.' });
      const generated = await passwordGenerator({ apiKey });
      const id = randomBytes(16).toString('hex'), row = { id, username: v.stdid, stdid_ct };
      for (const field of ['name','div','branch']) row[`${field}_ct`] = hcads.encrypt(v[field], `store:${id}:${field}`, storageKey);
      row.password_hash = await hashPassword(generated.password);
      const reply = hcads.seal(generated.password, `response:register:${nonce}:pwd`, req.channel.key);
      if (db.count() >= 1000) return res.status(503).json({ error: 'This lab has reached its 1000 account limit.' });
      db.insert(row);
      res.status(201).json({ ack: true, password: reply, randomness: generated.source });
    } catch (e) {
      if (e instanceof HashCapacityError) return res.status(429).json({ error: e.message });
      if (e.message === 'validation') return res.status(400).json({ error: 'Check student ID, name, division and branch formats.' });
      if (e.errcode === 2067 || String(e.code || '').includes('CONSTRAINT')) return res.status(409).json({ error: 'Registration could not be completed. If you already registered, sign in.' });
      res.status(400).json({ error: 'Registration rejected. Check your details and retry with a fresh request.' });
    }
  });
  app.post('/api/login', authLimit, channel, async (req, res) => {
    try {
      const nonce = challenge(req, 'login'), v = read(req, nonce, 'login', ['stdid','pwd']);
      const stdid = v.stdid.trim().toUpperCase();
      if (!/^[A-Z0-9][A-Z0-9_-]{2,31}$/.test(stdid) || v.pwd.length > 128) throw new Error();
      const key = tokenHash(stdid);
      const attempt = accountAttempts.get(key) || { count: 0, expires: clock() + 15 * 60_000 };
      if (attempt.count >= 10) return res.status(429).json({ error: 'Sign-in temporarily unavailable. Try again in 15 minutes.' });
      // Reserve the attempt before awaiting the slow hash to prevent races.
      attempt.count++; accountAttempts.set(key, attempt);
      if (accountAttempts.size > 10000) accountAttempts.delete(accountAttempts.keys().next().value);
      const row = db.find(stdid);
      const valid = await verifyPassword(v.pwd,row?.password_hash || dummyPasswordHash);
      if (!valid || !row) {
        throw new Error();
      }
      accountAttempts.delete(key);
      sessions.delete(tokenHash(req.cookies.ac_session || ''));
      cleanup(); if (sessions.size >= 1000) return res.status(503).json({ error: 'Capacity reached. Try later.' });
      const cookie = token(); sessions.set(tokenHash(cookie), { username: stdid, expires: clock() + 30 * 60_000 });
      res.cookie('ac_session', cookie, { ...cookieOptions, maxAge: 30 * 60_000 });
      res.json({ result: hcads.seal('authenticated', `response:login:${nonce}:result`, req.channel.key), expiresIn: 1800 });
    } catch (error) {
      if (error instanceof HashCapacityError) return res.status(429).json({ error: error.message });
      res.status(401).json({ error: 'Invalid credentials or request.' });
    }
  });
  function authenticated(req, res, next) {
    cleanup(); const s = sessions.get(tokenHash(req.cookies.ac_session || ''));
    if (!s || s.expires <= clock()) return res.status(401).json({ error: 'Session expired. Please sign in.' });
    req.auth = s; next();
  }
  app.post('/api/profile', channel, authenticated, (req, res) => {
    try {
      const nonce = challenge(req, 'profile'); read(req, nonce, 'profile', ['proof']);
      const row = db.find(req.auth.username); if (!row) throw new Error();
      const out = { stdid: hcads.decrypt(row.stdid_ct, 'store:stdid', storageKey) };
      for (const f of ['name','div','branch']) out[f] = hcads.decrypt(row[`${f}_ct`], `store:${row.id}:${f}`, storageKey);
      res.json({ profile: hcads.seal(JSON.stringify(out), `response:profile:${nonce}:profile`, req.channel.key) });
    } catch { res.status(400).json({ error: 'Profile request rejected.' }); }
  });
  app.post('/api/logout', channel, (req, res) => {
    try {
      const nonce = challenge(req, 'logout'); read(req, nonce, 'logout', ['proof']);
      sessions.delete(tokenHash(req.cookies.ac_session || ''));
      res.clearCookie('ac_session', cookieOptions);
      res.json({ result: hcads.seal('signed-out', `response:logout:${nonce}:result`, req.channel.key) });
    } catch { res.status(400).json({ error: 'Sign-out request rejected.' }); }
  });
  app.get('/vendor/crypto-js.js', (req,res) => res.sendFile(path.join(root, 'node_modules/crypto-js/crypto-js.js')));
  app.get('/vendor/qrcode.js', (req,res) => res.sendFile(path.join(root, 'public/vendor/qrcode.js')));
  app.get('/shared/hcads.js', (req,res) => res.type('application/javascript').sendFile(path.join(root, 'shared/hcads.cjs')));
  app.get('/report', (req,res) => res.download(path.join(root, 'docs/AC_Algorithm_and_Application.docx')));
  app.use(express.static(path.join(root, 'public'), { dotfiles: 'deny' }));
  app.use((req,res) => res.status(404).json({ error: 'Not found.' }));
  app.use((err, req, res, next) => res.status(err.type === 'entity.too.large' ? 413 : 400).json({ error: 'Invalid request.' }));
  return { app, db, close: () => { clearInterval(timer); channels.clear(); sessions.clear(); db.close(); } };
}
