import { DatabaseSync, backup } from 'node:sqlite';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import hcads from '../shared/hcads.cjs';

function readableDatabase(path) {
  if (!existsSync(path)) throw new Error('Database not found. Start the app and register an account first.');
  const db = new DatabaseSync(path,{readOnly:true});
  const columns = db.prepare('PRAGMA table_info(students)').all().map(c=>c.name);
  if (!columns.includes('password_hash')) { db.close(); throw new Error('Start the updated app once to migrate this database.'); }
  return db;
}
export function inspectDatabase(path, { storageKey, raw = false } = {}) {
  const db = readableDatabase(path);
  try {
    const rows = db.prepare('SELECT * FROM students ORDER BY created_at,id').all();
    if (raw) return rows.map(row=>({...row}));
    return rows.map(row=>({
      username: row.username,
      name: storageKey ? hcads.decrypt(row.name_ct,`store:${row.id}:name`,storageKey) : '[encrypted]',
      division: storageKey ? hcads.decrypt(row.div_ct,`store:${row.id}:div`,storageKey) : '[encrypted]',
      branch: storageKey ? hcads.decrypt(row.branch_ct,`store:${row.id}:branch`,storageKey) : '[encrypted]',
      password_hash: row.password_hash,
      created_at: row.created_at
    }));
  } finally { db.close(); }
}
export async function exportDatabase({ dbPath, storageKey, destinationRoot }) {
  if (!/^[a-fA-F0-9]{64}$/.test(storageKey || '')) throw new Error('Load the original STORAGE_KEY before exporting existing accounts.');
  const db = readableDatabase(dbPath);
  try {
    const first = db.prepare('SELECT username,stdid_ct FROM students LIMIT 1').get();
    if (first && hcads.decrypt(first.stdid_ct,'store:stdid',storageKey) !== first.username) throw new Error('Storage key does not match the database.');
    const folder = resolve(destinationRoot,`transfer-${Date.now()}-${randomUUID()}`);
    mkdirSync(join(folder,'data'),{recursive:true,mode:0o700});
    await backup(db,join(folder,'data','students.sqlite'));
    writeFileSync(join(folder,'.env'),`STORAGE_KEY=${storageKey}\nPORT=3000\nHOST=127.0.0.1\nAPP_ORIGIN=http://localhost:3000\nNODE_ENV=development\nANU_QRNG_KEY=\n`,{flag:'wx',mode:0o600});
    writeFileSync(join(folder,'TRANSFER.txt'),
      'PRIVATE ACCOUNT TRANSFER\n\nThis folder contains the profile decryption key and user records. Do not upload it to GitHub or a public website.\n\nOn the other laptop: install Node.js 24+, clone/download SecureAuth, run npm ci, and stop any running app. Copy this .env into the fresh project root and data/students.sqlite into its data folder. Then run npm run setup and npm start. Existing passwords still work. Do not overwrite a different existing database or key.\n\nANU API credentials were not included. Configure your own optional key. Active login sessions are not transferred; sign in again.\n',
      {flag:'wx',mode:0o600});
    return { folder, count: db.prepare('SELECT COUNT(*) AS n FROM students').get().n };
  } finally { db.close(); }
}
