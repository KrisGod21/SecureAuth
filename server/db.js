import { DatabaseSync, backup } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import hcads from '../shared/hcads.cjs';
import { hashPassword } from './password-hash.js';
const schema = name => `CREATE TABLE ${name} (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  stdid_ct TEXT NOT NULL UNIQUE,
  name_ct TEXT NOT NULL,
  div_ct TEXT NOT NULL,
  branch_ct TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);`;
export function openDatabase(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA secure_delete=ON;');
  if (!db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='students'").get()) {
    db.exec(schema('students')); db.exec('PRAGMA user_version=3;');
  }
  return {
    raw: db,
    find: username => db.prepare('SELECT * FROM students WHERE username = ?').get(username),
    count: () => db.prepare('SELECT COUNT(*) AS n FROM students').get().n,
    insert: row => db.prepare('INSERT INTO students (id,username,stdid_ct,name_ct,div_ct,branch_ct,password_hash) VALUES (?,?,?,?,?,?,?)').run(row.id,row.username,row.stdid_ct,row.name_ct,row.div_ct,row.branch_ct,row.password_hash),
    close: () => db.close()
  };
}
export async function prepareDatabase(path, storageKey) {
  const db = openDatabase(path);
  try {
    const columns = db.raw.prepare('PRAGMA table_info(students)').all().map(c=>c.name);
    if (columns.includes('pwd_ct')) {
      const rows = db.raw.prepare('SELECT * FROM students').all(), converted = [];
      for (const row of rows) {
        const username = hcads.decrypt(row.stdid_ct,'store:stdid',storageKey);
        const password = hcads.decrypt(row.pwd_ct,`store:${row.id}:pwd`,storageKey);
        converted.push({ ...row, username, password_hash: await hashPassword(password) });
      }
      if (path !== ':memory:') {
        const folder = join(dirname(path),'backups'); mkdirSync(folder,{recursive:true});
        await backup(db.raw,join(folder,`before-password-hashes-${Date.now()}-${randomUUID()}.sqlite`));
      }
      db.raw.exec('BEGIN IMMEDIATE;');
      try {
        db.raw.exec(schema('students_v3'));
        const insert = db.raw.prepare('INSERT INTO students_v3 (id,username,stdid_ct,name_ct,div_ct,branch_ct,password_hash,created_at) VALUES (?,?,?,?,?,?,?,?)');
        for (const row of converted) insert.run(row.id,row.username,row.stdid_ct,row.name_ct,row.div_ct,row.branch_ct,row.password_hash,row.created_at);
        db.raw.exec('DROP TABLE students; ALTER TABLE students_v3 RENAME TO students; PRAGMA user_version=3; COMMIT;');
      } catch (error) { db.raw.exec('ROLLBACK;'); throw error; }
      db.raw.exec('PRAGMA wal_checkpoint(TRUNCATE); VACUUM;');
    }
    const first = db.raw.prepare('SELECT username,stdid_ct FROM students LIMIT 1').get();
    if (first && hcads.decrypt(first.stdid_ct,'store:stdid',storageKey) !== first.username) throw new Error('Storage key does not match this database.');
    return db;
  } catch (error) { db.close(); throw error; }
}
