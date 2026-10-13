import { randomBytes } from 'node:crypto';
import { writeFileSync, existsSync, mkdirSync } from 'node:fs';
if (!existsSync('.env')) {
  writeFileSync('.env', `STORAGE_KEY=${randomBytes(32).toString('hex')}\nPORT=3000\nHOST=127.0.0.1\nAPP_ORIGIN=http://localhost:3000\nNODE_ENV=development\nANU_QRNG_KEY=\n`, { flag: 'wx', mode: 0o600 });
  console.log('Created .env with a random storage key. Back up this file privately; losing it makes stored records unreadable.');
} else console.log('.env already exists; preserved the existing key.');
mkdirSync('data', { recursive: true });
