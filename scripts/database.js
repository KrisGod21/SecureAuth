import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectDatabase, exportDatabase } from '../server/database-tools.js';
const root = resolve(dirname(fileURLToPath(import.meta.url)),'..');
const dbPath = process.env.DB_PATH ? resolve(process.env.DB_PATH) : resolve(root,'data','students.sqlite');
try {
  if (process.argv[2] === 'view') {
    const rows = inspectDatabase(dbPath,{storageKey:process.env.STORAGE_KEY,raw:process.argv.includes('--raw')});
    console.log(`SQLite database: ${dbPath}\nUsers: ${rows.length}\nPasswords are salted hashes, not readable passwords.`);
    if (rows.length) console.log(JSON.stringify(rows,null,2));
    else console.log('No accounts yet. Register through the application to create a row.');
  } else if (process.argv[2] === 'export') {
    const result = await exportDatabase({dbPath,storageKey:process.env.STORAGE_KEY,destinationRoot:resolve(root,'private-backups')});
    console.log(`Exported ${result.count} users to:\n${result.folder}\n\nTransfer that private folder separately from GitHub. Follow TRANSFER.txt on the destination laptop.`);
  } else throw new Error('Usage: npm run db:view [-- --raw] or npm run db:export');
} catch (error) { console.error(error.message); process.exitCode=1; }
