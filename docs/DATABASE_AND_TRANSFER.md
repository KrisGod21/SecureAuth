# SQLite database and moving to another laptop

The Express backend stores accounts in `data/students.sqlite` in the project folder. There is no separate database server to install. Use Node.js 24 or newer on Windows, macOS or Linux.

The student ID is the username. The `students` table contains a readable `username`, a salted `password_hash`, encrypted profile fields, a random record ID and a timestamp. Passwords are hashed using native scrypt with N=32768, r=8, p=3, a fresh 16-byte salt and a 32-byte result. No plaintext or reversible encrypted password is stored in the current table. SHA-256 ciphertext fingerprints used by the lab are separate from password hashing.

## View the stored data without installing a database tool

From the project folder, run:

```powershell
npm run db:view
```

This prints usernames, decrypted profile information, stored password hashes and registration timestamps locally. It never prints a plaintext password or storage key. To see the exact stored ciphertext columns, run:

```powershell
npm run db:view -- --raw
```

Register an account in the browser first if the table is empty. These commands are local administrative tools; there is no publicly exposed endpoint listing all users or password hashes.

## Open the SQLite file in a graphical viewer

1. Stop the app with Ctrl+C in its terminal before editing the database.
2. Open a trusted SQLite viewer, such as DB Browser for SQLite.
3. Choose **Open Database** and select the project's `data/students.sqlite` file. On this laptop, it is `D:\PROJECT MANIA\AC\data\students.sqlite`.
4. Select **Browse Data**, then choose the `students` table.
5. Inspect `username` and `password_hash`. Profile columns ending in `_ct` contain ciphertext.
6. Use read-only mode for demonstrations. Do not change the hash or encrypted fields to demonstrate tampering against real accounts.

The file is a binary SQLite database; opening it in Notepad will not display a useful table. The adjacent `-wal` and `-shm` files are SQLite working files. Do not copy just the main database while writes are occurring; use the export command below.

## Download the project and start a new empty installation

```powershell
git clone https://github.com/KrisGod21/SecureAuth.git
cd SecureAuth
npm ci
npm run setup
npm start
```

Alternatively, download the repository ZIP from GitHub and extract it, then run the last three commands in the extracted folder. Open `http://localhost:3000`. This creates a fresh private key and database. GitHub contains the complete application source and report; it does not contain private account records, keys or `node_modules`.

## Move existing accounts and their passwords

On the original laptop, run:

```powershell
npm run db:export
```

This creates a uniquely named directory under `private-backups`. It contains:

- `data/students.sqlite`: a consistent SQLite snapshot, including pending WAL data.
- `.env`: the original profile decryption key and fresh localhost settings.
- `TRANSFER.txt`: the destination setup instructions.

The optional ANU API credential is excluded. The export may run while the app is running. It uses SQLite's backup API, rather than copying a possibly incomplete live file.

Transfer this folder privately, for example using a USB drive. On the destination laptop:

1. Install Node.js 24+ and clone or extract the repository.
2. Run `npm ci` in the new project folder.
3. Before starting the app or registering users, copy the exported `.env` into that project root and exported `data/students.sqlite` into its `data` folder. Show hidden files if necessary to find `.env`.
4. Run `npm run setup`. It preserves the imported key.
5. Run `npm start`, then sign in using an existing username and password.
6. Run `npm run db:view` to confirm the imported users.

Use a fresh destination installation. Do not overwrite another populated database or another installation's key. A matching database and key must travel together: the salted password hashes can verify independently, but the profile fields require the original key. Active login sessions are not transferred, so sign in again. Two local copies are independent; changes made on one laptop are not synchronized to the other.

## Existing older databases

Starting the updated app automatically migrates the earlier `pwd_ct` schema into `username` plus `password_hash`. The original passwords continue to work. The migration validates the original key, creates a private backup in `data/backups`, rebuilds the table in a transaction and removes the reversible password column. If the key is wrong, migration fails without replacing the original table. Older migration backups still contain legacy encrypted passwords; protect them along with the old key.

## Deployment boundary

SQLite works on a persistent local server or a host with a persistent disk. This repository is not a Vercel-ready serverless deployment: database files and in-memory channel/session/challenge state need architectural changes for that environment. For hosting on a persistent Node server, configure `HOST`, `PORT`, HTTPS `APP_ORIGIN`, `NODE_ENV=production`, a persistent `DB_PATH` and a private `STORAGE_KEY`. The app must remain behind properly configured HTTPS.

## Primary documentation

- [Node SQLite backup API](https://nodejs.org/api/sqlite.html#sqlitebackupsourceDb-path-options)
- [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt)
- [DB Browser for SQLite](https://sqlitebrowser.org/)
