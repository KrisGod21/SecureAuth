# AC Secure Auth Lab

A complete local full-stack implementation of Experiment 9: encrypted registration, server-generated passwords, browser QR delivery, sign-in and a protected student profile. Passwords are stored as salted scrypt hashes alongside a readable username; profile fields remain encrypted. The interface includes a ciphertext inspector and an explanation of the algorithm.

**Current implementation:** the student ID is the username. The original `implementation_plan.md` is retained as the supplied historical plan; its ciphertext-only password schema has been superseded by the current hashed-password backend.

For database viewing, graphical SQLite instructions, private account export and moving to another laptop, read [Database and transfer instructions](docs/DATABASE_AND_TRANSFER.md).

## Run

Install Node.js 24 or newer, clone this repository (or extract its GitHub ZIP), then run:

```powershell
git clone https://github.com/KrisGod21/SecureAuth.git
cd SecureAuth
npm ci
npm run setup
npm start
```

Open **http://localhost:3000**. If you extracted a ZIP, run `npm ci`, `npm run setup` and `npm start` in the extracted project folder. Use that hostname exactly; the server validates the configured Host and Origin. To change the port, update `PORT` and `APP_ORIGIN` together in `.env`. All browser assets are served locally. Installation builds the QR renderer automatically; `npm run build` rebuilds it.

Register a student, save the generated password or QR, confirm that it is saved, and sign in using the student ID. QR codes contain the plaintext password. Keep them private. There is no password recovery in this lab.

`npm run setup` generates a random server-only storage key without overwriting an existing `.env`. Back up that file privately with the database. Losing it makes records unreadable. Never commit it, place it under `public`, or share it. The SQLite database lives in `data/students.sqlite` and survives restarts. Sessions and challenges are in memory and disappear on restart.

## Security design

HC-ADS v2 uses HKDF-SHA256 to derive independent AES-256, Triple-DES, synthetic-IV and authentication keys. AES-CTR is followed by PKCS7 padding and 3DES-CBC. An independent encrypt-then-MAC tag binds the version, field context, IV and ciphertext and is verified **before** CBC decryption. SHA-256 digests fingerprint the Base64URL ciphertext and are not a substitute for the keyed MAC.

The storage master key never reaches the browser. Browser and server establish a temporary P-256 ECDH channel key using native WebCrypto/Node crypto and HKDF. A random, one-use, action-bound challenge expires after 60 seconds. Each field authenticates its action, challenge and name. The student ID is also stored as a readable username for administrative inspection. Encrypted profile fields include the random row ID in their context. SQL uses bound parameters.

Passwords are stored with native asynchronous scrypt: N=32768, r=8, p=3, a random 16-byte salt and a 32-byte result. This is OWASP's 32 MiB configuration. The stored value contains the algorithm, parameters, salt and hash. Login verifies this hash after authenticating and decrypting the request; password encryption is used only for transport and one-time QR delivery. The current schema has no `pwd_ct` column. Expensive hashing jobs have bounded concurrency and a bounded queue. See [OWASP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt).

Run `npm run db:view` to display usernames, profiles and password hashes locally, or `npm run db:view -- --raw` for the actual stored columns. Run `npm run db:export` to create a consistent SQLite snapshot and a matching private key file under the ignored `private-backups` folder. Copy these privately into a fresh installation before running setup to preserve existing accounts. A GitHub clone alone starts a new empty database; it does not synchronize records between laptops. Older databases migrate automatically on app startup, with a private backup created first.

The server adds strict Host/Origin checks, SameSite and HttpOnly cookies, request limits, per-account failed-login throttling, small JSON body limits, security headers, generic login errors and authenticated profile responses. Cookies are Secure in HTTPS production mode. Only `public` and specifically selected vendor/shared files are served.

## Scope and limits

This is an **educational composition**, without a formal security proof or an independent audit. Triple DES has been retired for new NIST encryption use. CryptoJS is discontinued and retained only for portable legacy cipher demonstrations; it is not an appropriate dependency for a new production security system. The tested cascade does not establish security stronger than AES alone. JavaScript execution does not guarantee constant-time behavior or complete memory erasure.

Application encryption does not replace HTTPS. An unauthenticated ECDH exchange can be intercepted without TLS. HTTP mode is restricted to loopback; production requires an HTTPS `APP_ORIGIN`. There is no public deployment. A production successor should use vetted AEAD (for example native AES-GCM), managed keys, TLS, audited libraries and a distributed session/challenge/rate-limit store. The current salted password hashes are not reversible with the storage key; encrypted profile fields are. Usernames are intentionally readable. Equality and length leak from deterministic encryption. Registration duplicates can reveal enrollment. Account throttling can be abused to cause temporary denial of service. There is no MFA, identity proofing, recovery, key rotation or distributed deployment support. Private migration backups can still contain legacy encrypted passwords.

The lab caps enrollment at 1000 records, but this is **not** a complete TDEA key-usage budget. Existing sessions last 30 minutes; browser channels last 10 minutes. Refresh after a channel expires. Simultaneous tabs share cookies and can invalidate each other's channels.

## Quantum randomness

Add an ANU API key to `ANU_QRNG_KEY` in `.env` and restart. The server requests 64 bytes from the official ANU endpoint, validates the response, XORs it with 64 independent OS CSPRNG bytes, and expands with HKDF. Rejection sampling avoids modulo bias across a 70-character alphabet. Passwords must include uppercase, lowercase, digits and symbols.

Without a key, the app reports `csprng-only`. Timeouts or invalid quantum responses report `csprng-only-fallback`. There is **no simulated source labeled as quantum**. API credentials and passwords are never logged. The live service is optional and was tested with mocked responses; a real quantum request requires your own key.

## Verify

```powershell
npm test
npm run check
npm audit
```

Tests use in-memory SQLite, temporary files and fresh local servers. Coverage includes native OpenSSL cross-checks, the RFC 5869 vector, AES counter carry, Unicode and block boundaries, tampering, browser/Node parity, replay, field substitution, challenges, expiry, registration, sign-in, logout, SQL schema, salted password verification, database migration, portable export, private file access, origin checks and quantum fallback. Browser QA can run against `node scripts/ui-fixture.js` on port 3001; that isolated process uses an explicit synthetic password and never opens the real database. Do not deploy the fixture.

## Files

- `shared/hcads.cjs`: shared versioned cipher and digest envelope
- `server/app.js`: API, channel/challenge/session controls
- `server/db.js`: SQLite username, password hash and encrypted profile storage
- `server/password-hash.js`: bounded asynchronous scrypt password verification
- `server/database-tools.js`: local viewing and consistent private export
- `server/password.js`: password generation and optional ANU integration
- `public/`: responsive interface and local QR renderer
- `tests/`: cipher, API and randomness verification
- `docs/AC_Algorithm_and_Application.docx`: current complete report with flowcharts
- `docs/DATABASE_AND_TRANSFER.md`: viewing and laptop transfer instructions
- `scripts/create_report.py`: reproducible document generator

The report is downloadable through the application's Algorithm report link.

## API

All POST requests require `Content-Type: application/json` and the configured `Origin`. Encrypted field values use `{ct, digest}`; request envelopes use `{challenge, fields}`.

| Route | Purpose |
|---|---|
| GET `/api/health` | Public algorithm and source configuration status |
| POST `/api/channel` | P-256 public-key exchange and channel cookie |
| POST `/api/challenge` | One-use token bound to an action |
| POST `/api/register` | Validate four encrypted fields and return an encrypted generated password |
| POST `/api/login` | Validate encrypted student ID and password and issue an auth cookie |
| POST `/api/profile` | Return the signed-in student's encrypted profile |
| POST `/api/logout` | Revoke the current auth session |

See the Word report for labels, byte layout, equations and the exact request lifecycle.
