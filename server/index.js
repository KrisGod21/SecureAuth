import { createApp } from './app.js';
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || '127.0.0.1';
const project = await createApp({ storageKey: process.env.STORAGE_KEY, dbPath: process.env.DB_PATH || undefined, origin: process.env.APP_ORIGIN || `http://localhost:${port}`, production: process.env.NODE_ENV === 'production', apiKey: process.env.ANU_QRNG_KEY });
const server = project.app.listen(port, host, () => console.log(`AC Secure Auth Lab\nLocal: ${process.env.APP_ORIGIN || `http://localhost:${port}`}\nHC-ADS v2 educational mode. Storage key stays on the server.`));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => { project.close(); process.exit(0); }));
