import { build } from 'esbuild';
await build({ entryPoints: ['scripts/qr-entry.js'], bundle: true, minify: true, platform: 'browser', outfile: 'public/vendor/qrcode.js' });
console.log('Built local QR code renderer.');
