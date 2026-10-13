import { execFileSync } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
function walk(dir) {
  for (const name of readdirSync(dir)) {
    const file = `${dir}/${name}`;
    if (statSync(file).isDirectory()) { if(name !== 'vendor') walk(file); }
    else if (/\.(js|cjs)$/.test(name)) execFileSync(process.execPath, ['--check', file], { stdio: 'inherit' });
  }
}
for (const dir of ['server','shared','public','scripts','tests']) walk(dir);
console.log('All source JavaScript syntax checks passed.');
