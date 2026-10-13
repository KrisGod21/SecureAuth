import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
const root=resolve('.');
const entries=execFileSync('git',['-c',`safe.directory=${root}`,'ls-files','--stage','-z'],{encoding:'utf8'}).split('\0').filter(Boolean).map(line=>{
  const tab=line.indexOf('\t'),parts=line.slice(0,tab).split(' ');
  if(parts[2]!=='0')throw new Error('Resolve staged merge conflicts before publishing.');
  return {file:line.slice(tab+1),oid:parts[1]};
});
const files=entries.map(entry=>entry.file);
if (!files.length) throw new Error('Stage the intended source files before checking publication.');
const privateNames=files.filter(name=>/^(?:node_modules|data|private-backups|output\/qa)\//.test(name)||/(?:^|\/)\.env(?:$|\.(?!example$))/.test(name)||/\.(?:sqlite|db)(?:-wal|-shm)?$/.test(name));
if(privateNames.length)throw new Error(`Private files were staged: ${privateNames.join(', ')}`);
const secrets=existsSync('.env')?readFileSync('.env','utf8').split(/\r?\n/).filter(line=>/^(STORAGE_KEY|ANU_QRNG_KEY)=/.test(line)).map(line=>line.slice(line.indexOf('=')+1).trim()).filter(value=>value.length>=12):[];
const objects=execFileSync('git',['-c',`safe.directory=${root}`,'cat-file','--batch'],{input:entries.map(entry=>entry.oid).join('\n')+'\n',maxBuffer:32*1024*1024});
let offset=0;
for(const {file} of entries) {
  const end=objects.indexOf(10,offset),header=objects.subarray(offset,end).toString('utf8').split(' '),size=Number(header[2]);
  if(header[1]!=='blob'||!Number.isInteger(size))throw new Error(`Unsupported staged object: ${file}`);
  const content=objects.subarray(end+1,end+1+size);offset=end+1+size+1;
  if(secrets.some(value=>content.includes(Buffer.from(value))))throw new Error(`A local secret appears in staged source: ${file}`);
}
console.log(`Publication check passed for ${files.length} staged files. Private data and local keys are excluded.`);
