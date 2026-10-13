import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, isAbsolute } from 'node:path';
import { openDatabase, prepareDatabase } from '../server/db.js';
import { hashPassword, verifyPassword } from '../server/password-hash.js';
import { inspectDatabase, exportDatabase } from '../server/database-tools.js';
import hcads from '../shared/hcads.cjs';
const key='03'.repeat(32), password='Portable123!AbCd';
function ownedTemp(t) {
  const root=mkdtempSync(join(tmpdir(),'secureauth-storage-'));
  t.after(()=>{const location=relative(tmpdir(),root);assert.ok(location.startsWith('secureauth-storage-')&&!location.startsWith('..')&&!isAbsolute(location));rmSync(root,{recursive:true,force:true});});
  return root;
}
function row(hash) {
  const id='b'.repeat(32),username='PORTABLE001';
  return {id,username,stdid_ct:hcads.encrypt(username,'store:stdid',key),name_ct:hcads.encrypt('Portable Student',`store:${id}:name`,key),div_ct:hcads.encrypt('A1',`store:${id}:div`,key),branch_ct:hcads.encrypt('CSE',`store:${id}:branch`,key),password_hash:hash};
}
test('salted scrypt hashes verify passwords without reversible password storage',async()=>{
  const a=await hashPassword(password),b=await hashPassword(password);
  assert.notEqual(a,b);assert.equal(await verifyPassword(password,a),true);assert.equal(await verifyPassword('wrong',a),false);
  assert.equal(await verifyPassword(password,a.replace('$32768$','$99999999$')),false);
  assert.equal(await verifyPassword(password,'malformed'),false);
});
test('private export preserves database, original key and password verification on another installation',async t=>{
  const root=ownedTemp(t),source=join(root,'source.sqlite'),db=openDatabase(source);
  db.insert(row(await hashPassword(password)));db.close();
  const exported=await exportDatabase({dbPath:source,storageKey:key,destinationRoot:join(root,'exports')});assert.equal(exported.count,1);
  const copiedKey=readFileSync(join(exported.folder,'.env'),'utf8').match(/^STORAGE_KEY=(.*)$/m)[1];
  const copy=await prepareDatabase(join(exported.folder,'data','students.sqlite'),copiedKey);
  assert.equal(await verifyPassword(password,copy.find('PORTABLE001').password_hash),true);copy.close();
  const viewed=inspectDatabase(join(exported.folder,'data','students.sqlite'),{storageKey:copiedKey});assert.equal(viewed[0].name,'Portable Student');assert.ok(!JSON.stringify(viewed).includes(password));
  await assert.rejects(()=>exportDatabase({dbPath:source,storageKey:'04'.repeat(32),destinationRoot:join(root,'wrong')}));
});
test('legacy encrypted password rows migrate atomically and still accept the same password',async t=>{
  const root=ownedTemp(t),path=join(root,'legacy.sqlite'),legacy=new DatabaseSync(path),r=row('unused');
  legacy.exec('CREATE TABLE students (id TEXT PRIMARY KEY,stdid_ct TEXT UNIQUE NOT NULL,name_ct TEXT NOT NULL,div_ct TEXT NOT NULL,branch_ct TEXT NOT NULL,pwd_ct TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);');
  legacy.prepare('INSERT INTO students (id,stdid_ct,name_ct,div_ct,branch_ct,pwd_ct) VALUES (?,?,?,?,?,?)').run(r.id,r.stdid_ct,r.name_ct,r.div_ct,r.branch_ct,hcads.encrypt(password,`store:${r.id}:pwd`,key));legacy.close();
  await assert.rejects(()=>prepareDatabase(path,'04'.repeat(32)));
  const intact=new DatabaseSync(path);assert.ok(intact.prepare('PRAGMA table_info(students)').all().some(c=>c.name==='pwd_ct'));intact.close();
  const migrated=await prepareDatabase(path,key);assert.equal(await verifyPassword(password,migrated.find(r.username).password_hash),true);
  assert.ok(!migrated.raw.prepare('PRAGMA table_info(students)').all().some(c=>c.name==='pwd_ct'));migrated.close();
  assert.equal(readdirSync(join(root,'backups')).length,1);
  const reopened=await prepareDatabase(path,key);assert.equal(reopened.count(),1);reopened.close();
});
