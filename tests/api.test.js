import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, diffieHellman, createPublicKey, hkdfSync } from 'node:crypto';
import { createApp } from '../server/app.js';
import { request as httpRequest } from 'node:http';
import hcads from '../shared/hcads.cjs';
import { verifyPassword } from '../server/password-hash.js';
const origin='http://localhost:3000';
async function fixture(t,options={}) {
  let now=Date.now();
  const project=await createApp({storageKey:'02'.repeat(32),dbPath:':memory:',origin,clock:()=>now,...options});
  const server=project.app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
  t.after(()=>new Promise(resolve=>server.close(()=>{project.close();resolve();})));
  const url=`http://127.0.0.1:${server.address().port}`;let cookies={},channelKey;
  async function send(method,route,body,extra={}) {
    return new Promise((resolve,reject)=>{
      const req=httpRequest(url+route,{method,headers:{host:'localhost:3000',origin,'content-type':'application/json',cookie:Object.entries(cookies).map(([k,v])=>`${k}=${v}`).join('; '),...extra}},res=>{
        let text='';res.setEncoding('utf8');res.on('data',chunk=>text+=chunk);res.on('end',()=>{let parsed;try{parsed=JSON.parse(text);}catch{parsed=text;}
          const headers=new Headers();for(const [k,v]of Object.entries(res.headers))if(Array.isArray(v)){for(const item of v)headers.append(k,item);}else if(v!==undefined)headers.set(k,v);
          resolve({status:res.statusCode,body:parsed,headers});});
      });req.on('error',reject);req.end(body===undefined?undefined:JSON.stringify(body));
    });
  }
  async function post(route,body,extra={}) {
    const res=await send('POST',route,body,extra);
    for(const cookie of res.headers.getSetCookie()) {const [pair]=cookie.split(';');const index=pair.indexOf('=');cookies[pair.slice(0,index)]=pair.slice(index+1);}
    return res;
  }
  async function handshake(){
    const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});const res=await post('/api/channel',{publicKey:pair.publicKey.export({format:'jwk'})});assert.equal(res.status,200);
    const shared=diffieHellman({privateKey:pair.privateKey,publicKey:createPublicKey({key:res.body.publicKey,format:'jwk'})});channelKey=Buffer.from(hkdfSync('sha256',shared,Buffer.from(res.body.salt),Buffer.from('AC-channel-v2'),32)).toString('hex');
    assert.match(res.headers.get('set-cookie'),/HttpOnly/);assert.match(res.headers.get('set-cookie'),/SameSite=Strict/);
  }
  async function packet(action,values){const res=await post('/api/challenge',{action});assert.equal(res.status,200);const nonce=res.body.challenge;return{challenge:nonce,fields:Object.fromEntries(Object.entries(values).map(([k,v])=>[k,hcads.seal(v,`request:${action}:${nonce}:${k}`,channelKey)]))};}
  await handshake();
  return {project,url,post,get:route=>send('GET',route),packet,handshake,key:()=>channelKey,advance:ms=>now+=ms};
}
const student={stdid:'ac2026001',name:'Aarav Sharma',div:'A1',branch:'CSE'};
async function enroll(f){const packet=await f.packet('register',student);const res=await f.post('/api/register',packet);assert.equal(res.status,201);return hcads.open(res.body.password,`response:register:${packet.challenge}:pwd`,f.key());}
test('end-to-end enrollment, salted password database, login, encrypted profile and logout',async t=>{
  const f=await fixture(t);const password=await enroll(f);
  const rows=f.project.db.raw.prepare('SELECT * FROM students').all();assert.equal(rows.length,1);
  for(const field of ['stdid_ct','name_ct','div_ct','branch_ct']) {assert.match(rows[0][field],/^[A-Za-z0-9_-]+$/);for(const plain of Object.values(student).concat(password))assert.notEqual(rows[0][field],plain);}
  assert.equal(rows[0].username,'AC2026001');assert.match(rows[0].password_hash,/^scrypt\$/);assert.ok(await verifyPassword(password,rows[0].password_hash));assert.ok(!JSON.stringify(rows).includes(password));
  const columns=f.project.db.raw.prepare('PRAGMA table_info(students)').all().map(c=>c.name);assert.deepEqual(columns,['id','username','stdid_ct','name_ct','div_ct','branch_ct','password_hash','created_at']);
  const login=await f.packet('login',{stdid:student.stdid,pwd:password});const result=await f.post('/api/login',login);assert.equal(result.status,200);assert.equal(hcads.open(result.body.result,`response:login:${login.challenge}:result`,f.key()),'authenticated');
  const pp=await f.packet('profile',{proof:'read-profile'});const profile=await f.post('/api/profile',pp);assert.equal(profile.status,200);const data=JSON.parse(hcads.open(profile.body.profile,`response:profile:${pp.challenge}:profile`,f.key()));assert.equal(data.name,student.name);assert.equal(data.stdid,'AC2026001');assert.ok(!JSON.stringify(profile.body).includes(student.name));
  const out=await f.packet('logout',{proof:'sign-out'});assert.equal((await f.post('/api/logout',out)).status,200);
  assert.equal((await f.post('/api/profile',await f.packet('profile',{proof:'read-profile'}))).status,401);
});
test('tamper rejection despite recomputed digest, challenge reuse and expiry rejection',async t=>{
  const f=await fixture(t);const p=await f.packet('register',student);const bytes=Buffer.from(p.fields.name.ct,'base64url');bytes[40]^=1;p.fields.name.ct=bytes.toString('base64url');p.fields.name.digest=hcads.hash(p.fields.name.ct);
  assert.equal((await f.post('/api/register',p)).status,400);assert.equal((await f.post('/api/register',p)).status,400);assert.equal(f.project.db.count(),0);
  const expired=await f.packet('register',student);f.advance(60001);assert.equal((await f.post('/api/register',expired)).status,400);
});
test('successful requests cannot be replayed or transplanted between actions or fields',async t=>{
  const f=await fixture(t);const packet=await f.packet('register',student);assert.equal((await f.post('/api/register',packet)).status,201);assert.equal((await f.post('/api/register',packet)).status,400);
  const transplant=await f.packet('register',{...student,stdid:'AC2026002'});[transplant.fields.name,transplant.fields.branch]=[transplant.fields.branch,transplant.fields.name];assert.equal((await f.post('/api/register',transplant)).status,400);
  const action=await f.packet('login',{stdid:student.stdid,pwd:'wrong'});assert.equal((await f.post('/api/register',action)).status,400);
});
test('duplicates, generic credential failures, per-account throttling and validation',async t=>{
  const f=await fixture(t);await enroll(f);assert.equal((await f.post('/api/register',await f.packet('register',student))).status,409);
  const invalid=await f.post('/api/register',await f.packet('register',{...student,stdid:'x',branch:'UNKNOWN'}));assert.equal(invalid.status,400);
  const wrong=await f.post('/api/login',await f.packet('login',{stdid:student.stdid,pwd:'incorrect'}));const unknown=await f.post('/api/login',await f.packet('login',{stdid:'AC9999999',pwd:'incorrect'}));assert.equal(wrong.status,401);assert.deepEqual(wrong.body,unknown.body);
  for(let i=0;i<9;i++)assert.equal((await f.post('/api/login',await f.packet('login',{stdid:student.stdid,pwd:'incorrect'}))).status,401);
  assert.equal((await f.post('/api/login',await f.packet('login',{stdid:student.stdid,pwd:'incorrect'}))).status,429);
});
test('cross-origin, untrusted host, invalid JSON, unauthenticated profile and channel expiry',async t=>{
  const f=await fixture(t);
  assert.equal((await f.post('/api/challenge',{action:'login'},{origin:'https://attacker.example'})).status,403);
  assert.equal((await f.post('/api/challenge',{action:'login'},{host:'attacker.example'})).status,403);
  assert.equal((await f.post('/api/challenge',{action:'login'},{'content-type':'text/plain'})).status,415);
  assert.equal((await f.post('/api/profile',await f.packet('profile',{proof:'test'}))).status,401);
  f.advance(600001);assert.equal((await f.post('/api/challenge',{action:'login'})).status,401);
});
test('private application files are not served and security headers are present',async t=>{
  const f=await fixture(t);
  const page=await f.get('/');assert.equal(page.status,200);assert.match(page.headers.get('content-security-policy'),/script-src 'self'/);assert.equal(page.headers.get('x-content-type-options'),'nosniff');
  const report=await f.get('/report');assert.equal(report.status,200);assert.match(report.headers.get('content-disposition'),/AC_Algorithm_and_Application.docx/);
  assert.equal((await f.get('/vendor/qrcode.js')).status,200);assert.equal((await f.get('/vendor/crypto-js.js')).status,200);
  for(const file of ['/.env','/data/students.sqlite','/server/app.js','/implementation_plan.md'])assert.equal((await f.get(file)).status,404);
  await assert.rejects(()=>createApp({storageKey:'02'.repeat(32),production:true,origin:'http://example.com',dbPath:':memory:'}));
});
