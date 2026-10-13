import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, createHmac, hkdfSync } from 'node:crypto';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import hcads from '../shared/hcads.cjs';
import CryptoJS from 'crypto-js';
const key = '01'.repeat(32);
test('round trips empty, Unicode, block boundaries and maximum size', () => {
  for(const p of ['', 'A', '12345678', '1234567890123456', 'Mamta शर्मा 🔐', 'x'.repeat(1024)]) assert.equal(hcads.decrypt(hcads.encrypt(p,'name',key),'name',key),p);
  assert.throws(()=>hcads.encrypt('x'.repeat(1025),'name',key));
});
test('determinism, different field labels and different keys', () => {
  const a = hcads.encrypt('CSE','branch',key);
  assert.equal(a,hcads.encrypt('CSE','branch',key));
  assert.notEqual(a,hcads.encrypt('CSE','name',key));
  assert.notEqual(a,hcads.encrypt('CSE','branch','02'.repeat(32)));
  assert.throws(()=>hcads.decrypt(a,'name',key)); assert.throws(()=>hcads.decrypt(a,'branch','02'.repeat(32)));
});
test('every bit of version, IV, ciphertext and MAC is authenticated', () => {
  const original = Buffer.from(hcads.encrypt('a random password!','pwd',key),'base64url');
  for(let i=0;i<original.length;i++) for(let bit=0;bit<8;bit++) { const modified = Buffer.from(original); modified[i] ^= 1<<bit; assert.throws(()=>hcads.decrypt(modified.toString('base64url'),'pwd',key)); }
});
test('SHA-256 replacement cannot bypass the keyed MAC', () => {
  const packet=hcads.seal('AC2026001','stdid',key); const raw=Buffer.from(packet.ct,'base64url'); raw[40]^=1; packet.ct=raw.toString('base64url');packet.digest=hcads.hash(packet.ct);
  assert.throws(()=>hcads.open(packet,'stdid',key));
  for(const ct of ['!', 'a', 'abc=', '', 'x'.repeat(1601)]) assert.throws(()=>hcads.decrypt(ct,'stdid',key));
});
test('HKDF matches RFC 5869 test case 1', () => {
  const hexBytes = s => Buffer.from(s,'hex').toString('latin1');
  const ikm=hexBytes('0b'.repeat(22)),salt=hexBytes('000102030405060708090a0b0c'),info=hexBytes('f0f1f2f3f4f5f6f7f8f9');
  assert.equal(Buffer.from(hcads.hkdf(ikm,salt,info,42),'latin1').toString('hex'),'3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});
function reference(p,label) {
  const keys=Buffer.from(hkdfSync('sha256',Buffer.from(key,'hex'),Buffer.from('HCADS-v2'),Buffer.from('independent-keys'),120));
  const frame=b=>{const n=Buffer.alloc(4);n.writeUInt32BE(b.length);return Buffer.concat([n,b]);};
  const h=(k,b)=>createHmac('sha256',k).update(b).digest();
  const l=Buffer.from(label),plain=Buffer.from(p);
  const v=h(keys.subarray(56,88),Buffer.concat([Buffer.from('HCADS2-SIV'),frame(l),frame(plain)]));
  const aes=createCipheriv('aes-256-ctr',keys.subarray(0,32),v.subarray(0,16));
  const a=Buffer.concat([aes.update(plain),aes.final()]);
  const des=createCipheriv('des-ede3-cbc',keys.subarray(32,56),v.subarray(16,24));
  const b=Buffer.concat([des.update(a),des.final()]);
  const body=Buffer.concat([Buffer.from([2]),v,b]);
  const mac=h(keys.subarray(88),Buffer.concat([Buffer.from('HCADS2-AUTH'),frame(l),body]));
  return Buffer.concat([body,mac]).toString('base64url');
}
test('cipher matches independent native OpenSSL AES, 3DES, HKDF and HMAC composition', () => {
  for(const p of ['AC2026001','क्षमता 🔐','x'.repeat(128)]) assert.equal(hcads.encrypt(p,'request:test:stdid',key),reference(p,'request:test:stdid'));
});
test('browser UMD module and Node implementation interoperate', () => {
  const context = vm.createContext({CryptoJS}); vm.runInContext(readFileSync('shared/hcads.cjs','utf8'),context);
  const ct=context.HCADS.encrypt('browser parity','name',key);
  assert.equal(ct,hcads.encrypt('browser parity','name',key));assert.equal(context.HCADS.decrypt(hcads.encrypt('server parity','pwd',key),'pwd',key),'server parity');
});
test('AES counter carries across 32-bit and 128-bit rollover boundaries', () => {
  const context=vm.createContext({CryptoJS});
  vm.runInContext(readFileSync('shared/hcads.cjs','utf8').replace('Object.freeze({ encrypt','Object.freeze({ _crypt: crypt, encrypt'),context);
  const rawKey=Buffer.alloc(32,7),plain=Buffer.alloc(48,42);
  for(const iv of [Buffer.from('00112233445566778899aabbfffffffe','hex'),Buffer.alloc(16,255)]) {
    const native=createCipheriv('aes-256-ctr',rawKey,iv);const expected=Buffer.concat([native.update(plain),native.final()]);
    const actual=context.HCADS._crypt('AES-CTR',rawKey.toString('latin1'),iv.toString('latin1'),plain.toString('latin1'),false);
    assert.equal(Buffer.from(actual,'latin1').toString('hex'),expected.toString('hex'));
  }
});
