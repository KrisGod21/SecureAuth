/* HC-ADS v2: educational composition, not an independently reviewed cipher.
 * Same implementation in Node and browser. All strings representing binary
 * data below are Latin1 byte strings. Plaintext and labels are UTF-8. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('crypto-js'));
  else root.HCADS = factory(root.CryptoJS);
})(typeof globalThis !== 'undefined' ? globalThis : this, function (C) {
  'use strict';
  const VERSION = '\x02';
  const MAX_BYTES = 1024;
  const parse = s => C.enc.Latin1.parse(s);
  const bytes = w => C.enc.Latin1.stringify(w);
  function utf8(s) { return bytes(C.enc.Utf8.parse(s)); }
  function u32(n) { return String.fromCharCode(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255); }
  function framed(s) { return u32(s.length) + s; }
  function hmac(key, bytes) {
    return C.enc.Latin1.stringify(C.HmacSHA256(parse(bytes), parse(key)));
  }
  function equal(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }
  function hkdf(ikm, salt, info, length) {
    if (!Number.isInteger(length) || length < 1 || length > 255 * 32) throw new Error('Invalid HKDF length');
    const prk = hmac(salt || '\x00'.repeat(32), ikm);
    let result = '', last = '';
    for (let i = 1; result.length < length; i++) { last = hmac(prk, last + info + String.fromCharCode(i)); result += last; }
    return result.slice(0, length);
  }
  function keyBytes(keyHex) {
    if (typeof keyHex !== 'string' || !/^[a-fA-F0-9]{64}$/.test(keyHex)) throw new Error('A 256-bit key is required');
    return bytes(C.enc.Hex.parse(keyHex));
  }
  function derive(keyHex) {
    const k = hkdf(keyBytes(keyHex), 'HCADS-v2', 'independent-keys', 120);
    return { aes: k.slice(0, 32), des: k.slice(32, 56), siv: k.slice(56, 88), auth: k.slice(88, 120) };
  }
  function labelBytes(label) {
    if (typeof label !== 'string' || !label || utf8(label).length > 512) throw new Error('Invalid field context');
    return utf8(label);
  }
  function b64url(raw) { return C.enc.Base64.stringify(parse(raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, ''); }
  function decode(text) {
    if (typeof text !== 'string' || text.length > 1600 || !/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) throw new Error('Invalid envelope');
    const raw = bytes(C.enc.Base64.parse(text.replace(/-/g, '+').replace(/_/g, '/')));
    if (b64url(raw) !== text) throw new Error('Invalid envelope');
    return raw;
  }
  // Full 128-bit big-endian counter increment, including carry across words.
  // CryptoJS's stock CTR increments just one 32-bit word. This mode matches
  // the standard counter semantics used by Node/OpenSSL and WebCrypto.
  const CTR128 = C.lib.BlockCipherMode.extend();
  CTR128.Encryptor = CTR128.extend({ processBlock: function(words, offset) {
    if (this._iv) { this._counter = this._iv.slice(); this._iv = undefined; }
    const stream = this._counter.slice(); this._cipher.encryptBlock(stream,0);
    for (let i=3;i>=0;i--) { this._counter[i] = (this._counter[i]+1)|0; if(this._counter[i] !== 0) break; }
    for (let i=0;i<4;i++) words[offset+i] ^= stream[i];
  }});
  CTR128.Decryptor = CTR128.Encryptor;
  function crypt(algorithm, key, iv, raw, decrypt) {
    if (algorithm === 'AES-CTR') {
      const options = { iv:parse(iv), mode:CTR128, padding:C.pad.NoPadding };
      return bytes(decrypt ? C.AES.decrypt({ciphertext:parse(raw)},parse(key),options) : C.AES.encrypt(parse(raw),parse(key),options).ciphertext);
    }
    const options = { iv:parse(iv),mode:C.mode.CBC,padding:C.pad.NoPadding };
    if(!decrypt) { const n=8-(raw.length%8);raw+=String.fromCharCode(n).repeat(n);return bytes(C.TripleDES.encrypt(parse(raw),parse(key),options).ciphertext); }
    const padded=bytes(C.TripleDES.decrypt({ciphertext:parse(raw)},parse(key),options));
    const n=padded.charCodeAt(padded.length-1);
    if(n<1||n>8||padded.slice(-n)!==String.fromCharCode(n).repeat(n))throw new Error('Invalid envelope');
    return padded.slice(0,-n);
  }
  function encrypt(plaintext, label, keyHex) {
    if (typeof plaintext !== 'string') throw new Error('Invalid plaintext');
    const p = utf8(plaintext), l = labelBytes(label), k = derive(keyHex);
    if (p.length > MAX_BYTES) throw new Error('Field too large');
    const v = hmac(k.siv, 'HCADS2-SIV' + framed(l) + framed(p));
    const a = crypt('AES-CTR', k.aes, v.slice(0, 16), p, false);
    // crypt applies and validates PKCS7 padding exactly once.
    const b = crypt('3DES-CBC', k.des, v.slice(16, 24), a, false);
    const body = VERSION + v + b;
    const mac = hmac(k.auth, 'HCADS2-AUTH' + framed(l) + body);
    return b64url(body + mac);
  }
  function decrypt(ciphertext, label, keyHex) {
    try {
      const bytes = decode(ciphertext), l = labelBytes(label), k = derive(keyHex);
      if (bytes.length < 73 || bytes.charAt(0) !== VERSION || (bytes.length - 65) % 8 !== 0) throw new Error();
      const body = bytes.slice(0, -32), mac = bytes.slice(-32);
      // Never invoke CBC decryption or padding removal until this tag passes.
      if (!equal(mac, hmac(k.auth, 'HCADS2-AUTH' + framed(l) + body))) throw new Error();
      const v = body.slice(1, 33), b = body.slice(33);
      const a = crypt('3DES-CBC', k.des, v.slice(16, 24), b, true);
      const p = crypt('AES-CTR', k.aes, v.slice(0, 16), a, true);
      if (p.length > MAX_BYTES || !equal(v, hmac(k.siv, 'HCADS2-SIV' + framed(l) + framed(p)))) throw new Error();
      return C.enc.Utf8.stringify(parse(p));
    } catch { throw new Error('Invalid authenticated envelope'); }
  }
  function hash(ciphertext) {
    return C.SHA256(ciphertext).toString(C.enc.Hex);
  }
  function seal(plaintext, label, keyHex) { const ct = encrypt(plaintext, label, keyHex); return { ct, digest: hash(ct) }; }
  function open(packet, label, keyHex) {
    if (!packet || typeof packet.ct !== 'string' || typeof packet.digest !== 'string' || !/^[a-f0-9]{64}$/.test(packet.digest) || !equal(hash(packet.ct), packet.digest)) throw new Error('Invalid authenticated envelope');
    return decrypt(packet.ct, label, keyHex);
  }
  return Object.freeze({ encrypt, decrypt, hash, seal, open, hkdf, equal, VERSION: 2, MAX_BYTES });
});
