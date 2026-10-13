import test from 'node:test';
import assert from 'node:assert/strict';
import { generatePassword, CHARSET, quantumBytes } from '../server/password.js';
test('70-symbol alphabet and strong 16-character passwords',async()=>{
  assert.equal(CHARSET.length,70); assert.equal(new Set(CHARSET).size,70);
  const passwords=new Set(); for(let i=0;i<100;i++) { const {password,source}=await generatePassword();assert.equal(password.length,16);assert.match(password,/[A-Z]/);assert.match(password,/[a-z]/);assert.match(password,/\d/);assert.match(password,/[!@#$%&*?]/);assert.equal(source,'csprng-only');passwords.add(password); }
  assert.equal(passwords.size,100);
});
test('live quantum integration validates data and reports genuine fallback honestly',async()=>{
  let url,headers;
  const {password,source}=await generatePassword({apiKey:'test-key',fetchFn:async(u,o)=>{url=u;headers=o.headers;return{ok:true,json:async()=>({success:true,data:Array.from({length:64},(_,i)=>i)})};}});
  assert.equal(source,'csprng+anu-qrng');assert.equal(password.length,16);assert.match(url,/api.quantumnumbers.anu.edu.au/);assert.equal(headers['x-api-key'],'test-key');
  for(const json of [{success:false,data:[]},{success:true,data:Array(64).fill(256)},{success:true,data:Array(63).fill(1)}]) assert.equal((await quantumBytes('test-key',async()=>({ok:true,json:async()=>json}))).source,'csprng-only-fallback');
  assert.equal((await generatePassword({apiKey:'test-key',fetchFn:async()=>{throw new Error('unreachable');}})).source,'csprng-only-fallback');
});
