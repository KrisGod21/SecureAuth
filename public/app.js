/* All session key material stays in this closure, never localStorage/sessionStorage. */
(async function () {
  'use strict';
  const $ = id => document.getElementById(id);
  const views = ['register','login','protocol','password','dashboard'];
  let channelKey = null, currentView = 'register', savedId = '', secretPassword = '', busy = false;
  const titles = {
    register: ['Your identity. Protected.','Create your account with an extra layer of confidence.','Create account'],
    login: ['Good to see you again.','A secure sign-in starts with verified credentials.','Sign in'],
    protocol: ['Security, step by step.','Understand what happens between your browser and the database.','How it works'],
    password: ['Your account is ready.','A private credential for your next sign-in.','Password delivery'],
    dashboard: ['Welcome to your workspace.','Your session is active and your identity is verified.','Your workspace']
  };
  function message(text, error = false) { const el = $('global-message'); el.textContent = text; el.classList.toggle('error', error); el.hidden = !text; }
  function clearPassword() { secretPassword = ''; $('generated-password').value = ''; const canvas = $('password-qr'); canvas.getContext('2d').clearRect(0,0,canvas.width,canvas.height); $('password-saved').checked = false; $('continue-login').disabled = true; }
  function view(name) {
    if (!views.includes(name) || busy) return;
    if (currentView === 'password' && name !== 'password' && !$('password-saved').checked) { message('Save your password and check the confirmation before leaving this screen.', true); return; }
    if (currentView === 'password' && name !== 'password') clearPassword();
    currentView = name; for (const v of views) $(`${v}-view`).hidden = v !== name;
    document.querySelectorAll('[data-view]').forEach(el => el.classList.toggle('active', el.dataset.view === name));
    $('page-title').textContent = titles[name][0]; $('page-description').textContent = titles[name][1]; $('breadcrumb-current').textContent = titles[name][2];
    message(''); history.replaceState(null, '', `#${name}`);
  }
  document.querySelectorAll('[data-view]').forEach(el => el.addEventListener('click', () => view(el.dataset.view)));
  document.querySelector('.brand').addEventListener('click', event => { event.preventDefault(); view('register'); });
  function loading(button, state) { busy = state; button.disabled = state || !channelKey; if (state) { button.dataset.original = button.textContent; button.textContent = 'Protecting your request…'; } else button.textContent = button.dataset.original || button.textContent; }
  async function api(path, body) {
    const response = await fetch(`/api/${path}`, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await response.json();
    if (!response.ok) { const error = new Error(data.error || 'Request failed.'); error.status = response.status; throw error; }
    return data;
  }
  function pipe(stage) { ['encrypt','hash','verify','store'].forEach((v,i) => $(`pipe-${v}`).classList.toggle('complete', i < stage)); }
  function inspect(packet) { $('packet-ct').textContent = packet.ct; $('packet-digest').textContent = packet.digest; }
  async function request(action, values) {
    if (!channelKey) throw new Error('Secure channel unavailable. Refresh the page.');
    const { challenge } = await api('challenge', { action });
    const fields = {}; pipe(0);
    for (const [field, value] of Object.entries(values)) fields[field] = HCADS.seal(value, `request:${action}:${challenge}:${field}`, channelKey);
    pipe(2); inspect(Object.values(fields)[0]);
    const data = await api(action, { challenge, fields }); pipe(4);
    return { data, challenge };
  }
  async function loadProfile() {
    const { data, challenge } = await request('profile', { proof: 'read-profile' });
    const profile = JSON.parse(HCADS.open(data.profile, `response:profile:${challenge}:profile`, channelKey));
    $('welcome-name').textContent = `Hello, ${profile.name.split(' ')[0]}.`;
    $('profile-fields').replaceChildren();
    for (const [field,label] of [['stdid','Student ID'],['name','Full name'],['div','Division'],['branch','Branch']]) {
      const card = document.createElement('div'); card.className = 'profile-item';
      const title = document.createElement('small'); title.textContent = label;
      const value = document.createElement('strong'); value.textContent = profile[field]; card.append(title,value); $('profile-fields').append(card);
    }
    view('dashboard');
  }
  $('register-form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return;
    message(''); const button = $('register-submit'); loading(button,true);
    try {
      const values = Object.fromEntries(new FormData(event.target)); savedId = values.stdid.trim().toUpperCase();
      const { data, challenge } = await request('register',values);
      secretPassword = HCADS.open(data.password,`response:register:${challenge}:pwd`,channelKey);
      $('generated-password').value = secretPassword; $('generated-password').type = 'password'; $('reveal-password').textContent = 'Reveal';
      $('randomness-source').textContent = { 'csprng-only':'Operating system CSPRNG', 'csprng-only-fallback':'CSPRNG fallback · ANU unavailable', 'csprng+anu-qrng':'CSPRNG + ANU quantum source' }[data.randomness] || data.randomness;
      await QRCode.toCanvas($('password-qr'),secretPassword,{width:260,margin:3,errorCorrectionLevel:'M',color:{dark:'#182f54',light:'#ffffff'}});
      event.target.reset(); loading(button,false); view('password');
    } catch(error) { message(error.message,true); } finally { if (busy) loading(button,false); }
  });
  $('login-form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return;
    const button = $('login-submit'); loading(button,true); message('');
    try {
      const { data,challenge } = await request('login',Object.fromEntries(new FormData(event.target)));
      if (HCADS.open(data.result,`response:login:${challenge}:result`,channelKey) !== 'authenticated') throw new Error('Invalid server response.');
      $('login-pwd').value = ''; loading(button,false); await loadProfile();
    } catch(error) { pipe(2); message(error.message,true); } finally { if (busy) loading(button,false); }
  });
  $('toggle-login-password').addEventListener('click', () => { const el = $('login-pwd'), hidden = el.type === 'password'; el.type = hidden ? 'text':'password'; $('toggle-login-password').textContent = hidden ? 'Hide':'Show'; $('toggle-login-password').setAttribute('aria-label',hidden ? 'Hide password':'Show password'); });
  $('reveal-password').addEventListener('click', () => { const el = $('generated-password'), hidden = el.type === 'password'; el.type = hidden ? 'text':'password'; $('reveal-password').textContent = hidden ? 'Hide':'Reveal'; });
  $('copy-password').addEventListener('click', async () => { try { await navigator.clipboard.writeText(secretPassword); message('Password copied. Save it in your password manager.'); } catch { message('Clipboard unavailable. Reveal and copy your password manually.',true); } });
  $('download-qr').addEventListener('click', () => { const a = document.createElement('a'); a.href = $('password-qr').toDataURL('image/png'); a.download = 'ac-password-qr.png'; a.click(); message('QR saved. It contains your password; keep the image private.'); });
  $('password-saved').addEventListener('change', () => $('continue-login').disabled = !$('password-saved').checked);
  $('continue-login').addEventListener('click', () => { $('login-stdid').value = savedId; view('login'); $('login-pwd').focus(); });
  $('logout').addEventListener('click', async () => {
    if (busy) return; const button = $('logout'); loading(button,true);
    try { const {data,challenge} = await request('logout',{proof:'sign-out'}); if (HCADS.open(data.result,`response:logout:${challenge}:result`,channelKey) !== 'signed-out') throw new Error('Sign-out verification failed.'); $('profile-fields').replaceChildren(); loading(button,false); view('login'); message('You have signed out.'); } catch(error) { message(error.message,true); } finally { if(busy) loading(button,false); }
  });
  $('inspect-toggle').addEventListener('click', () => { const hidden = $('packet-inspector').hidden; $('packet-inspector').hidden = !hidden; $('inspect-toggle').setAttribute('aria-expanded',String(hidden)); $('inspect-toggle').textContent = hidden ? 'Close inspector ↑':'Inspect last packet ↗'; });
  window.addEventListener('pagehide', () => { channelKey = null; clearPassword(); $('login-pwd').value = ''; });
  window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
  $('register-submit').disabled = true; $('login-submit').disabled = true;
  view(['register','login','protocol'].includes(location.hash.slice(1)) ? location.hash.slice(1) : 'register');
  try {
    if (!globalThis.crypto?.subtle) throw new Error('Open the lab on localhost or HTTPS to enable browser cryptography.');
    const pair = await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
    const publicKey = await crypto.subtle.exportKey('jwk',pair.publicKey);
    const response = await api('channel',{publicKey});
    const peer = await crypto.subtle.importKey('jwk',response.publicKey,{name:'ECDH',namedCurve:'P-256'},false,[]);
    const shared = await crypto.subtle.deriveBits({name:'ECDH',public:peer},pair.privateKey,256);
    const base = await crypto.subtle.importKey('raw',shared,'HKDF',false,['deriveBits']);
    const material = await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:new TextEncoder().encode(response.salt),info:new TextEncoder().encode('AC-channel-v2')},base,256);
    channelKey = Array.from(new Uint8Array(material),b=>b.toString(16).padStart(2,'0')).join('');
    new Uint8Array(shared).fill(0); new Uint8Array(material).fill(0);
    $('channel-status').textContent = 'Secure channel ready'; $('footer-status').textContent = 'Session keys held in memory';
    $('register-submit').disabled = false; $('login-submit').disabled = false;
    // A reload makes a new channel; a still-valid HttpOnly auth cookie can restore the profile.
    try { await loadProfile(); } catch { pipe(0); $('packet-ct').textContent='Create an account or sign in to inspect a packet.'; $('packet-digest').textContent='—'; }
    setTimeout(() => { channelKey = null; $('channel-status').textContent = 'Channel expired'; $('register-submit').disabled = true; $('login-submit').disabled = true; message('Your secure channel has expired. Refresh this page to continue.',true); },response.expiresIn*1000);
  } catch(error) { $('channel-status').textContent = 'Channel unavailable'; message(error.message,true); }
})();
