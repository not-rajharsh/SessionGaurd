'use strict';
// views: every HTML page. No inline scripts (CSP forbids them); behaviour lives in public/*.js.
// All interpolated values go through esc(). Attacker-controlled data (UA, routes) is never
// rendered server-side at all: the admin page fetches JSON and renders it with textContent.
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const scripts = (...names) => names.map((n) => `<script src="${n}"></script>`).join('');

const page = (title, body) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>body{font:16px system-ui;max-width:44rem;margin:2.5rem auto;padding:0 1rem}input,button{font:inherit;padding:.4rem;margin:.2rem 0}
pre{background:#f4f4f4;padding:.6rem;overflow:auto;white-space:pre-wrap}.err{color:#b00020}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:.3rem .5rem;text-align:left;font-size:.9rem}
tr.row{cursor:pointer}tr.row:hover{background:#f0f6ff}.bad{color:#b00020;font-weight:600}.ok{color:#1b7f3b}.mid{color:#a66a00}
.ev{border-left:4px solid #ccc;margin:.6rem 0;padding:.2rem .6rem}.ev.terminate{border-color:#b00020}.ev.challenge{border-color:#e0a000}.ev.allow{border-color:#1b7f3b}
.muted{color:#666;font-size:.85rem}</style>${body}`;

const SIMPLEWEBAUTHN = '/static/vendor/simplewebauthn-browser.js';

const loginForm = (msg = '') => page('Login', `<h1>Demo bank</h1>${msg ? `<p class="err">${esc(msg)}</p>` : ''}
<form id="login-form" method="post" action="/login"><label>User <input name="username" autocomplete="username"></label><br>
<label>Password <input name="password" type="password" autocomplete="current-password"></label><br>
<input type="hidden" name="pubkey" value=""><button>Log in</button></form>
<p class="muted">Logging in creates a device-bound key in this browser (non-extractable).</p>
${scripts('/static/devicekey.js', '/static/login.js')}`);

const dashboardPage = (user, balance) => page('Dashboard', `<h1>Welcome, ${esc(user)}</h1>
<p>Balance: $<span id="bal">${esc(balance)}</span> (fake)</p>
<h2>Transfer</h2><input id="to" value="alice"> <input id="amt" type="number" value="100"> <button id="go">Send</button>
<pre id="out">(no transfer yet)</pre>
<p><a href="/passkey/setup">Passkey setup</a></p>
<form method="post" action="/logout"><button>Log out</button></form>
${scripts(SIMPLEWEBAUTHN, '/static/devicekey.js', '/static/stepup.js', '/static/dashboard.js')}`);

const stepupPage = () => page('Verify it is you', `<h1>Verification required</h1>
<p>This request looked unusual. Confirm with your passkey.</p><p id="status" data-state="pending">working…</p>
${scripts(SIMPLEWEBAUTHN, '/static/devicekey.js', '/static/stepup.js', '/static/stepup-page.js')}`);

const passkeyPage = () => page('Passkey setup', `<h1>Register a passkey</h1>
<button id="register">Register passkey</button><p id="status"></p>
${scripts(SIMPLEWEBAUTHN, '/static/devicekey.js', '/static/passkey-setup.js')}`);

const adminLoginForm = (msg = '') => page('Admin login', `<h1>Admin</h1>${msg ? `<p class="err">${esc(msg)}</p>` : ''}
<form method="post" action="/admin/login"><label>User <input name="username"></label><br>
<label>Password <input name="password" type="password"></label><br><button>Log in</button></form>`);

const adminPage = () => page('Admin dashboard', `<h1>Risk dashboard</h1>
<p class="muted">Auto-refreshes every 2 s. <form method="post" action="/admin/logout" style="display:inline"><button>Log out</button></form></p>
<h2>Sessions</h2><table id="sessions"><thead><tr><th>Session</th><th>Status</th><th>Events</th><th>Last</th><th>Max score</th><th>Last action</th></tr></thead><tbody></tbody></table>
<h2>Timeline <span id="selected" class="muted"></span></h2><div id="timeline"></div><div id="events"></div>
${scripts('/static/admin.js')}`);

module.exports = { esc, page, loginForm, dashboardPage, stepupPage, passkeyPage, adminLoginForm, adminPage };
