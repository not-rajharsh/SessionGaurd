// passkey-setup.js (C1): register a passkey; both POSTs carry a device proof.
SG.startHeartbeat();
const status = document.getElementById('status');
document.getElementById('register').onclick = async () => {
  try {
    const post = (url, body) => SG.fetchWithProof(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const o = await post('/passkey/register/options', {});
    if (!o.ok) throw new Error(`options ${o.status}`);
    const attestation = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: await o.json() });
    const v = await post('/passkey/register/verify', { response: attestation });
    status.textContent = v.ok ? 'registered' : `failed ${v.status}`;
  } catch (e) { status.textContent = `failed ${e.message}`; }
};
