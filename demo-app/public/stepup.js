// stepup.js (C2): passkey step-up. Any failure is reported to the server, which terminates the session.
window.SG = window.SG || {};
SG.lastStepUpError = '';
SG.stepUp = async () => {
  const post = (url, body) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  try {
    const o = await post('/stepup/options', {});
    if (!o.ok) throw Object.assign(new Error(`options failed: ${o.status}`), { name: `OptionsHttp${o.status}` });
    const assertion = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: await o.json() });
    return (await post('/stepup/verify', { response: assertion })).ok;
  } catch (err) {
    SG.lastStepUpError = String((err && err.name) || err).slice(0, 40);
    await post('/stepup/verify', { failed: true, reason: String((err && err.name) || err) }).catch(() => {});
    return false;
  }
};
