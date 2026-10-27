// dashboard.js: heartbeat + transfer with a per-action device proof; handles a step-up challenge.
SG.startHeartbeat();
const out = document.getElementById('out');
const transfer = () => SG.fetchWithProof('/transfer', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ to: document.getElementById('to').value, amount: Number(document.getElementById('amt').value) }),
});
document.getElementById('go').onclick = async () => {
  let r = await transfer();
  if (r.status === 403 && (await r.clone().json()).error === 'step_up_required') {
    out.textContent = 'Step-up required: confirm with your passkey…';
    if (await SG.stepUp()) r = await transfer();
  }
  const j = await r.json().catch(() => ({}));
  out.textContent = `${r.status} ${JSON.stringify(j, null, 2)}`;
  if (j.balance != null) document.getElementById('bal').textContent = j.balance;
};
