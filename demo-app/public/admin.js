// admin.js (E1/E2): renders ONLY with textContent / createElement. Nothing from the API is ever
// parsed as HTML, and the page's CSP forbids inline script, so a hostile User-Agent stays text.
const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = String(text); if (cls) e.className = cls; return e; };
const svg = (tag, attrs) => { const e = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };
const fmt = (ts) => new Date(ts * 1000).toLocaleTimeString();
const cls = (action) => ({ allow: 'ok', challenge: 'mid', terminate: 'bad' }[action] || '');
let selected = null;

async function api(path) {
  const r = await fetch(path);
  if (r.status === 401) { location.assign('/admin/login'); throw new Error('login required'); }
  return r.json();
}

async function loadSessions() {
  const { sessions } = await api('/admin/api/sessions');
  const body = document.querySelector('#sessions tbody');
  body.replaceChildren(...sessions.map((s) => {
    const tr = el('tr', undefined, 'row');
    tr.dataset.ref = s.ref;
    tr.append(el('td', s.ref), el('td', s.status, s.status === 'terminated' ? 'bad' : s.status === 'active' ? 'ok' : ''),
      el('td', s.events), el('td', fmt(s.last_ts)), el('td', s.max_score), el('td', s.last_action, cls(s.last_action)));
    tr.onclick = () => { selected = s.ref; loadDetail(); };
    return tr;
  }));
}

function timeline(events) {
  const W = 600, H = 110, pad = 14;
  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, width: '100%', role: 'img' });
  const y = (score) => H - pad - (Math.max(0, Math.min(100, Number(score))) / 100) * (H - 2 * pad);
  const x = (i) => pad + (events.length < 2 ? (W - 2 * pad) / 2 : (i * (W - 2 * pad)) / (events.length - 1));
  for (const [v, label] of [[30, '30'], [70, '70']]) {
    root.append(svg('line', { x1: pad, x2: W - pad, y1: y(v), y2: y(v), stroke: '#bbb', 'stroke-dasharray': '4' }));
    const t = svg('text', { x: W - pad, y: y(v) - 2, 'font-size': 9, 'text-anchor': 'end', fill: '#888' }); t.textContent = label; root.append(t);
  }
  root.append(svg('polyline', { points: events.map((e, i) => `${x(i)},${y(e.score)}`).join(' '), fill: 'none', stroke: '#456' }));
  const color = { allow: '#1b7f3b', challenge: '#e0a000', terminate: '#b00020' };
  events.forEach((e, i) => {
    const c = svg('circle', { cx: x(i), cy: y(e.score), r: 5, fill: color[e.action] || '#888' });
    const title = svg('title', {}); title.textContent = `${e.route || ''} score ${e.score} ${e.action}`; c.append(title); root.append(c);
  });
  return root;
}

async function loadDetail() {
  if (!selected) return;
  const { events } = await api(`/admin/api/sessions/${selected}`);
  $('selected').textContent = `(${selected})`;
  $('timeline').replaceChildren(timeline(events));
  $('events').replaceChildren(...events.map((e) => {
    const box = el('div', undefined, `ev ${e.action}`);
    const head = el('div'); head.append(el('strong', `${e.action.toUpperCase()} ${e.score}/100 `, cls(e.action)), el('span', `${fmt(e.ts)} ${e.route || ''} from ${e.ip}`, 'muted'));
    box.append(head, el('div', `User-Agent: ${e.user_agent}`, 'muted'));
    for (const s of e.signals) box.append(el('div', `${s.weight > 0 ? '+' : ''}${s.weight} ${s.name}: ${s.detail}`));
    const prov = e.provider || e.rationale_source || 'unknown';
    box.append(el('div', e.rationale ? `Rationale (${prov}): ${e.rationale}` : 'Rationale: pending…', 'muted'));
    return box;
  }));
}

const refresh = () => loadSessions().then(loadDetail).catch(() => {});
refresh();
setInterval(refresh, 5000);
