'use strict';
// netsim: DEMO-ONLY "edge proxy + network simulator". localhost cannot fake different
// locations, so browsers talk to this proxy, which stands where a real edge proxy would:
//   * it DISCARDS any client-supplied X-Forwarded-For (as a real edge must), and
//   * writes X-Forwarded-For from the simulated source in the X-Sim-IP header (which it also strips).
// The app trusts only loopback (TRUST_PROXY=loopback), i.e. this proxy. A client that talks to the
// app directly and sets X-Forwarded-For gets nothing (see trustProxy tests).
const http = require('node:http');

function startNetsim({ port, targetPort }) {
  const server = http.createServer((req, res) => {
    const headers = { ...req.headers };
    const sim = headers['x-sim-ip'];
    delete headers['x-sim-ip'];
    delete headers['x-forwarded-for'];
    headers['x-forwarded-for'] = sim || req.socket.remoteAddress;
    const up = http.request({ host: '127.0.0.1', port: targetPort, method: req.method, path: req.url, headers }, (r) => {
      res.writeHead(r.statusCode, r.headers);
      r.pipe(res);
    });
    up.on('error', () => { res.writeHead(502); res.end('bad gateway'); });
    req.pipe(up);
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve(server)));
}

module.exports = { startNetsim };
if (require.main === module) {
  require('./ensure-env').ensureEnv();
  const port = Number(process.env.NETSIM_PORT || 3001);
  startNetsim({ port, targetPort: Number(process.env.APP_PORT || 3000) }).then(() => console.log(`[netsim] :${port} -> app`));
}
