'use strict';
/**
 * admin: /admin dashboard behind its OWN login (ADMIN_USER / ADMIN_PASSWORD) and its OWN session
 * cookie ("asid", path /admin, SameSite=Strict, separate store). A normal user session never
 * grants admin, and admin requests never pass through riskGuard. Disabled (404) when the admin
 * credentials are not configured. The page only ships a shell: data arrives as JSON from
 * /admin/api/* (proxied to the engine, whose key the browser never sees) and is rendered with
 * textContent, so attacker-controlled User-Agents cannot become markup.
 */
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const { adminLoginForm, adminPage } = require('./views');

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function createAdminRouter({ engine, env, store }) {
  const router = express.Router();
  if (!env.ADMIN_USER || !env.ADMIN_PASSWORD) {
    router.use((_req, res) => res.status(404).send('admin disabled'));
    return router;
  }
  router.use(session({
    name: 'asid', store, secret: `${env.SESSION_SECRET}:admin`, resave: false, saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'strict', path: '/admin', maxAge: 30 * 60 * 1000 },
  }));
  const requireAdmin = (req, res, next) => {
    if (req.session.admin) return next();
    return req.path.startsWith('/api/') ? res.status(401).json({ error: 'admin_login_required' }) : res.redirect('/admin/login');
  };

  router.get('/login', (_req, res) => res.send(adminLoginForm()));
  router.post('/login', (req, res, next) => {
    const { username = '', password = '' } = req.body || {};
    const ok = safeEqual(username, env.ADMIN_USER) & safeEqual(password, env.ADMIN_PASSWORD);
    if (!ok) return res.status(401).send(adminLoginForm('Invalid credentials'));
    return req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.admin = true;
      return req.session.save((e) => (e ? next(e) : res.redirect('/admin')));
    });
  });
  router.post('/logout', requireAdmin, (req, res) => req.session.destroy(() => { res.clearCookie('asid', { path: '/admin' }); res.redirect('/admin/login'); }));

  router.get('/', requireAdmin, (_req, res) => res.send(adminPage()));
  router.get('/api/sessions', requireAdmin, async (_req, res, next) => {
    try { res.json(await engine.admin('/admin/sessions')); } catch (e) { next(e); }
  });
  router.get('/api/sessions/:ref', requireAdmin, async (req, res, next) => {
    if (!/^[0-9a-f]{12}$/.test(req.params.ref)) return res.status(400).json({ error: 'bad_ref' });
    try { return res.json(await engine.admin(`/admin/sessions/${req.params.ref}`)); } catch (e) { return next(e); }
  });
  return router;
}

module.exports = { createAdminRouter };
