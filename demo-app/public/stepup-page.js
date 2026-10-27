// stepup-page.js: runs the passkey step-up for a browser that was challenged, then returns to the app.
(async () => {
  const status = document.getElementById('status');
  const ok = await SG.stepUp();
  status.dataset.state = ok ? 'passed' : 'failed';
  status.dataset.reason = ok ? '' : SG.lastStepUpError;
  status.textContent = ok ? 'passed' : 'failed';
  if (ok) location.assign(location.pathname === '/stepup' ? '/dashboard' : location.href);
})();
