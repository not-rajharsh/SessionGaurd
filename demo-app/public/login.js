// login.js: create the device key first, then submit the form with only the PUBLIC key attached.
document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  try {
    form.elements.pubkey.value = await SG.generate();
  } catch (err) {
    document.querySelector('.muted').textContent = 'This browser cannot create a device key.';
    return;
  }
  form.submit(); // form.submit() does not re-fire the submit event
});
