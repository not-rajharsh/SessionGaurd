'use strict';
// Tests for the passkey store: roundtrip, update, missing file.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createPasskeyStore } = require('../passkeys');

test('passkey store roundtrip', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pk-'));
  const store = createPasskeyStore(path.join(dir, 'sub', 'p.json'));
  assert.equal(store.get('demo'), null);
  store.set('demo', { id: 'abc', publicKey: 'pk', counter: 0, transports: [] });
  store.update('demo', { counter: 5 });
  assert.deepEqual(store.get('demo'), { id: 'abc', publicKey: 'pk', counter: 5, transports: [] });
  store.update('nobody', { counter: 1 }); // no-op, must not create an entry
  assert.equal(store.get('nobody'), null);
  fs.rmSync(dir, { recursive: true, force: true });
});
