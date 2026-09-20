const assert = require('node:assert/strict');
const { createHash, createHmac } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const html = readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const minute = 60_000;
// Public test data, not an account secret.
const testKey = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const testKeyBytes = Buffer.from('12345678901234567890');

function expectedOTP(timestamp) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(timestamp / 30_000)));
  const hash = createHmac('sha1', testKeyBytes).update(counter).digest();
  return String((hash.readUInt32BE(hash[19] & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

function createPage({ response = 'ok', hidden = false, online = true, protocol = 'https:' } = {}) {
  let now = 0;
  let deviceOffset = 0;
  let responseMode = response;
  let nextTimerId = 0;
  const epoch = Date.UTC(2026, 8, 20, 0, 0, 0, 500);
  const timers = new Map();
  const listeners = new Map();
  const requests = [];
  const copies = [];
  const elements = new Map();
  const addEventListener = (name, callback) => {
    if (!listeners.has(name)) listeners.set(name, []);
    listeners.get(name).push(callback);
  };
  const emit = name => {
    for (const callback of listeners.get(name) || []) callback();
  };
  const document = {
    hidden,
    addEventListener,
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, { value: '', textContent: '', style: {} });
      return elements.get(id);
    }
  };
  class DeviceDate extends Date {
    static now() { return epoch + now + deviceOffset; }
  }
  const navigator = {
    onLine: online,
    clipboard: { async writeText(text) { copies.push(text); } }
  };
  const context = vm.createContext({
    URL, AbortController, Date: DeviceDate, document, navigator,
    window: {
      location: { href: protocol + '//example.invalid/', protocol },
      performance: { now: () => now },
      isSecureContext: true,
      addEventListener
    },
    // Exercise the page's HMAC and TOTP code with Node's SHA-1 primitive;
    // the expected OTP uses Node's independent HMAC implementation above.
    CryptoJS: {
      lib: { WordArray: { create: bytes => Buffer.from(bytes) } },
      SHA1: bytes => ({ toString: () => createHash('sha1').update(bytes).digest('hex') })
    },
    setTimeout(callback, delay) {
      const id = ++nextTimerId;
      timers.set(id, { callback, at: now + Math.max(0, delay || 0) });
      return id;
    },
    clearTimeout(id) { timers.delete(id); },
    fetch(url, options) {
      const request = { url, options, at: now, aborted: false };
      requests.push(request);
      const reply = () => ({
        ok: responseMode !== 'http-error',
        headers: {
          get(name) {
            return name === 'Date' && responseMode !== 'missing-date'
              ? new Date(epoch + now).toUTCString() : null;
          }
        }
      });
      if (responseMode === 'network-error') return Promise.reject(new TypeError('Network error'));
      if (responseMode !== 'pending') return Promise.resolve(reply());
      return new Promise((resolve, reject) => {
        request.resolve = () => resolve(reply());
        options.signal.addEventListener('abort', () => {
          request.aborted = true;
          reject(new DOMException('Aborted', 'AbortError'));
        }, { once: true });
      });
    }
  });
  vm.runInContext(script, context);

  async function flush() {
    for (let i = 0; i < 32; i++) await Promise.resolve();
  }
  async function advance(milliseconds) {
    const target = now + milliseconds;
    await flush();
    let callbacks = 0;
    while (timers.size) {
      const [id, timer] = [...timers].sort((a, b) => a[1].at - b[1].at)[0];
      if (timer.at > target) break;
      assert.ok(++callbacks < 100_000, 'Timers must not spin without advancing time');
      now = timer.at;
      timers.delete(id);
      timer.callback();
      await flush();
    }
    now = target;
    await flush();
  }
  return {
    context, requests, copies, document, navigator, emit, advance, flush,
    serverTime: () => epoch + now,
    async enterKey(value = testKey) {
      document.getElementById('key').value = value;
      context.generateTOTP();
      await flush();
    },
    async setHidden(value) { document.hidden = value; emit('visibilitychange'); await flush(); },
    async setOnline(value) { navigator.onLine = value; emit(value ? 'online' : 'offline'); await flush(); },
    setResponse(value) { responseMode = value; },
    changeDeviceClock(milliseconds) { deviceOffset += milliseconds; }
  };
}

test('empty and invalid inputs never start time requests, including focus and copy', async () => {
  const page = createPage();
  for (const input of ['', '   ', 'INVALID-KEY', '123456']) {
    await page.enterKey(input);
    page.emit('focus');
    page.emit('pageshow');
    page.emit('online');
    await page.context.copyKey();
  }
  await page.advance(60 * minute);
  assert.equal(page.requests.length, 0);
  assert.equal(page.copies.length, 0);
});

test('a hidden page waits until visible before its first calibration', async () => {
  const page = createPage({ hidden: true });
  await page.enterKey();
  await page.advance(24 * 60 * minute);
  assert.equal(page.requests.length, 0);
  await page.setHidden(false);
  assert.equal(page.requests.length, 3);
});

test('hiding a calibrated page stops polling; returning refreshes an expired clock once', async () => {
  const page = createPage();
  await page.enterKey();
  await page.setHidden(true);
  await page.advance(24 * 60 * minute);
  assert.equal(page.requests.length, 3);
  await page.setHidden(false);
  page.emit('focus');
  page.emit('pageshow');
  await page.flush();
  assert.equal(page.requests.length, 6);
  assert.equal(page.document.getElementById('totp').textContent, expectedOTP(page.serverTime()));
});

test('clearing a key stops polling without discarding a recent calibration', async () => {
  const page = createPage();
  await page.enterKey();
  await page.enterKey('');
  await page.advance(5 * minute);
  await page.enterKey();
  assert.equal(page.requests.length, 3);
  await page.enterKey('');
  await page.advance(60 * minute);
  assert.equal(page.requests.length, 3);
});

test('offline and local-file pages do not send time requests', async () => {
  const offline = createPage({ online: false });
  await offline.enterKey();
  await offline.advance(60 * minute);
  assert.equal(offline.requests.length, 0);
  await offline.setOnline(true);
  assert.equal(offline.requests.length, 3);
  await offline.setOnline(false);
  await offline.advance(60 * minute);
  assert.equal(offline.requests.length, 3);
  const local = createPage({ protocol: 'file:' });
  await local.enterKey();
  await local.advance(60 * minute);
  assert.equal(local.requests.length, 0);
  assert.equal(local.document.getElementById('totp').textContent, expectedOTP(local.serverTime()));
});

test('continuous visible use sends six HEAD requests in its first hour, without the key', async () => {
  const page = createPage();
  await page.enterKey();
  await page.advance(60 * minute - 1);
  assert.deepEqual(page.requests.map(request => request.at), [0, 0, 0, 30 * minute, 30 * minute, 30 * minute]);
  for (const request of page.requests) {
    const url = new URL(request.url);
    assert.equal(url.origin, 'https://example.invalid');
    assert.deepEqual([...url.searchParams.keys()], ['_totp_time_sync']);
    assert.ok(!url.href.includes(testKey));
    assert.equal(request.options.method, 'HEAD');
    assert.equal(request.options.cache, 'no-store');
    assert.equal(request.options.body, undefined);
  }
});

test('failures back off for 1, 2, 4, 8, 16, then 30 minutes', async () => {
  const page = createPage({ response: 'http-error' });
  await page.enterKey();
  await page.advance(120 * minute - 1);
  const rounds = page.requests.filter((_, index) => index % 3 === 0).map(request => request.at / minute);
  assert.deepEqual(rounds, [0, 1, 3, 7, 15, 31, 61, 91]);
});

test('input, focus, copy, and online events cannot bypass a failed attempt cooldown', async () => {
  const page = createPage({ response: 'http-error' });
  await page.enterKey();
  for (let i = 0; i < 20; i++) {
    await page.advance(1_000);
    await page.enterKey();
    page.emit('focus');
    page.emit('pageshow');
    await page.setOnline(false);
    await page.setOnline(true);
    page.changeDeviceClock(minute);
    await page.context.copyKey();
  }
  assert.equal(page.requests.length, 3);
  await page.advance(40_000);
  assert.equal(page.requests.length, 6);
});

test('missing Date headers and network errors follow the same cooldown', async () => {
  for (const response of ['missing-date', 'network-error']) {
    const page = createPage({ response });
    await page.enterKey();
    page.emit('focus');
    await page.advance(minute - 1);
    assert.equal(page.requests.length, 3);
    assert.equal(page.context.trustedClock, null);
    await page.advance(1);
    assert.equal(page.requests.length, 6);
  }
});

test('a successful retry restores the normal interval', async () => {
  const page = createPage({ response: 'http-error' });
  await page.enterKey();
  await page.advance(minute);
  page.setResponse('ok');
  await page.advance(2 * minute);
  assert.equal(page.requests.length, 9);
  await page.advance(30 * minute - 1);
  assert.equal(page.requests.length, 9);
  await page.advance(1);
  assert.equal(page.requests.length, 12);
});

test('concurrent UI events share an in-flight calibration', async () => {
  const page = createPage({ response: 'pending' });
  await page.enterKey();
  for (let i = 0; i < 20; i++) {
    page.emit('focus');
    page.emit('pageshow');
    page.context.generateTOTP();
  }
  assert.equal(page.requests.length, 1);
  page.setResponse('ok');
  page.requests[0].resolve();
  await page.flush();
  assert.equal(page.requests.length, 3);
});

test('hiding, clearing, going offline, and pagehide abort pending requests without restarting', async () => {
  for (const action of ['hide', 'clear', 'offline', 'pagehide']) {
    const page = createPage({ response: 'pending' });
    await page.enterKey();
    if (action === 'hide') await page.setHidden(true);
    if (action === 'clear') await page.enterKey('');
    if (action === 'offline') await page.setOnline(false);
    if (action === 'pagehide') page.emit('pagehide');
    await page.advance(60 * minute);
    assert.ok(page.requests[0].aborted, action);
    assert.equal(page.requests.length, 1, action);
  }
});

test('a hung calibration times out and releases copy instead of retrying immediately', async () => {
  const page = createPage({ response: 'pending' });
  await page.enterKey();
  const copied = page.context.copyKey();
  await page.advance(5_000);
  await copied;
  assert.ok(page.requests[0].aborted);
  assert.equal(page.requests.length, 1);
  assert.equal(page.copies.at(-1), expectedOTP(page.serverTime()));
  await page.advance(minute - 1);
  assert.equal(page.requests.length, 1);
  await page.advance(1);
  assert.equal(page.requests.length, 2);
});

test('device clock changes recalibrate, while failures keep their retry deadline', async () => {
  const page = createPage();
  await page.enterKey();
  page.changeDeviceClock(60 * minute);
  page.emit('focus');
  await page.flush();
  assert.equal(page.requests.length, 6);
  assert.equal(page.context.currentTimestampMs(), page.serverTime());
  page.setResponse('http-error');
  page.changeDeviceClock(60 * minute);
  page.emit('focus');
  await page.flush();
  assert.equal(page.requests.length, 9);
  page.changeDeviceClock(60 * minute);
  page.emit('focus');
  await page.advance(minute - 1);
  assert.equal(page.requests.length, 9);
});

test('calibration corrects a bad device clock and copy recalculates across a TOTP boundary', async () => {
  const page = createPage();
  page.changeDeviceClock(10 * minute);
  await page.enterKey();
  assert.equal(page.context.currentTimestampMs(), page.serverTime());
  await page.advance(29_499);
  await page.context.copyKey();
  assert.equal(page.copies.at(-1), expectedOTP(page.serverTime()));
  const oldOTP = page.copies.at(-1);
  await page.advance(2);
  page.document.getElementById('totp').textContent = oldOTP;
  await page.context.copyKey();
  assert.equal(page.copies.at(-1), expectedOTP(page.serverTime()));
  assert.notEqual(page.copies.at(-1), oldOTP);
  assert.equal(page.requests.length, 3);
});
