/* =========================================================================
   JUSTICEVAULT — Shamir's Secret Sharing (3-of-5) Educational Demo
   -------------------------------------------------------------------------
   Pure vanilla JavaScript implementation of Shamir's Secret Sharing (SSS)
   over a finite field defined by a large, well-known prime.

   This file is organized into three parts:
     1. Finite-field arithmetic helpers (BigInt based)
     2. Shamir's Secret Sharing core (split / reconstruct)
     3. UI wiring + self-test harness

   IMPORTANT: This is an educational prototype. Do not use it to protect
   real secrets. See README.md and the in-page "Security & Limitations"
   section for details.
   ========================================================================= */

'use strict';

/* -------------------------------------------------------------------------
   1. FINITE FIELD ARITHMETIC
   -------------------------------------------------------------------------
   We work in GF(p), the field of integers modulo a prime p.

   Prime chosen: the Mersenne prime 2^521 - 1.
     - It is a well-known, publicly documented prime (used as the modulus
       for the NIST P-521 elliptic curve field), so nothing about it is
       secret or "magic."
     - At 521 bits (~157 decimal digits) it comfortably exceeds the size
       of any secret this demo will encode as text (UTF-8 strings up to
       roughly 64 bytes), which is required: every secret value and every
       polynomial coefficient MUST be strictly less than p for the scheme
       to be sound.
   ------------------------------------------------------------------------- */

// p = 2^521 - 1 (documented, standard Mersenne prime)
const FIELD_PRIME = (1n << 521n) - 1n;

// Non-negative modulo (BigInt % can return negative values in JS)
function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

// Modular addition / subtraction / multiplication
function modAdd(a, b, m) { return mod(a + b, m); }
function modSub(a, b, m) { return mod(a - b, m); }
function modMul(a, b, m) { return mod(a * b, m); }

// Extended Euclidean algorithm -> modular inverse (needed for Lagrange
// interpolation, which divides by differences of x-coordinates in GF(p)).
function modInverse(a, m) {
  a = mod(a, m);
  if (a === 0n) throw new Error('Cannot invert 0 in a finite field');
  let [oldR, r] = [a, m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('Modular inverse does not exist');
  return mod(oldS, m);
}

/* -------------------------------------------------------------------------
   Cryptographically secure random field elements
   -------------------------------------------------------------------------
   Uses crypto.getRandomValues() (never Math.random()) and rejection
   sampling so every value in [1, p-1] is equally likely (no modulo bias).
   ------------------------------------------------------------------------- */
function secureRandomBigIntBelow(limitExclusive) {
  const bitLength = limitExclusive.toString(2).length;
  const byteLength = Math.ceil(bitLength / 8);
  const mask = 8 - (byteLength * 8 - bitLength); // extra bits to clear in top byte

  while (true) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    // Clear the unused high bits of the first byte so the candidate stays
    // within (roughly) the bit length of the limit, keeping rejection
    // sampling efficient.
    bytes[0] &= (0xff >> mask);

    let candidate = 0n;
    for (const byte of bytes) {
      candidate = (candidate << 8n) | BigInt(byte);
    }
    if (candidate > 0n && candidate < limitExclusive) {
      return candidate;
    }
    // else: reject and resample (keeps distribution uniform)
  }
}

/* -------------------------------------------------------------------------
   Text <-> field element encoding
   -------------------------------------------------------------------------
   The secret (arbitrary short text) is encoded as a big-endian BigInt of
   its UTF-8 bytes, prefixed with a 0x01 sentinel byte. The sentinel
   preserves leading zero bytes in the original text (e.g. secrets that
   start with a NUL byte) so encode/decode round-trips exactly.
   ------------------------------------------------------------------------- */
function textToFieldElement(text) {
  const utf8 = new TextEncoder().encode(text);
  if (utf8.length === 0) {
    throw new Error('Secret must not be empty.');
  }
  const withSentinel = new Uint8Array(utf8.length + 1);
  withSentinel[0] = 0x01;
  withSentinel.set(utf8, 1);

  let value = 0n;
  for (const byte of withSentinel) {
    value = (value << 8n) | BigInt(byte);
  }
  if (value >= FIELD_PRIME) {
    throw new Error('Secret is too long for this demo\'s field size (max ~64 bytes).');
  }
  return value;
}

function fieldElementToText(value) {
  let hex = value.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  // Drop the leading 0x01 sentinel byte
  const withoutSentinel = bytes.slice(1);
  return new TextDecoder().decode(new Uint8Array(withoutSentinel));
}

/* -------------------------------------------------------------------------
   2. SHAMIR'S SECRET SHARING CORE
   -------------------------------------------------------------------------
   Scheme parameters (fixed for this demo): threshold t = 3, shares n = 5,
   polynomial degree = t - 1 = 2.

   f(x) = a0 + a1*x + a2*x^2   (mod p)

   a0            = the secret
   a1, a2        = cryptographically random coefficients in [1, p-1]
   share i       = ( x = i, y = f(i) mod p )  for i = 1..5

   Any 3 shares determine the degree-2 polynomial uniquely (3 points fix a
   quadratic); Lagrange interpolation recovers f(0) = a0 = the secret.
   Any 2 (or fewer) shares leave one free parameter, so the secret is
   information-theoretically hidden — not just computationally hard to
   find, but mathematically underdetermined.
   ------------------------------------------------------------------------- */

const THRESHOLD = 3;
const TOTAL_SHARES = 5;

function generateShares(secretText) {
  const a0 = textToFieldElement(secretText);
  const a1 = secureRandomBigIntBelow(FIELD_PRIME);
  const a2 = secureRandomBigIntBelow(FIELD_PRIME);
  const coefficients = [a0, a1, a2]; // degree-2 polynomial

  const shares = [];
  for (let x = 1; x <= TOTAL_SHARES; x++) {
    const xBig = BigInt(x);
    // Horner's method: f(x) = ((a2*x) + a1)*x + a0
    let y = 0n;
    for (let i = coefficients.length - 1; i >= 0; i--) {
      y = modAdd(modMul(y, xBig, FIELD_PRIME), coefficients[i], FIELD_PRIME);
    }
    shares.push({ x: xBig, y, id: x });
  }
  return shares;
}

// Lagrange interpolation evaluated at x = 0, i.e. recovering f(0) = secret.
function reconstructSecret(shares) {
  if (shares.length < THRESHOLD) {
    throw new Error(`Recovery denied: at least ${THRESHOLD} shares are required.`);
  }

  // Validate: no duplicate x-coordinates
  const seenX = new Set();
  for (const s of shares) {
    const key = s.x.toString();
    if (seenX.has(key)) {
      throw new Error(`Duplicate share detected (Share ${s.id}). Each share must be unique.`);
    }
    seenX.add(key);
  }

  let secret = 0n;
  for (let i = 0; i < shares.length; i++) {
    const { x: xi, y: yi } = shares[i];
    let numerator = 1n;
    let denominator = 1n;
    for (let j = 0; j < shares.length; j++) {
      if (i === j) continue;
      const xj = shares[j].x;
      numerator = modMul(numerator, modSub(0n, xj, FIELD_PRIME), FIELD_PRIME);
      denominator = modMul(denominator, modSub(xi, xj, FIELD_PRIME), FIELD_PRIME);
    }
    const lagrangeCoeff = modMul(numerator, modInverse(denominator, FIELD_PRIME), FIELD_PRIME);
    secret = modAdd(secret, modMul(yi, lagrangeCoeff, FIELD_PRIME), FIELD_PRIME);
  }

  return fieldElementToText(secret);
}

/* -------------------------------------------------------------------------
   Share serialization: human-copyable string format
   K<id>-<x>-<y in hex>
   ------------------------------------------------------------------------- */
function shareToString(share) {
  return `K${share.id}-${share.x.toString()}-${share.y.toString(16)}`;
}

function parseShareString(str) {
  const trimmed = str.trim();
  const match = trimmed.match(/^K(\d+)-(\d+)-([0-9a-fA-F]+)$/);
  if (!match) {
    throw new Error(`Malformed share: "${str}"`);
  }
  const id = parseInt(match[1], 10);
  const x = BigInt(match[2]);
  const y = BigInt('0x' + match[3]);
  if (x < 1n || x > BigInt(TOTAL_SHARES)) {
    throw new Error(`Malformed share: "${str}" (x out of range)`);
  }
  return { id, x, y };
}

/* =========================================================================
   3. UI WIRING
   ========================================================================= */

const DEMO_SECRET = 'Evidence-Key-Alpha-42';

let currentShares = []; // array of {x, y, id}

const el = (id) => document.getElementById(id);

function setStatus(message, kind) {
  const statusEl = el('statusBadge');
  statusEl.textContent = message;
  statusEl.className = 'status-badge status-' + (kind || 'idle');
}

function renderShareCards(shares) {
  const container = el('shareCards');
  container.innerHTML = '';
  shares.forEach((share) => {
    const card = document.createElement('div');
    card.className = 'share-card';
    card.innerHTML = `
      <div class="share-card-header">
        <label class="share-checkbox-label">
          <input type="checkbox" class="share-checkbox" data-id="${share.id}">
          Share K${share.id}
        </label>
      </div>
      <div class="share-field"><span>X</span><code>${share.x.toString()}</code></div>
      <div class="share-field"><span>Y</span><code class="y-value">${share.y.toString(16)}</code></div>
      <button class="btn btn-small copy-share-btn" data-id="${share.id}">Copy Share</button>
    `;
    container.appendChild(card);
  });

  container.querySelectorAll('.copy-share-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const id = parseInt(btn.dataset.id, 10);
      const share = shares.find((s) => s.id === id);
      copyToClipboard(shareToString(share), btn);
    });
  });

  container.querySelectorAll('.share-checkbox').forEach((cb) => {
    cb.addEventListener('change', updateSelectedCount);
  });

  updateSelectedCount();
}

function updateSelectedCount() {
  const checked = document.querySelectorAll('.share-checkbox:checked').length;
  el('selectedCount').textContent = `${checked} of ${TOTAL_SHARES} shares selected`;
  el('recoverBtn').disabled = false; // validation happens on click, with clear messaging
}

async function copyToClipboard(text, btnEl) {
  try {
    await navigator.clipboard.writeText(text);
    if (btnEl) {
      const original = btnEl.textContent;
      btnEl.textContent = 'Copied!';
      setTimeout(() => { btnEl.textContent = original; }, 1200);
    }
  } catch (e) {
    // Fallback for older mobile browsers
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
  }
}

function showRecoveryResult(message, isSuccess) {
  const resultEl = el('recoveryResult');
  resultEl.textContent = message;
  resultEl.className = 'recovery-result ' + (isSuccess ? 'result-success' : 'result-error');
  resultEl.hidden = false;
}

function handleGenerateShares() {
  const secretInput = el('secretInput').value;
  try {
    if (!secretInput || secretInput.trim().length === 0) {
      throw new Error('Please enter a secret before generating shares.');
    }
    currentShares = generateShares(secretInput);
    renderShareCards(currentShares);
    el('shareSection').hidden = false;
    el('recoveryResult').hidden = true;
    setStatus('5 shares generated', 'success');
  } catch (err) {
    setStatus('Error: ' + err.message, 'error');
    alert(err.message);
  }
}

function handleUseDemoSecret() {
  el('secretInput').value = DEMO_SECRET;
}

function handleCopyAllShares() {
  if (currentShares.length === 0) return;
  const allText = currentShares.map(shareToString).join('\n');
  copyToClipboard(allText, el('copyAllBtn'));
}

function handleRecoverSecret() {
  const checked = Array.from(document.querySelectorAll('.share-checkbox:checked'))
    .map((cb) => parseInt(cb.dataset.id, 10));

  if (checked.length < THRESHOLD) {
    showRecoveryResult(`Recovery denied: at least ${THRESHOLD} shares are required.`, false);
    setStatus('Recovery denied — insufficient shares', 'error');
    return;
  }

  const selectedShares = currentShares.filter((s) => checked.includes(s.id));

  try {
    const recovered = reconstructSecret(selectedShares);
    showRecoveryResult(`SUCCESS — Recovered secret: "${recovered}"`, true);
    setStatus('Secret recovered successfully', 'success');
  } catch (err) {
    showRecoveryResult('Error: ' + err.message, false);
    setStatus('Recovery failed', 'error');
  }
}

/* -------------------------------------------------------------------------
   Automatic test harness
   ------------------------------------------------------------------------- */
function runAutomaticTests() {
  const results = [];
  const testSecret = 'AutoTest-Secret-2026';

  function record(name, passed, detail) {
    results.push({ name, passed, detail });
  }

  // Generate a fresh share set for testing
  let shares;
  try {
    shares = generateShares(testSecret);
  } catch (err) {
    record('Share generation', false, err.message);
    renderTestResults(results);
    return;
  }

  const byId = (ids) => shares.filter((s) => ids.includes(s.id));

  // Test 1: K1+K2+K3 -> PASS
  try {
    const recovered = reconstructSecret(byId([1, 2, 3]));
    record('K1+K2+K3 → PASS', recovered === testSecret, recovered === testSecret ? 'Recovered correctly' : `Got "${recovered}"`);
  } catch (err) {
    record('K1+K2+K3 → PASS', false, err.message);
  }

  // Test 2: K1+K3+K5 -> PASS
  try {
    const recovered = reconstructSecret(byId([1, 3, 5]));
    record('K1+K3+K5 → PASS', recovered === testSecret, recovered === testSecret ? 'Recovered correctly' : `Got "${recovered}"`);
  } catch (err) {
    record('K1+K3+K5 → PASS', false, err.message);
  }

  // Test 3: K2+K4+K5 -> PASS
  try {
    const recovered = reconstructSecret(byId([2, 4, 5]));
    record('K2+K4+K5 → PASS', recovered === testSecret, recovered === testSecret ? 'Recovered correctly' : `Got "${recovered}"`);
  } catch (err) {
    record('K2+K4+K5 → PASS', false, err.message);
  }

  // Test 4: K1+K2 -> REJECTED
  try {
    reconstructSecret(byId([1, 2]));
    record('K1+K2 → REJECTED', false, 'Did not reject as expected');
  } catch (err) {
    record('K1+K2 → REJECTED', true, err.message);
  }

  // Test 5: K4 -> REJECTED
  try {
    reconstructSecret(byId([4]));
    record('K4 → REJECTED', false, 'Did not reject as expected');
  } catch (err) {
    record('K4 → REJECTED', true, err.message);
  }

  // Extra validations (not part of the headline 5, shown separately)
  const extra = [];

  try {
    textToFieldElement('');
    extra.push({ name: 'Empty secret rejected', passed: false, detail: 'Did not throw' });
  } catch (err) {
    extra.push({ name: 'Empty secret rejected', passed: true, detail: err.message });
  }

  try {
    const dupShares = [shares[0], shares[0], shares[1]];
    reconstructSecret(dupShares);
    extra.push({ name: 'Duplicate shares rejected', passed: false, detail: 'Did not throw' });
  } catch (err) {
    extra.push({ name: 'Duplicate shares rejected', passed: true, detail: err.message });
  }

  try {
    parseShareString('not-a-real-share');
    extra.push({ name: 'Malformed share string rejected', passed: false, detail: 'Did not throw' });
  } catch (err) {
    extra.push({ name: 'Malformed share string rejected', passed: true, detail: err.message });
  }

  renderTestResults(results, extra);
}

function renderTestResults(results, extra) {
  const container = el('testResults');
  container.innerHTML = '';

  const passCount = results.filter((r) => r.passed).length;
  const summary = document.createElement('div');
  summary.className = 'test-summary ' + (passCount === results.length ? 'result-success' : 'result-error');
  summary.textContent = `${passCount}/${results.length} PASS`;
  container.appendChild(summary);

  const list = document.createElement('ul');
  list.className = 'test-list';
  results.forEach((r) => {
    const li = document.createElement('li');
    li.className = r.passed ? 'test-pass' : 'test-fail';
    li.textContent = `${r.passed ? '✓' : '✗'} ${r.name} — ${r.detail}`;
    list.appendChild(li);
  });
  container.appendChild(list);

  if (extra && extra.length) {
    const extraHeading = document.createElement('div');
    extraHeading.className = 'test-extra-heading';
    extraHeading.textContent = 'Additional validation checks:';
    container.appendChild(extraHeading);

    const extraList = document.createElement('ul');
    extraList.className = 'test-list';
    extra.forEach((r) => {
      const li = document.createElement('li');
      li.className = r.passed ? 'test-pass' : 'test-fail';
      li.textContent = `${r.passed ? '✓' : '✗'} ${r.name} — ${r.detail}`;
      extraList.appendChild(li);
    });
    container.appendChild(extraList);
  }

  el('testResultsSection').hidden = false;
}

/* -------------------------------------------------------------------------
   Init
   ------------------------------------------------------------------------- */
document.addEventListener('DOMContentLoaded', () => {
  el('useDemoSecretBtn').addEventListener('click', handleUseDemoSecret);
  el('generateSharesBtn').addEventListener('click', handleGenerateShares);
  el('copyAllBtn').addEventListener('click', handleCopyAllShares);
  el('recoverBtn').addEventListener('click', handleRecoverSecret);
  el('runTestsBtn').addEventListener('click', runAutomaticTests);

  setStatus('Ready', 'idle');
});
