# JusticeVault — Shamir's Secret Sharing 3-of-5 Demo

An educational, browser-only prototype demonstrating **Shamir's Secret
Sharing (SSS)** with a 3-of-5 threshold scheme, built as a proposed
building block for a future evidence-management system called
"JusticeVault."

> ⚠️ **This is a proof-of-concept for educational/mentor demonstration
> purposes only.** It is **not** the production JusticeVault system, has
> not been security-reviewed, and must never be used with real
> government, police, court, financial, medical, or personal data.

---

## Problem Statement

Sensitive systems (such as digital evidence archives) often need a way to
ensure that no single person can unilaterally access protected material,
while still allowing a small, defined group of authorized people to
recover access together. Shamir's Secret Sharing solves this by splitting
a secret into N shares such that any K of them (K ≤ N) can reconstruct
it, while any group smaller than K learns nothing about the secret at
all — not even with unlimited computing power.

## Objectives

- Implement Shamir's Secret Sharing from scratch, in the browser, for
  learning purposes.
- Demonstrate a concrete 3-of-5 threshold scheme with a simple, testable
  UI.
- Explain the underlying mathematics (finite fields, polynomials,
  Lagrange interpolation) in plain language.
- Sketch how this primitive could fit into a larger, professionally
  engineered evidence-management architecture — without claiming that
  architecture already exists or is in use anywhere.

## Technologies

- HTML5
- CSS3 (mobile-first, responsive, no framework)
- Vanilla JavaScript (no build step, no npm, no bundler)
- `BigInt` for all finite-field arithmetic (never ordinary `Number`)
- `crypto.getRandomValues()` for all randomness (never `Math.random()`)
- No backend, no database, no external APIs or dependencies
- Deployable as a static site on GitHub Pages

## What Is Shamir's Secret Sharing?

Shamir's Secret Sharing (SSS) is a **secret-sharing / threshold
technique** — it is **not encryption**. Instead of scrambling data for
confidentiality, it distributes a secret across multiple "shares" so
that a minimum number of them (the threshold) must be combined to
recover it. Below that threshold, the remaining shares mathematically
could correspond to *any* possible secret — the missing information
isn't just hard to compute, it genuinely isn't there.

### The 3-of-5 Scheme

- **Total shares (N):** 5
- **Threshold (K):** 3
- Any 3 of the 5 shares reconstruct the secret.
- Any 2 (or fewer) shares reveal nothing about the secret.

This demo builds a random **degree-2 polynomial**:

```
f(x) = a0 + a1x + a2x²   (mod p)
```

where `a0` is the secret and `a1`, `a2` are cryptographically random
coefficients. Each share `i` (for i = 1..5) is the point `(i, f(i) mod p)`.
Because a quadratic curve is uniquely determined by exactly 3 points, any
3 shares suffice to reconstruct `f` via **Lagrange interpolation** and
recover `f(0) = a0`, the secret. This is why the polynomial's degree (2)
is always one less than the threshold (3).

## Mathematics

All arithmetic happens in the finite field `GF(p)`, where `p` is the
well-documented Mersenne prime:

```
p = 2^521 − 1
```

(the same modulus used for the NIST P-521 elliptic curve field). Using a
public, standard prime means there is nothing secret about the field
itself — only the polynomial's coefficients are secret.

Lagrange interpolation at `x = 0` reconstructs the secret from any 3
shares `(x1,y1), (x2,y2), (x3,y3)`:

```
f(0) = Σ yi · Π (0 − xj) / (xi − xj), for j ≠ i   (mod p)
```

All arithmetic — addition, subtraction, multiplication, and modular
inversion (via the extended Euclidean algorithm) — is implemented with
JavaScript's `BigInt` type to avoid any floating-point rounding errors
that would corrupt the secret.

## How to Operate the Demo

1. Open `index.html` (locally or via GitHub Pages).
2. Enter a secret in the **Secret** field, or tap **Use Demo Secret**.
3. Tap **Generate 5 Shares**. Five share cards (K1–K5) appear, each
   showing its `X` and `Y` values.
4. Tap **Copy Share** on any card to copy just that share, or **Copy All
   Shares** to copy all five.
5. Tick the checkboxes on **at least 3** share cards.
6. Tap **Recover Secret**:
   - 3 or more valid, non-duplicate shares → the original secret is
     recovered and shown with a SUCCESS message.
   - Fewer than 3 shares → recovery is denied with the message
     `"Recovery denied: at least 3 shares are required."`
7. Tap **Run Automatic Tests** to see the built-in test suite execute
   the standard combinations described below.

## Testing

The **Run Automatic Tests** button exercises:

| Combination | Expected Result |
|---|---|
| K1 + K2 + K3 | PASS (secret recovered) |
| K1 + K3 + K5 | PASS (secret recovered) |
| K2 + K4 + K5 | PASS (secret recovered) |
| K1 + K2 | REJECTED (insufficient shares) |
| K4 alone | REJECTED (insufficient shares) |

It also runs additional validation checks (shown separately in the UI):

- Rejects an empty secret.
- Rejects duplicate shares presented together.
- Rejects a malformed share string.

A passing run reports **5/5 PASS** for the five headline tests, plus the
results of the additional checks.

## GitHub Pages Deployment (Android-friendly)

This is a fully static site — `index.html`, `style.css`, and `script.js`
— with no build step, so it can be hosted directly on GitHub Pages:

1. On GitHub (web or app), create a **new repository**, e.g.
   `justicevault-shamir-demo`.
2. Upload `index.html`, `style.css`, `script.js`, `README.md`, `LICENSE`,
   and `.gitignore` to the repository root.
3. Go to **Settings → Pages**.
4. Under **Build and deployment**, choose **Deploy from a branch**.
5. Select branch **main**, folder **/root**, then **Save**.
6. After a minute or two, GitHub Pages will publish the site at
   `https://<your-username>.github.io/justicevault-shamir-demo/`.

## Security & Limitations

- This is an **educational prototype**, not a production system.
- It has **not** undergone professional security review or penetration
  testing.
- All computation happens client-side in the browser; nothing is
  transmitted anywhere — but the page also implements no protections
  against a compromised device, malicious browser extension, or
  shoulder-surfing.
- Production systems must use **professionally reviewed, audited
  cryptographic libraries** and proper key-management practices (secure
  share transport and storage, access logging, revocation, etc.), none
  of which this demo implements.
- **Do not use real government, police, court, financial, medical, or
  personal data with this demo.**

## Future JusticeVault Architecture (Proposed, Not Implemented)

This demo represents one building block — protecting a symmetric
encryption key — within a **proposed** future architecture:

```
Digital Evidence
  → AES-256 encryption
  → Encrypted Evidence + AES key
  → Shamir 3-of-5 protects the AES key
  → K1 K2 K3 K4 K5 distributed to 5 authorized custodians
  → Any 3 authorized parties combine their shares
  → Recover the AES key
  → Decrypt the evidence
```

Critically, Shamir's Secret Sharing would protect the **AES encryption
key**, not the evidence file itself — the (typically much larger)
evidence stays encrypted with AES-256, and only the small key is split.

Additional components such an architecture would need — **none of which
are implemented here** — include: authentication, role-based access
control (RBAC), AES-256 encryption of evidence, SHA-256 integrity
verification, digital signatures, chain-of-custody tracking, audit
logging, and a secure submission workflow.

No claim is made that ICJS, CCTNS, any Tamil Nadu Government system, or
any police department or court currently uses this exact implementation.
This is presented purely as a proposed architecture for educational
discussion.

## License

MIT License — see `LICENSE`.
