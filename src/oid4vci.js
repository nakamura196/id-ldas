// OpenID for Verifiable Credential Issuance 1.0 (OID4VCI), pre-authorized code flow only.
// Lets a wallet app (walt.id, EUDI-style wallets) take the membership credential (dc+sd-jwt).
//
//   1. The signed-in person presses "Add to wallet": POST /api/oid4vci/offers makes a one-time offer
//      (QR code / link) and a 6-digit code (tx_code) shown on screen.
//   2. The wallet reads the offer, fetches our metadata, swaps code + tx_code for an access token,
//      gets a nonce, and sends a proof JWT signed with its own key.
//   3. We issue the SD-JWT with every disclosure and bind it to that key (cnf.jwk).
//      The wallet then chooses what to disclose each time it presents.
//
// Secrets (pre-authorized code, access token, nonce, tx_code) are stored only as SHA-256 hashes.
// Wallet endpoints are called server-to-server without cookies, so they carry no session and no CORS
// beyond the public GET documents.
//
// Spec: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
//       RFC 8414 (authorization server metadata)

import { importJWK, jwtVerify, decodeProtectedHeader } from 'jose';

export const CONFIG_ID = 'LdasMember_dc+sd-jwt';
const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const MINUTE = 60 * 1000;
const DAY_MS = 24 * 60 * MINUTE;
const OFFER_TTL = 5 * MINUTE;
const TOKEN_TTL = 5 * MINUTE;
const NONCE_TTL = 5 * MINUTE;
const TX_CODE_LENGTH = 6;
const TX_MAX_ATTEMPTS = 5;            // wrong tx_code this many times and the offer is dead
const OFFERS_PER_USER_PER_DAY = 5;    // each offer can become at most one credential
const OFFERS_PER_DAY = 500;
const NONCES_PER_HOUR = 3000;         // the nonce endpoint is anonymous; this bounds the table
const PROOF_MAX_AGE_S = 300;
const PROOF_ALGS = { ES256: { kty: 'EC', crv: 'P-256' }, EdDSA: { kty: 'OKP', crv: 'Ed25519' } };

// Tables, created by the Store Durable Object (src/store.js) at start-up.
export const OID4VCI_SCHEMA = `
  -- One row per offer. The pre-authorized code is the secret in the offer link; only its hash is kept.
  CREATE TABLE IF NOT EXISTS oid4vci_offers (
    code_hash  TEXT PRIMARY KEY,           -- SHA-256 of the pre-authorized code
    user_id    TEXT NOT NULL REFERENCES users(id),
    tx_hash    TEXT NOT NULL,              -- SHA-256 of code + ':' + tx_code
    attempts   INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,                    -- set once, when exchanged for an access token
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS oid4vci_tokens (
    token_hash TEXT PRIMARY KEY,           -- SHA-256 of the access token
    user_id    TEXT NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL,
    used_at    INTEGER                     -- one credential per token
  );
  CREATE TABLE IF NOT EXISTS oid4vci_nonces (
    nonce_hash TEXT PRIMARY KEY,           -- SHA-256 of c_nonce; deleted when used
    expires_at INTEGER NOT NULL
  );
`;

// --------------------------------------------------------------------------------------------
// Entry points (called from src/index.js). `d` carries helpers from index.js:
//   { db, currentUser, issueMemberSdJwt, hitLimit, jsonApi, jsonApiError }
// --------------------------------------------------------------------------------------------

// Wallet-facing routes. Returns a Response, or null when the path is not ours.
export async function oid4vciRoute(request, url, env, d) {
  const route = `${request.method} ${url.pathname}`;
  try {
    if (route === 'GET /.well-known/openid-credential-issuer') return publicJson(issuerMetadata(url));
    if (route === 'GET /.well-known/oauth-authorization-server') return publicJson(authServerMetadata(url));
    if (request.method === 'GET' && url.pathname.startsWith('/oid4vci/offer/')) return await offerDocument(url, env, d);
    if (route === 'POST /oid4vci/token') return await token(request, env, d);
    if (route === 'POST /oid4vci/nonce') return await nonce(env, d);
    if (route === 'POST /oid4vci/credential') return await credential(request, url, env, d);
    if (url.pathname.startsWith('/oid4vci/')) return oauthError(404, 'invalid_request', 'not found');
    return null;
  } catch (e) {
    console.error(e);
    return oauthError(e.status || 500, e.oauthError || 'server_error', e.message);
  }
}

// POST /api/oid4vci/offers (signed-in, same-origin; the Origin check is in index.js for all /api/).
export async function createOffer(request, url, env, d) {
  const user = await d.currentUser(request, env);
  if (!user) return d.jsonApiError('log in first', 401);
  if (!eligible(user)) return d.jsonApiError('not approved yet', 403);
  if (!(await d.hitLimit(env, `oid4vci:offer:user:${user.id}`, OFFERS_PER_USER_PER_DAY, DAY_MS))) {
    return d.jsonApiError(`you can add the credential to a wallet at most ${OFFERS_PER_USER_PER_DAY} times a day`, 429);
  }
  if (!(await d.hitLimit(env, 'oid4vci:offer:all', OFFERS_PER_DAY, DAY_MS))) {
    return d.jsonApiError('too many wallet requests today; try again tomorrow', 429);
  }
  const code = randomToken(32);
  const txCode = randomDigits(TX_CODE_LENGTH);
  const now = Date.now();
  const expiresAt = now + OFFER_TTL;
  const db = d.db(env);
  // Old rows are no use to anyone; clear them while we are here.
  await db.batch([
    db.prepare('DELETE FROM oid4vci_offers WHERE expires_at < ?').bind(now - DAY_MS),
    db.prepare('DELETE FROM oid4vci_tokens WHERE expires_at < ?').bind(now - DAY_MS),
    db.prepare('INSERT INTO oid4vci_offers (code_hash, user_id, tx_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(await sha256(code), user.id, await sha256(`${code}:${txCode}`), expiresAt, now),
  ]);
  const offerUrl = `${url.origin}/oid4vci/offer/${code}`;
  return d.jsonApi({
    type: 'credential-offer',
    id: (await sha256(code)).slice(0, 12),
    attributes: {
      offerUri: `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUrl)}`,
      txCode,
      expiresAt: new Date(expiresAt).toISOString(),
      credentialConfigurationId: CONFIG_ID,
    },
  }, { headers: { 'Cache-Control': 'no-store' } });
}

// --------------------------------------------------------------------------------------------
// Metadata
// --------------------------------------------------------------------------------------------

function vctFor(url) {
  // Must be byte-identical to the `vct` inside the credential (src/index.js issueMemberSdJwt).
  return `${url.origin}/credentials/member/v1`;
}

const CLAIM_LABELS = [
  ['name', 'Name', '氏名'],
  ['orcid', 'ORCID iD', 'ORCID iD'],
  ['memberOf', 'Member of', '所属団体'],
  ['affiliation', 'Affiliation', '所属機関'],
  ['emailDomain', 'Email domain', 'メールのドメイン'],
  ['wallet', 'Wallet address', 'ウォレットのアドレス'],
];

function issuerMetadata(url) {
  const o = url.origin;
  return {
    credential_issuer: o,
    authorization_servers: [o],
    credential_endpoint: `${o}/oid4vci/credential`,
    nonce_endpoint: `${o}/oid4vci/nonce`,
    display: [{ name: 'LDAS ID', locale: 'en' }, { name: 'LDAS ID', locale: 'ja' }],
    credential_configurations_supported: {
      [CONFIG_ID]: {
        format: 'dc+sd-jwt',
        scope: CONFIG_ID,
        vct: vctFor(url),
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['EdDSA'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: Object.keys(PROOF_ALGS) } },
        credential_metadata: {
          display: [
            { name: 'LDAS member credential', locale: 'en', description: 'Issued by LDAS ID (id.ldas.jp)' },
            { name: 'LDAS 会員証', locale: 'ja', description: 'LDAS ID（id.ldas.jp）が発行' },
          ],
          claims: CLAIM_LABELS.map(([k, en, ja]) => ({
            path: [k],
            display: [{ name: en, locale: 'en' }, { name: ja, locale: 'ja' }],
          })),
        },
      },
    },
  };
}

function authServerMetadata(url) {
  const o = url.origin;
  return {
    issuer: o,
    token_endpoint: `${o}/oid4vci/token`,
    // RFC 8414 makes this field REQUIRED (walt.id fails without it). There is no authorization endpoint
    // here; "code" is listed only because some wallets reject an empty list.
    response_types_supported: ['code'],
    grant_types_supported: [PRE_AUTH_GRANT],
    token_endpoint_auth_methods_supported: ['none'],
    'pre-authorized_grant_anonymous_access_supported': true,
  };
}

// --------------------------------------------------------------------------------------------
// Offer, token, nonce, credential
// --------------------------------------------------------------------------------------------

async function offerDocument(url, env, d) {
  const code = url.pathname.slice('/oid4vci/offer/'.length);
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(code)) return oauthError(404, 'invalid_request', 'unknown offer');
  const row = await d.db(env).prepare(
    'SELECT expires_at FROM oid4vci_offers WHERE code_hash = ? AND used_at IS NULL AND expires_at > ? AND attempts < ?',
  ).bind(await sha256(code), Date.now(), TX_MAX_ATTEMPTS).first();
  if (!row) return oauthError(404, 'invalid_request', 'unknown, expired or used offer');
  return publicJson({
    credential_issuer: url.origin,
    credential_configuration_ids: [CONFIG_ID],
    grants: {
      [PRE_AUTH_GRANT]: {
        'pre-authorized_code': code,
        tx_code: {
          input_mode: 'numeric',
          length: TX_CODE_LENGTH,
          description: 'Enter the 6-digit code shown on the LDAS ID page / LDAS ID の画面に出ている 6 桁の番号',
        },
      },
    },
  }, { 'Cache-Control': 'no-store' });
}

async function token(request, env, d) {
  const form = await readForm(request);
  if (form.get('grant_type') !== PRE_AUTH_GRANT) {
    return oauthError(400, 'unsupported_grant_type', 'only the pre-authorized code grant is supported');
  }
  const code = form.get('pre-authorized_code') || '';
  const txCode = form.get('tx_code') || '';
  if (!code) return oauthError(400, 'invalid_request', 'pre-authorized_code is missing');
  const now = Date.now();
  // One statement: count the attempt and, only if the tx_code matches, mark the code used.
  // Two requests at the same moment cannot both get a token, and guesses are capped.
  const row = await d.db(env).prepare(
    `UPDATE oid4vci_offers SET attempts = attempts + 1,
       used_at = CASE WHEN tx_hash = ? THEN ? ELSE used_at END
     WHERE code_hash = ? AND used_at IS NULL AND attempts < ? AND expires_at > ?
     RETURNING user_id, used_at, attempts`,
  ).bind(await sha256(`${code}:${txCode}`), now, await sha256(code), TX_MAX_ATTEMPTS, now).first();
  if (!row) return oauthError(400, 'invalid_grant', 'the code is unknown, expired, already used, or blocked after too many tries');
  if (Number(row.used_at) !== now) {
    const left = TX_MAX_ATTEMPTS - Number(row.attempts);
    return oauthError(400, 'invalid_grant', `wrong tx_code (${left} ${left === 1 ? 'try' : 'tries'} left)`);
  }
  const accessToken = randomToken(32);
  await d.db(env).prepare('INSERT INTO oid4vci_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(await sha256(accessToken), row.user_id, now + TOKEN_TTL).run();
  const cNonce = await newNonce(env, d);
  return json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: TOKEN_TTL / 1000,
    // Not in the 1.0 token response any more, but older wallets need it; 1.0 wallets ignore it.
    c_nonce: cNonce,
    c_nonce_expires_in: NONCE_TTL / 1000,
  }, 200, { 'Cache-Control': 'no-store' });
}

async function nonce(env, d) {
  if (!(await d.hitLimit(env, 'oid4vci:nonce:all', NONCES_PER_HOUR, 60 * MINUTE))) {
    return oauthError(429, 'temporarily_unavailable', 'too many nonce requests; try again later');
  }
  return json({ c_nonce: await newNonce(env, d) }, 200, { 'Cache-Control': 'no-store' });
}

async function newNonce(env, d) {
  const value = randomToken(24);
  const now = Date.now();
  const db = d.db(env);
  await db.batch([
    db.prepare('DELETE FROM oid4vci_nonces WHERE expires_at < ?').bind(now),
    db.prepare('INSERT INTO oid4vci_nonces (nonce_hash, expires_at) VALUES (?, ?)').bind(await sha256(value), now + NONCE_TTL),
  ]);
  return value;
}

async function credential(request, url, env, d) {
  const auth = request.headers.get('Authorization') || '';
  const m = /^Bearer ([A-Za-z0-9_-]{20,100})$/.exec(auth);
  if (!m) return oauthError(401, 'invalid_token', 'Bearer access token required', { 'WWW-Authenticate': 'Bearer' });
  const tokenHash = await sha256(m[1]);
  const db = d.db(env);
  const now = Date.now();
  const tok = await db.prepare('SELECT user_id FROM oid4vci_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?')
    .bind(tokenHash, now).first();
  if (!tok) return oauthError(401, 'invalid_token', 'unknown, expired or used access token', { 'WWW-Authenticate': 'Bearer error="invalid_token"' });

  const body = await request.json().catch(() => null);
  if (!body || typeof body !== 'object') return oauthError(400, 'invalid_credential_request', 'JSON body required');
  if (body.credential_configuration_id !== CONFIG_ID) {
    return oauthError(400, 'unknown_credential_configuration', `use credential_configuration_id "${CONFIG_ID}"`);
  }
  // 1.0 sends proofs: { jwt: [...] }. Accept the older single `proof` too.
  let proofs = [];
  if (body.proofs && Array.isArray(body.proofs.jwt)) proofs = body.proofs.jwt;
  else if (body.proof && body.proof.proof_type === 'jwt' && typeof body.proof.jwt === 'string') proofs = [body.proof.jwt];
  if (proofs.length !== 1 || typeof proofs[0] !== 'string') {
    return oauthError(400, 'invalid_proof', 'exactly one jwt proof is required (batch issuance is not supported)');
  }

  let holder;
  try {
    holder = await verifyProof(proofs[0], url.origin);
  } catch (e) {
    return oauthError(400, 'invalid_proof', e.message);
  }
  // The nonce is used up here, whatever happens next.
  const used = await db.prepare('DELETE FROM oid4vci_nonces WHERE nonce_hash = ? AND expires_at > ? RETURNING nonce_hash')
    .bind(await sha256(holder.nonce), now).first();
  if (!used) return oauthError(400, 'invalid_nonce', 'the nonce is unknown, expired or already used; get a new one from the nonce endpoint');
  // The token is used up only now, so a wallet whose first proof had a stale nonce can retry.
  const took = await db.prepare('UPDATE oid4vci_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? RETURNING user_id')
    .bind(now, tokenHash, now).first();
  if (!took) return oauthError(401, 'invalid_token', 'access token already used', { 'WWW-Authenticate': 'Bearer error="invalid_token"' });

  // Check the person again: they may have been rejected since the offer was made.
  const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(took.user_id).first();
  if (!user || !eligible(user)) return oauthError(403, 'credential_request_denied', 'this account cannot receive a credential');

  const { issued } = await d.issueMemberSdJwt(url, env, user, { cnfJwk: holder.jwk });
  return json({ credentials: [{ credential: issued }] }, 200, { 'Cache-Control': 'no-store' });
}

// Proof of possession (OID4VCI 1.0, appendix F.1): a JWT signed by the key the credential will be
// bound to, with that public key in the header. Returns { jwk, nonce } or throws.
async function verifyProof(jwt, issuerOrigin) {
  let header;
  try { header = decodeProtectedHeader(jwt); } catch { throw new Error('proof is not a JWT'); }
  if (header.typ !== 'openid4vci-proof+jwt') throw new Error('proof typ must be openid4vci-proof+jwt');
  const want = PROOF_ALGS[header.alg];
  if (!want) throw new Error(`proof alg must be one of ${Object.keys(PROOF_ALGS).join(', ')}`);
  const raw = header.jwk;
  if (!raw || typeof raw !== 'object') throw new Error('proof header must carry the public key as jwk');
  if (raw.d !== undefined) throw new Error('proof jwk must not contain a private key');
  if (raw.kty !== want.kty || raw.crv !== want.crv) throw new Error(`alg ${header.alg} needs a ${want.kty} ${want.crv} key`);
  if (header.x5c) throw new Error('x5c proofs are not supported');
  const jwk = {
    kty: raw.kty,
    crv: raw.crv,
    x: raw.x,
    ...(raw.kty === 'EC' ? { y: raw.y } : {}),
    // walt.id puts the RFC 7638 thumbprint here; keep it so a verifier can match the key by kid.
    ...(typeof raw.kid === 'string' && raw.kid.length <= 128 ? { kid: raw.kid } : {}),
  };
  let payload;
  try {
    const key = await importJWK({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, ...(jwk.y ? { y: jwk.y } : {}) }, header.alg);
    ({ payload } = await jwtVerify(jwt, key, {
      algorithms: [header.alg],
      typ: 'openid4vci-proof+jwt',
      audience: issuerOrigin,
    }));
  } catch (e) {
    throw new Error(`proof signature or claims invalid: ${e.code || e.message}`);
  }
  const nowS = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== 'number') throw new Error('proof iat is missing');
  if (payload.iat > nowS + 60 || nowS - payload.iat > PROOF_MAX_AGE_S) throw new Error('proof iat is too old or in the future');
  if (typeof payload.nonce !== 'string' || !payload.nonce) throw new Error('proof nonce is missing');
  return { jwk, nonce: payload.nonce };
}

// --------------------------------------------------------------------------------------------
// Small helpers
// --------------------------------------------------------------------------------------------

function eligible(user) {
  return user.status === 'approved' || user.status === 'verified';
}

async function readForm(request) {
  const type = request.headers.get('Content-Type') || '';
  if (!type.startsWith('application/x-www-form-urlencoded')) return new URLSearchParams();
  return new URLSearchParams(await request.text());
}

function randomToken(bytes) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Uniform digits: draw bytes and drop 250-255 so every digit is equally likely.
function randomDigits(n) {
  let out = '';
  while (out.length < n) {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    for (const x of b) if (x < 250 && out.length < n) out += String(x % 10);
  }
  return out;
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((x) => x.toString(16).padStart(2, '0')).join('');
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

// Public documents a browser-based wallet may read from another origin (no cookies involved).
function publicJson(body, headers = {}) {
  return json(body, 200, { 'Access-Control-Allow-Origin': '*', ...headers });
}

// OAuth 2.0 / OID4VCI error shape: { error, error_description }.
function oauthError(status, error, description, headers = {}) {
  return json({ error, error_description: description }, status, { 'Cache-Control': 'no-store', ...headers });
}
