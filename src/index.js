// id.ldas.jp — a small ID server for learning DID/VC + passkeys on Cloudflare Workers.
//
// What it does:
//   1. Publishes its own public key as a DID document (did:web) at /.well-known/did.json
//   2. New accounts come only from "Sign in with ORCID" and are approved automatically;
//      an admin (ADMIN_ORCIDS) can reject (block) someone afterwards
//   3. A person may link an Ethereum wallet by signing a message with it (MetaMask)
//   4. A signed-in person may add a passkey to come back without ORCID
//   5. Issues a signed membership credential (VC, as a JWT). With a linked wallet, the credential is
//      about the wallet (did:pkh), so only whoever holds that wallet can show it is theirs
// Anyone can check that credential with only the public key in did.json; they never ask this server's DB.

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { SignJWT, importJWK, generateKeyPair, exportJWK, createRemoteJWKSet, jwtVerify } from 'jose';
import { SdJwtInstance, uint8ArrayToBase64Url } from '@sd-jwt/core';
import { db } from './store.js';
import { recoverAddress, checksum } from './eth.js';

export { Store } from './store.js';

const RP_NAME = 'LDAS ID';
const CHALLENGE_TTL = 5 * 60 * 1000;
const SESSION_TTL = 24 * 60 * 60 * 1000;
const VC_TTL_DAYS = 30;
const ORCID = 'https://orcid.org';
const orcidKeys = createRemoteJWKSet(new URL(`${ORCID}/oauth/jwks`));

export default {
  async fetch(request, env) {
    return withSecurityHeaders(await route(request, env));
  },
};

// Pages of this site must not be framed by other sites (clickjacking on the consent and wallet screens).
function withSecurityHeaders(response) {
  const r = new Response(response.body, response);
  r.headers.set('X-Frame-Options', 'DENY');
  if (!r.headers.has('Content-Security-Policy')) r.headers.set('Content-Security-Policy', "frame-ancestors 'none'");
  r.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  return r;
}

// State-changing API calls must come from this site's own pages. SameSite=Lax cookies are still sent
// from sibling *.ldas.jp sites (same "site"), so check the browser's Origin / Sec-Fetch-Site too.
// Non-browser clients (curl) send neither header and are let through; they have no victim's cookie.
function isCrossOriginWrite(request, url) {
  if (request.method === 'GET' || request.method === 'HEAD' || request.method === 'OPTIONS') return false;
  const origin = request.headers.get('Origin');
  if (origin && origin !== url.origin) return true;
  const site = request.headers.get('Sec-Fetch-Site');
  return !!site && site !== 'same-origin' && site !== 'none';
}

async function route(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/.well-known/did.json') return await didDocument(url, env);
      if (url.pathname === '/status/1') return await statusListCredential(url, env);
      if (url.pathname === '/auth/orcid') return await orcidStart(url, env);
      if (url.pathname === '/auth/orcid/callback') return await orcidCallback(request, url, env);
      if (url.pathname === '/auth/grdm') return await grdmStart(request, url, env);
      if (url.pathname === '/auth/grdm/callback') return await grdmCallback(request, url, env);
      if (url.pathname.startsWith('/api/')) {
        if (isCrossOriginWrite(request, url)) return jsonApiError('cross-origin request refused', 403);
        return await api(request, url, env);
      }
      // The admin page itself is only served to admins (its data API checks again).
      if (url.pathname === '/admin' || url.pathname === '/admin.html') {
        const user = await currentUser(request, env);
        if (!user || !isAdminOrcid(env, user.orcid)) return Response.redirect(`${url.origin}/`, 302);
      }
    } catch (e) {
      console.error(e);
      if (url.pathname.startsWith('/api/')) return jsonApiError(e.message, e.status || 400);
      return json({ error: e.message }, e.status || 400);
    }
    return env.ASSETS.fetch(request);
}

async function api(request, url, env) {
  const route = `${request.method} ${url.pathname}`;
  switch (route) {
    case 'POST /api/register/options': return registerOptions(request, url, env);
    case 'POST /api/register/verify':  return registerVerify(request, url, env);
    case 'POST /api/login/options':    return loginOptions(url, env);
    case 'POST /api/login/verify':     return loginVerify(request, url, env);
    case 'GET /api/me':                return me(request, url, env);
    case 'POST /api/logout':           return logout(request, env);
    case 'POST /api/credential':       return issueCredential(request, url, env);
    case 'POST /api/credential/revoke': return revokeOwnCredential(request, env);
    case 'POST /api/wallet/challenge': return walletChallenge(request, url, env);
    case 'POST /api/wallet/verify':    return walletVerify(request, env);
    case 'POST /api/email/challenge':      return emailChallenge(request, url, env);
    case 'POST /api/email/verify':         return emailVerify(request, env);
    case 'POST /api/auth/email/start':     return emailLoginStart(request, url, env);
    case 'POST /api/auth/email/verify':    return emailLoginVerify(request, env);
    case 'GET /api/admin/users':           return adminUsers(request, env);
    case 'POST /api/admin/decide':     return adminDecide(request, env);
  }
  return jsonApiError('not found', 404);
}

// ---------------------------------------------------------------------------
// DID (did:web): the server's identity is its domain name.
//   id.ldas.jp       -> did:web:id.ldas.jp       -> https://id.ldas.jp/.well-known/did.json
//   localhost:8787   -> did:web:localhost%3A8787 -> http(s)://localhost:8787/.well-known/did.json
// ---------------------------------------------------------------------------

function didFor(url) {
  return `did:web:${url.host.replace(':', '%3A')}`;
}

async function didDocument(url, env) {
  const did = didFor(url);
  const { publicJwk } = await issuerKey(url, env);
  return json({
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: did,
    verificationMethod: [{
      id: `${did}#key-1`,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: publicJwk,
    }],
    // "assertionMethod" = this key may be used to sign statements (credentials) on behalf of the DID.
    assertionMethod: [`${did}#key-1`],
  }, 200, { 'Access-Control-Allow-Origin': '*' }); // public: any app may fetch it to verify
}

// The issuer's private key lives only in a Worker secret (ISSUER_JWK), never in the DB or the code.
// On localhost without the secret, a throwaway key is made per process so you can try things freely.
let devKey;
async function issuerKey(url, env) {
  let privateJwk;
  if (env.ISSUER_JWK) {
    privateJwk = JSON.parse(env.ISSUER_JWK);
  } else if (url.hostname === 'localhost') {
    if (!devKey) {
      const { privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
      devKey = await exportJWK(privateKey);
    }
    privateJwk = devKey;
  } else {
    throw new Error('ISSUER_JWK secret is not set');
  }
  const { d, ...publicJwk } = privateJwk;
  return { privateKey: await importJWK(privateJwk, 'EdDSA'), publicJwk };
}

// ---------------------------------------------------------------------------
// Passkeys (WebAuthn). The DB keeps only the public half of each passkey.
// ---------------------------------------------------------------------------

// Adding a passkey needs an existing (ORCID) sign-in: passkeys are a faster way back, not a way in.
async function registerOptions(request, url, env) {
  const user = await currentUser(request, env);
  if (!user) return jsonApiError('sign in with ORCID first', 401);
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: url.hostname,
    userName: user.orcid ? `${user.name} (${user.orcid})` : user.name,
    userID: new TextEncoder().encode(user.id),
    attestationType: 'none',
    // residentKey "required" = the passkey remembers the account, so login needs no username.
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
  });
  return withChallenge(env, options, { userId: user.id });
}

async function registerVerify(request, url, env) {
  const ch = await takeChallenge(request, env);
  const response = await request.json();
  const { verified, registrationInfo } = await verifyRegistrationResponse({
    response,
    expectedChallenge: ch.challenge,
    expectedOrigin: url.origin,
    expectedRPID: url.hostname,
  });
  if (!verified) throw new Error('registration not verified');
  const cred = registrationInfo.credential;
  const now = Date.now();
  await db(env).prepare('INSERT INTO credentials (id, user_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind(cred.id, ch.user_id, isoBase64URL.fromBuffer(cred.publicKey), cred.counter, JSON.stringify(cred.transports ?? []), now).run();
  return jsonApi({ type: 'passkey', id: cred.id, attributes: { ok: true } });
}

async function loginOptions(url, env) {
  // No allowCredentials: the browser offers whichever passkeys it has for this site.
  const options = await generateAuthenticationOptions({ rpID: url.hostname, userVerification: 'preferred' });
  return withChallenge(env, options, {});
}

async function loginVerify(request, url, env) {
  const ch = await takeChallenge(request, env);
  const response = await request.json();
  const row = await db(env).prepare('SELECT * FROM credentials WHERE id = ?').bind(response.id).first();
  if (!row) throw new Error('unknown passkey (registered on another server?)');
  const { verified, authenticationInfo } = await verifyAuthenticationResponse({
    response,
    expectedChallenge: ch.challenge,
    expectedOrigin: url.origin,
    expectedRPID: url.hostname,
    credential: {
      id: row.id,
      publicKey: isoBase64URL.toBuffer(row.public_key),
      counter: row.counter,
      transports: JSON.parse(row.transports || '[]'),
    },
  });
  if (!verified) throw new Error('login not verified');
  await db(env).prepare('UPDATE credentials SET counter = ? WHERE id = ?').bind(authenticationInfo.newCounter, row.id).run();
  return startSession(env, row.user_id);
}

async function withChallenge(env, options, { userId = null, name = null }) {
  const id = crypto.randomUUID();
  await db(env).prepare('INSERT INTO challenges (id, challenge, user_id, name, expires_at) VALUES (?, ?, ?, ?, ?)')
    .bind(id, options.challenge, userId, name, Date.now() + CHALLENGE_TTL).run();
  return jsonApi(
    { type: 'webauthn-options', id, attributes: options },
    { headers: { 'Set-Cookie': cookie('ch', id, CHALLENGE_TTL) } },
  );
}

// ---------------------------------------------------------------------------
// Sign in with ORCID (OpenID Connect). ORCID tells us "this person controls ORCID iD X".
// It does not tell us they are a researcher we trust; that is the admin's approval below.
// ---------------------------------------------------------------------------

function safeNextPath(raw) {
  if (!raw || typeof raw !== 'string') return '/';
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return '/';
  return raw;
}

async function orcidStart(url, env) {
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const nextPath = safeNextPath(url.searchParams.get('next'));
  await db(env).prepare('INSERT INTO challenges (id, challenge, user_id, name, expires_at) VALUES (?, ?, NULL, ?, ?)')
    .bind(state, nonce, nextPath, Date.now() + CHALLENGE_TTL).run();
  const auth = new URL(`${ORCID}/oauth/authorize`);
  auth.search = new URLSearchParams({
    client_id: env.ORCID_CLIENT_ID,
    response_type: 'code',
    scope: 'openid',
    redirect_uri: `${url.origin}/auth/orcid/callback`,
    state,
    nonce,
  });
  return new Response(null, { status: 302, headers: { Location: auth.toString(), 'Set-Cookie': cookie('ch', state, CHALLENGE_TTL) } });
}

async function orcidCallback(request, url, env) {
  const state = url.searchParams.get('state');
  if (!state || state !== cookies(request).ch) throw new Error('state mismatch; start again');
  const ch = await takeChallenge(request, env);
  if (url.searchParams.get('error')) return Response.redirect(`${url.origin}/?orcid=cancelled`, 302);

  // Exchange the one-time code for tokens, server to server (the client secret never reaches the browser).
  const r = await fetch(`${ORCID}/oauth/token`, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.ORCID_CLIENT_ID,
      client_secret: env.ORCID_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code: url.searchParams.get('code'),
      redirect_uri: `${url.origin}/auth/orcid/callback`,
    }),
  });
  const tokens = await r.json();
  if (!r.ok || !tokens.id_token) throw new Error(`ORCID token exchange failed: ${tokens.error_description || r.status}`);

  // The id_token is itself a signed JWT from ORCID: check it with ORCID's public keys.
  const { payload } = await jwtVerify(tokens.id_token, orcidKeys, { issuer: ORCID, audience: env.ORCID_CLIENT_ID });
  if (payload.nonce !== ch.challenge) throw new Error('nonce mismatch');
  const orcid = payload.sub;
  const name = tokens.name || [payload.given_name, payload.family_name].filter(Boolean).join(' ') || orcid;

  let user = await db(env).prepare('SELECT id FROM users WHERE orcid = ?').bind(orcid).first();
  if (!user) {
    user = { id: crypto.randomUUID() };
    // Having an ORCID iD is enough (decided 2026-10-02): approved at once, an admin can reject later.
    await db(env).prepare("INSERT INTO users (id, name, created_at, orcid, status, approved_at) VALUES (?, ?, ?, ?, 'approved', ?)")
      .bind(user.id, name, Date.now(), orcid, Date.now()).run();
  } else {
    await db(env).prepare('UPDATE users SET name = ? WHERE id = ?').bind(name, user.id).run();
  }
  return new Response(null, { status: 302, headers: { Location: safeNextPath(ch.name), 'Set-Cookie': await newSession(env, user.id) } });
}

function isAdminOrcid(env, orcid) {
  return !!orcid && (env.ADMIN_ORCIDS || '').split(',').map((s) => s.trim()).includes(orcid);
}

async function takeChallenge(request, env) {
  const id = cookies(request).ch;
  if (!id) throw new Error('no challenge; start again');
  const ch = await db(env).prepare('DELETE FROM challenges WHERE id = ? RETURNING *').bind(id).first();
  if (!ch || ch.expires_at < Date.now()) throw new Error('challenge expired; start again');
  return ch;
}

// ---------------------------------------------------------------------------
// Sessions (an ordinary random cookie; nothing DID-specific here)
// ---------------------------------------------------------------------------

async function newSession(env, userId) {
  const id = crypto.randomUUID();
  await db(env).prepare('INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(id, userId, Date.now() + SESSION_TTL).run();
  return cookie('sid', id, SESSION_TTL);
}

async function startSession(env, userId) {
  return jsonApi(
    { type: 'session', id: userId, attributes: { ok: true } },
    { headers: { 'Set-Cookie': await newSession(env, userId) } },
  );
}

async function currentUser(request, env) {
  const sid = cookies(request).sid;
  if (!sid) return null;
  return db(env).prepare(
    'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > ?'
  ).bind(sid, Date.now()).first();
}

async function me(request, url, env) {
  const user = await currentUser(request, env);
  // localhost targets are for development only: on the real site they would let a link send
  // someone's credential to whatever is listening on their own machine.
  const local = isLocalHost(url);
  const allowedReturnOrigins = (env.ALLOWED_RETURN_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((p) => local || !/^https?:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(p));
  const data = user
    ? {
        type: 'user',
        id: user.id,
        attributes: {
          name: user.name,
          orcid: user.orcid,
          status: user.status,
          wallet: user.wallet,
          affiliation: user.affiliation,
          email_domain: user.email_domain,
          affiliation_method: user.affiliation_method,
          affiliation_verified_at: user.affiliation_verified_at,
          isAdmin: isAdminOrcid(env, user.orcid),
        },
      }
    : null;
  return jsonApi(data, {
    meta: {
      allowedReturnOrigins,
      grdmEnabled: Boolean(env.GRDM_CLIENT_ID && env.GRDM_CLIENT_SECRET),
      emailDeliveryConfigured: Boolean(env.RESEND_API_KEY),
    },
  });
}

async function logout(request, env) {
  const sid = cookies(request).sid;
  if (sid) await db(env).prepare('DELETE FROM sessions WHERE id = ?').bind(sid).run();
  return jsonApi(
    { type: 'session', id: 'current', attributes: { ok: true } },
    { headers: { 'Set-Cookie': cookie('sid', '', 0) } },
  );
}

// ---------------------------------------------------------------------------
// Verifiable Credential (W3C VC Data Model 2.0, secured as a JWT: "vc+jwt")
// ---------------------------------------------------------------------------

const STATUS_LIST_BYTES = 16384; // 131,072 bits (W3C Bitstring Status List v1.0 minimum size)

async function encodeBitstring(revokedIndices) {
  const bytes = new Uint8Array(STATUS_LIST_BYTES);
  for (const idx of revokedIndices) {
    if (idx >= 0 && idx < STATUS_LIST_BYTES * 8) {
      // W3C Bitstring Status List uses MSB-first bit ordering inside each byte.
      bytes[idx >> 3] |= 1 << (7 - (idx & 7));
    }
  }
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'));
  const compressed = new Uint8Array(await new Response(stream).arrayBuffer());
  let bin = '';
  for (let i = 0; i < compressed.length; i++) bin += String.fromCharCode(compressed[i]);
  const b64url = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `u${b64url}`; // multibase base64url (no padding)
}

async function statusListCredential(url, env) {
  const did = didFor(url);
  const { privateKey } = await issuerKey(url, env);
  const rejectedRows = await db(env).prepare("SELECT status_index FROM users WHERE status = 'rejected' AND status_index IS NOT NULL").all();
  const selfRevokedRows = await db(env).prepare('SELECT idx FROM revoked_indices').all();
  const revokedIndices = [
    ...rejectedRows.map((r) => Number(r.status_index)),
    ...selfRevokedRows.map((r) => Number(r.idx)),
  ];
  const encodedList = await encodeBitstring(revokedIndices);
  const now = new Date();
  const statusCred = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `${url.origin}/status/1`,
    type: ['VerifiableCredential', 'BitstringStatusListCredential'],
    issuer: did,
    iss: did,
    iat: Math.floor(now.getTime() / 1000),
    validFrom: now.toISOString(),
    credentialSubject: {
      id: `${url.origin}/status/1#list`,
      type: 'BitstringStatusList',
      statusPurpose: 'revocation',
      encodedList,
    },
  };
  // W3C Bitstring Status List v1.0: sign the status list credential as a vc+jwt so verifiers can authenticate it.
  const signedJwt = await new SignJWT(statusCred)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+jwt', kid: `${did}#key-1` })
    .setIssuedAt(Math.floor(now.getTime() / 1000))
    .sign(privateKey);

  return new Response(signedJwt, {
    status: 200,
    headers: {
      'Content-Type': 'application/vc+jwt',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
    },
  });
}

const STATUS_LIST_CAPACITY = STATUS_LIST_BYTES * 8;
// Positions kept free for new members, so self-revocation alone can never fill the list.
const STATUS_LIST_RESERVE = 10000;
const SELF_REVOKE_PER_USER_PER_DAY = 3;
const SELF_REVOKE_PER_DAY = 300;
const DAY_MS = 86400 * 1000;

// The next free position, computed inside one SQL statement so two requests cannot take the same one.
const NEXT_STATUS_INDEX_SQL = `(SELECT MAX(m) + 1 FROM (
  SELECT COALESCE(MAX(status_index), -1) AS m FROM users
  UNION ALL SELECT COALESCE(MAX(idx), -1) AS m FROM revoked_indices))`;

async function ensureStatusIndex(env, user) {
  if (user.status_index !== null && user.status_index !== undefined) return Number(user.status_index);
  await db(env).prepare(`UPDATE users SET status_index = ${NEXT_STATUS_INDEX_SQL} WHERE id = ? AND status_index IS NULL`)
    .bind(user.id).run();
  const row = await db(env).prepare('SELECT status_index FROM users WHERE id = ?').bind(user.id).first();
  return Number(row.status_index);
}

// A position outside the list cannot be revoked, so never issue a credential that points there.
function assertRevocable(idx) {
  if (!(idx >= 0 && idx < STATUS_LIST_CAPACITY)) {
    throw Object.assign(new Error('status list is full; credentials cannot be issued until an administrator adds a new list'), { status: 503 });
  }
}

// Self-revocation: mark current status_index as revoked in /status/1 and rotate to a fresh index.
// Each call uses up one position in the list, so it is rate-limited per person and overall.
async function revokeOwnCredential(request, env) {
  const user = await currentUser(request, env);
  if (!user) return jsonApiError('log in first', 401);
  if (!(await hitLimit(env, `revoke:user:${user.id}`, SELF_REVOKE_PER_USER_PER_DAY, DAY_MS))) {
    return jsonApiError(`you can revoke at most ${SELF_REVOKE_PER_USER_PER_DAY} times a day`, 429);
  }
  if (!(await hitLimit(env, 'revoke:all', SELF_REVOKE_PER_DAY, DAY_MS))) {
    return jsonApiError('too many revocations today; try again tomorrow', 429);
  }
  const oldIdx = await ensureStatusIndex(env, user);
  const top = await db(env).prepare(`SELECT ${NEXT_STATUS_INDEX_SQL} AS n`).first();
  if (Number(top?.n) >= STATUS_LIST_CAPACITY - STATUS_LIST_RESERVE) {
    return jsonApiError('the revocation list is almost full; ask an administrator', 503);
  }
  // One transaction: record the old position as revoked, then move the person to the next free one.
  await db(env).batch([
    db(env).prepare('INSERT OR IGNORE INTO revoked_indices (idx, user_id, revoked_at) VALUES (?, ?, ?)').bind(oldIdx, user.id, Date.now()),
    db(env).prepare(`UPDATE users SET status_index = ${NEXT_STATUS_INDEX_SQL} WHERE id = ?`).bind(user.id),
  ]);
  const newIdx = Number((await db(env).prepare('SELECT status_index FROM users WHERE id = ?').bind(user.id).first()).status_index);
  return jsonApi({
    type: 'revocation',
    id: String(oldIdx),
    attributes: { ok: true, revokedIndex: oldIdx, newStatusIndex: newIdx },
  });
}

const sdHasher = async (data) => {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
};

const sdSaltGenerator = (length) => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return uint8ArrayToBase64Url(bytes);
};

async function issueCredential(request, url, env) {
  const user = await currentUser(request, env);
  if (!user) return jsonApiError('log in first', 401);
  if (user.status !== 'approved' && user.status !== 'verified') {
    return jsonApiError('not approved yet', 403);
  }
  const isLdasMember = user.status === 'approved';
  const reqBody = await request.json().catch(() => ({}));
  const format = reqBody?.format === 'sd-jwt' || reqBody?.format === 'dc+sd-jwt' ? 'dc+sd-jwt' : 'vc+jwt';
  const nonce = typeof reqBody?.nonce === 'string' && reqBody.nonce.length <= 256 ? reqBody.nonce : undefined;
  const aud = typeof reqBody?.aud === 'string' && reqBody.aud.length <= 256 ? reqBody.aud : undefined;
  // RFC 9901 Key Binding: when the holder browser provides its public key JWK (cnfJwk),
  // bind it via `cnf.jwk` so the holder signs `nonce`, `aud`, and `sd_hash` in a `kb+jwt`.
  const rawCnf = reqBody?.cnfJwk;
  const cnfJwk =
    rawCnf && typeof rawCnf === 'object' && typeof rawCnf.kty === 'string' && !rawCnf.d
      ? {
          kty: rawCnf.kty,
          ...(rawCnf.crv ? { crv: rawCnf.crv } : {}),
          ...(rawCnf.x ? { x: rawCnf.x } : {}),
          ...(rawCnf.y ? { y: rawCnf.y } : {}),
        }
      : undefined;
  const ALL_SD_KEYS = ['name', 'orcid', 'memberOf', 'wallet', 'affiliation', 'emailDomain'];
  const requestedDisclose = Array.isArray(reqBody?.disclose)
    ? reqBody.disclose.filter((k) => ALL_SD_KEYS.includes(k))
    : ALL_SD_KEYS;

  const did = didFor(url);
  const statusIndex = await ensureStatusIndex(env, user);
  assertRevocable(statusIndex);
  const { privateKey } = await issuerKey(url, env);
  const ttlDays = Math.max(1, Number(env.VC_TTL_DAYS || VC_TTL_DAYS));
  const now = new Date();
  const until = new Date(now.getTime() + ttlDays * 86400 * 1000);
  const credential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'LdasMemberCredential'],
    ...(format === 'dc+sd-jwt' ? { vct: `${url.origin}/credentials/member/v1` } : {}),
    issuer: did,
    iss: did,
    iat: Math.floor(now.getTime() / 1000),
    exp: Math.floor(until.getTime() / 1000),
    validFrom: now.toISOString(),
    validUntil: until.toISOString(),
    ...(cnfJwk ? { cnf: { jwk: cnfJwk } } : {}),
    // If cnf.jwk is bound, nonce/aud belong in the holder-signed kb+jwt (RFC 9901).
    // Only embed nonce/aud in the issuer JWT as a simplified fallback when no holder key is bound.
    ...(!cnfJwk && nonce ? { nonce } : {}),
    ...(!cnfJwk && aud ? { aud } : {}),
    credentialSubject: {
      id: user.wallet
        ? `did:pkh:eip155:${env.WALLET_CHAIN_ID}:${user.wallet}`
        : user.orcid
          ? `${ORCID}/${user.orcid}`
          : `urn:ldas:user:${user.id}`,
      ...(user.orcid ? { orcid: `${ORCID}/${user.orcid}` } : {}),
      name: user.name,
      ...(isLdasMember ? { memberOf: 'LDAS' } : {}),
      ...(user.wallet ? { wallet: user.wallet } : {}),
      ...(user.affiliation ? { affiliation: user.affiliation } : {}),
      ...(user.email_domain ? { emailDomain: user.email_domain } : {}),
    },
    credentialStatus: {
      id: `${url.origin}/status/1#${statusIndex}`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: String(statusIndex),
      statusListCredential: `${url.origin}/status/1`,
    },
    evidence: [{
      type: ['Evidence'],
      method: user.approved_by ? 'ORCID sign-in, approved by an administrator' : 'ORCID sign-in only (anyone with an ORCID iD)',
      ...(user.approved_by && { approvedBy: `${ORCID}/${user.approved_by}` }),
      ...(user.wallet && { wallet: 'holder signed a one-time message with this wallet (EIP-191)' }),
      ...(user.email_domain && {
        affiliationVerification: user.affiliation_method === 'grdm-oauth'
          ? 'GakuNin RDM (OAuth2) institutional profile'
          : 'Institutional email domain verified by one-time code (raw email not stored)',
        affiliationVerifiedAt: user.affiliation_verified_at
          ? new Date(user.affiliation_verified_at).toISOString()
          : undefined,
      }),
      checkedAt: new Date(user.approved_at || user.created_at).toISOString(),
    }],
  };

  if (format === 'dc+sd-jwt') {
    const sdjwt = new SdJwtInstance({
      signer: async (data) => {
        const sig = await crypto.subtle.sign('Ed25519', privateKey, new TextEncoder().encode(data));
        return uint8ArrayToBase64Url(new Uint8Array(sig));
      },
      signAlg: 'EdDSA',
      hasher: sdHasher,
      hashAlg: 'sha-256',
      saltGenerator: sdSaltGenerator,
    });
    const sdKeys = [
      'name',
      ...(user.orcid ? ['orcid'] : []),
      ...(isLdasMember ? ['memberOf'] : []),
      ...(user.wallet ? ['wallet'] : []),
      ...(user.affiliation ? ['affiliation'] : []),
      ...(user.email_domain ? ['emailDomain'] : []),
    ];
    const issued = await sdjwt.issue(
      credential,
      { credentialSubject: { _sd: sdKeys } },
      { header: { typ: 'dc+sd-jwt', kid: `${did}#key-1` } },
    );
    const presentFrame = { credentialSubject: {} };
    for (const k of sdKeys) {
      if (requestedDisclose.includes(k)) presentFrame.credentialSubject[k] = true;
    }
    const presentation = await sdjwt.present(issued, presentFrame);
    return jsonApi({
      type: 'credential',
      id: String(statusIndex),
      attributes: { jwt: presentation, format: 'dc+sd-jwt', disclosed: requestedDisclose, credential },
    });
  }

  const jwt = await new SignJWT(credential)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+jwt', kid: `${did}#key-1` })
    .setIssuedAt(Math.floor(now.getTime() / 1000))
    .setExpirationTime(Math.floor(until.getTime() / 1000))
    .sign(privateKey);
  return jsonApi({
    type: 'credential',
    id: String(statusIndex),
    attributes: { jwt, format: 'vc+jwt', credential },
  });
}

// ---------------------------------------------------------------------------
// Wallet link: the person signs a one-time message in MetaMask; we recover the signer's address.
// No blockchain call and no gas: a signature is pure math.
// ---------------------------------------------------------------------------

function walletMessage(url, user, nonce) {
  return `${url.host} wants you to link this wallet to your LDAS ID.\n\nORCID: ${user.orcid}\nNonce: ${nonce}`;
}

async function walletChallenge(request, url, env) {
  const user = await currentUser(request, env);
  if (!user) return jsonApiError('log in first', 401);
  const nonce = crypto.randomUUID();
  const message = walletMessage(url, user, nonce);
  const id = crypto.randomUUID();
  await db(env).prepare('INSERT INTO challenges (id, challenge, user_id, name, expires_at) VALUES (?, ?, ?, NULL, ?)')
    .bind(id, message, user.id, Date.now() + CHALLENGE_TTL).run();
  return jsonApi(
    { type: 'wallet-challenge', id, attributes: { message } },
    { headers: { 'Set-Cookie': cookie('ch', id, CHALLENGE_TTL) } },
  );
}

async function walletVerify(request, env) {
  const user = await currentUser(request, env);
  if (!user) return jsonApiError('log in first', 401);
  const ch = await takeChallenge(request, env);
  if (ch.user_id !== user.id) throw new Error('challenge belongs to another session');
  const { address, signature } = await request.json();
  const signer = recoverAddress(ch.challenge, signature);
  if (signer !== checksum(address)) throw new Error('signature is not from that wallet');
  const taken = await db(env).prepare('SELECT id FROM users WHERE wallet = ? AND id != ?').bind(signer, user.id).first();
  if (taken) throw new Error('this wallet is already linked to another account');
  await db(env).prepare('UPDATE users SET wallet = ? WHERE id = ?').bind(signer, user.id).run();
  return jsonApi({ type: 'wallet', id: signer, attributes: { wallet: signer } });
}

// ---------------------------------------------------------------------------
// Institutional Affiliation Verification:
//   (1) Email domain verification via 6-digit one-time code (raw email NEVER stored)
//   (2) GakuNin RDM (NII) OAuth2 profile/institution link (access token NEVER stored)
// ---------------------------------------------------------------------------

const EMAIL_CODE_TTL = 10 * 60 * 1000;
const EMAIL_COOLDOWN_MS = 60 * 1000;
const EMAIL_MAX_ATTEMPTS = 5;
const GRDM_ACCOUNTS = 'https://accounts.rdm.nii.ac.jp';
const GRDM_API = 'https://api.rdm.nii.ac.jp/v2';

const KNOWN_INSTITUTIONS = [
  { root: 'u-tokyo.ac.jp', affiliation: 'The University of Tokyo' },
  { root: 'ubc.ca', affiliation: 'The University of British Columbia' },
  { root: 'kyoto-u.ac.jp', affiliation: 'Kyoto University' },
  { root: 'osaka-u.ac.jp', affiliation: 'Osaka University' },
  { root: 'tohoku.ac.jp', affiliation: 'Tohoku University' },
  { root: 'nii.ac.jp', affiliation: 'National Institute of Informatics' },
  { root: 'keio.jp', affiliation: 'Keio University' },
  { root: 'waseda.jp', affiliation: 'Waseda University' },
];

// Fixed-window counter, updated in one SQL statement (safe when requests arrive at the same time).
// Returns true while the count for this window is within the limit.
async function hitLimit(env, key, limit, windowMs) {
  const now = Date.now();
  const row = await db(env).prepare(
    `INSERT INTO rate_limits (key, count, reset_at) VALUES (?, 1, ?)
     ON CONFLICT(key) DO UPDATE SET
       count = CASE WHEN rate_limits.reset_at <= ? THEN 1 ELSE rate_limits.count + 1 END,
       reset_at = CASE WHEN rate_limits.reset_at <= ? THEN excluded.reset_at ELSE rate_limits.reset_at END
     RETURNING count`,
  ).bind(key, now + windowMs, now, now).first();
  return Number(row?.count ?? Infinity) <= limit;
}

function isLocalHost(url) {
  return url.hostname === 'localhost' || url.hostname === '127.0.0.1';
}

// Mail goes to addresses typed by strangers, so cap it per sender IP and overall
// (Resend's free plan sends 100 a day; going over would stop sign-in for everyone).
const MAIL_PER_IP_PER_HOUR = 5;
const MAIL_PER_DAY = 80;

async function allowMail(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (!(await hitLimit(env, `mail:ip:${await sha256Hex(ip)}`, MAIL_PER_IP_PER_HOUR, 3600 * 1000))) {
    return jsonApiError('確認コードの送信が多すぎます。1 時間ほどしてからお試しください', 429);
  }
  if (!(await hitLimit(env, 'mail:all', MAIL_PER_DAY, DAY_MS))) {
    return jsonApiError('本日の確認メールの送信上限に達しました。明日お試しいただくか、ORCID でログインしてください', 429);
  }
  await db(env).prepare('DELETE FROM rate_limits WHERE reset_at < ?').bind(Date.now() - DAY_MS).run();
  return null;
}

// Use up one attempt before comparing the code. Done in one statement, so sending many guesses
// at the same moment cannot get past the limit. Returns the row (with the new count) or null.
async function takeAttempt(env, table, id, extraWhere = '', extraParams = []) {
  return db(env).prepare(
    `UPDATE ${table} SET attempts = attempts + 1
     WHERE id = ? AND attempts < ? AND expires_at > ? ${extraWhere} RETURNING *`,
  ).bind(id, EMAIL_MAX_ATTEMPTS, Date.now(), ...extraParams).first();
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function resolveDomainAffiliation(rawDomain) {
  const d = rawDomain.trim().toLowerCase();
  for (const entry of KNOWN_INSTITUTIONS) {
    if (d === entry.root || d.endsWith(`.${entry.root}`)) {
      return { emailDomain: entry.root, affiliation: entry.affiliation };
    }
  }
  const labels = d.split('.');
  if (d.endsWith('.ac.jp') && labels.length >= 3) {
    const canonical = labels.slice(-3).join('.');
    return { emailDomain: canonical, affiliation: canonical };
  }
  return { emailDomain: d, affiliation: d };
}

function parseInstitutionalEmail(rawEmail) {
  if (typeof rawEmail !== 'string') throw new Error('メールアドレスを入力してください');
  const normalized = rawEmail.trim().toLowerCase();
  if (normalized.length > 254) throw new Error('メールアドレスが長すぎます');
  const m = /^[^\s@]+@([a-z0-9-]+(?:\.[a-z0-9-]+)+)$/.exec(normalized);
  if (!m) throw new Error('有効なメールアドレス形式で入力してください');
  const { emailDomain, affiliation } = resolveDomainAffiliation(m[1]);
  return { normalizedEmail: normalized, emailDomain, affiliation };
}

async function emailChallenge(request, url, env) {
  const user = await currentUser(request, env);
  if (!user) return jsonApiError('log in first', 401);

  const body = await request.json().catch(() => ({}));
  const { normalizedEmail, emailDomain, affiliation } = parseInstitutionalEmail(body?.email);

  const now = Date.now();
  const recent = await db(env)
    .prepare('SELECT created_at FROM email_verifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 1')
    .bind(user.id)
    .first();
  if (recent && now - Number(recent.created_at) < EMAIL_COOLDOWN_MS) {
    return jsonApiError('確認コードの再送信は 60 秒お待ちください', 429);
  }
  const limited = await allowMail(request, env);
  if (limited) return limited;

  const rand = new Uint32Array(1);
  crypto.getRandomValues(rand);
  const code = String(rand[0] % 1000000).padStart(6, '0');
  const id = crypto.randomUUID();
  const emailHash = await sha256Hex(normalizedEmail);
  const codeHash = await sha256Hex(`${id}:${code}`);

  await db(env).batch([
    db(env).prepare('DELETE FROM email_verifications WHERE user_id = ?').bind(user.id),
    db(env)
      .prepare('INSERT INTO email_verifications (id, user_id, email_hash, domain, affiliation, code_hash, attempts, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)')
      .bind(id, user.id, emailHash, emailDomain, affiliation, codeHash, now + EMAIL_CODE_TTL, now),
  ]);

  const isLocal = isLocalHost(url);
  if (env.RESEND_API_KEY) {
    const from = env.MAIL_FROM || 'LDAS ID <noreply@id.ldas.jp>';
    const sendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from,
        to: [normalizedEmail],
        subject: `[LDAS ID] 所属ドメイン確認コード: ${code}`,
        text: `LDAS ID の所属ドメイン確認コードは ${code} です（有効期限 10 分）。\n\n確認されるドメイン: ${emailDomain}\n所属表記: ${affiliation}\n\n※メールアドレス本体はサーバおよび証明書（VC）には保存されません。`,
      }),
    });
    if (!sendRes.ok) {
      const detail = await sendRes.text().catch(() => '');
      throw Object.assign(new Error(`確認メールの送信に失敗しました (${sendRes.status}): ${detail.slice(0, 120)}`), { status: 502 });
    }
    return jsonApi({
      type: 'email-challenge',
      id,
      attributes: { challengeId: id, emailDomain, affiliation, delivery: 'resend' },
    });
  }

  if (isLocal) {
    console.log(`[id-ldas local dev] Email verification code for ${emailDomain} (${affiliation}): ${code}`);
    return jsonApi({
      type: 'email-challenge',
      id,
      attributes: { challengeId: id, emailDomain, affiliation, delivery: 'local-dev', devCode: code },
    });
  }

  return jsonApiError('メール送信機能（RESEND_API_KEY）がまだ設定されていません', 503);
}

async function emailVerify(request, env) {
  const user = await currentUser(request, env);
  if (!user) return jsonApiError('log in first', 401);

  const body = await request.json().catch(() => ({}));
  const challengeId = typeof body?.challengeId === 'string' ? body.challengeId.trim() : '';
  const code = typeof body?.code === 'string' ? body.code.trim() : '';
  if (!challengeId || !/^\d{6}$/.test(code)) {
    return jsonApiError('6 桁の確認コードを入力してください', 400);
  }

  const row = await takeAttempt(env, 'email_verifications', challengeId, 'AND user_id = ?', [user.id]);
  if (!row) {
    await db(env).prepare('DELETE FROM email_verifications WHERE id = ? AND user_id = ?').bind(challengeId, user.id).run();
    return jsonApiError('確認コードの有効期限が切れたか、試行回数の上限に達しました。最初からやり直してください', 400);
  }

  const expectedHash = await sha256Hex(`${row.id}:${code}`);
  if (!constantTimeEqual(expectedHash, String(row.code_hash))) {
    const left = EMAIL_MAX_ATTEMPTS - Number(row.attempts);
    if (left <= 0) await db(env).prepare('DELETE FROM email_verifications WHERE id = ?').bind(row.id).run();
    return jsonApiError(left <= 0 ? '試行回数の上限に達しました。確認コードを再発行してください' : `確認コードが一致しません（残り ${left} 回）`, left <= 0 ? 429 : 400);
  }

  // The code is used once: only the request that actually deletes the row goes on.
  const used = await db(env).prepare('DELETE FROM email_verifications WHERE id = ? RETURNING id').bind(row.id).first();
  if (!used) return jsonApiError('この確認コードは既に使われました', 400);
  const now = Date.now();
  await db(env).batch([
    db(env)
      .prepare('UPDATE users SET email_domain = ?, affiliation = ?, affiliation_method = ?, affiliation_verified_at = ? WHERE id = ?')
      .bind(row.domain, row.affiliation, 'email-code', now, user.id),
  ]);

  return jsonApi({
    type: 'affiliation',
    id: user.id,
    attributes: { emailDomain: row.domain, affiliation: row.affiliation, method: 'email-code' },
  });
}

async function hmacEmailHash(normalizedEmail, env) {
  const pepper = env.ISSUER_JWK || 'ldas-id-local-dev-pepper-not-for-prod';
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(pepper),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(normalizedEmail));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function emailLoginStart(request, url, env) {
  const body = await request.json().catch(() => ({}));
  const { normalizedEmail, emailDomain, affiliation } = parseInstitutionalEmail(body?.email);
  const isFreeWebmail = FREE_WEBMAIL_DOMAINS.has(emailDomain) ? 1 : 0;
  const emailHash = await hmacEmailHash(normalizedEmail, env);
  const now = Date.now();

  const recent = await db(env)
    .prepare('SELECT created_at FROM email_login_challenges WHERE email_hash = ? ORDER BY created_at DESC LIMIT 1')
    .bind(emailHash)
    .first();
  if (recent && now - Number(recent.created_at) < EMAIL_COOLDOWN_MS) {
    return jsonApiError('確認コードの再送信は 60 秒お待ちください', 429);
  }
  const limited = await allowMail(request, env);
  if (limited) return limited;

  const rand = new Uint32Array(1);
  crypto.getRandomValues(rand);
  const code = String(rand[0] % 1000000).padStart(6, '0');
  const id = crypto.randomUUID();
  const codeHash = await sha256Hex(`${id}:${code}`);

  await db(env).batch([
    db(env).prepare('DELETE FROM email_login_challenges WHERE email_hash = ? OR expires_at < ?').bind(emailHash, now),
    db(env)
      .prepare('INSERT INTO email_login_challenges (id, email_hash, domain, affiliation, is_free_webmail, code_hash, attempts, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)')
      .bind(id, emailHash, emailDomain, affiliation, isFreeWebmail, codeHash, now + EMAIL_CODE_TTL, now),
  ]);

  const isLocal = isLocalHost(url);
  if (env.RESEND_API_KEY) {
    const from = env.MAIL_FROM || 'LDAS ID <noreply@ldas.jp>';
    const sendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from,
        to: [normalizedEmail],
        subject: `[LDAS ID] ログイン確認コード: ${code}`,
        text: `LDAS ID のログイン確認コードは ${code} です（有効期限 10 分・最大 5 回まで入力可能）。\n\n※メールアドレス本体はデータベースおよび証明書（VC）には一切保存されません（不可逆な HMAC ハッシュ値のみで本人を識別します）。`,
      }),
    });
    if (!sendRes.ok) {
      const detail = await sendRes.text().catch(() => '');
      throw Object.assign(new Error(`確認メールの送信に失敗しました (${sendRes.status}): ${detail.slice(0, 120)}`), { status: 502 });
    }
    return jsonApi({
      type: 'email-login-challenge',
      id,
      attributes: { challengeId: id, emailDomain: isFreeWebmail ? null : emailDomain, delivery: 'resend' },
    });
  }

  if (isLocal) {
    return jsonApi({
      type: 'email-login-challenge',
      id,
      attributes: { challengeId: id, emailDomain: isFreeWebmail ? null : emailDomain, delivery: 'local-dev', devCode: code },
    });
  }
  return jsonApiError('メール送信機能（RESEND_API_KEY）がまだ設定されていません', 503);
}

async function emailLoginVerify(request, env) {
  const body = await request.json().catch(() => ({}));
  const challengeId = typeof body?.challengeId === 'string' ? body.challengeId.trim() : '';
  const code = typeof body?.code === 'string' ? body.code.trim() : '';
  const displayName = typeof body?.name === 'string' ? body.name.trim().slice(0, 80) : '';
  if (!challengeId || !/^\d{6}$/.test(code)) {
    return jsonApiError('6 桁の確認コードを入力してください', 400);
  }

  const now = Date.now();
  const row = await takeAttempt(env, 'email_login_challenges', challengeId);
  if (!row) {
    const gone = await db(env).prepare('DELETE FROM email_login_challenges WHERE id = ? RETURNING id').bind(challengeId).first();
    return gone
      ? jsonApiError('確認コードの有効期限（10分）が切れたか、試行回数の上限に達しました。再送信してください', 429)
      : jsonApiError('確認コードが見つかりません。もう一度送信してください', 400);
  }

  const expectedHash = await sha256Hex(`${challengeId}:${code}`);
  if (!constantTimeEqual(expectedHash, String(row.code_hash))) {
    return jsonApiError('確認コードが一致しません', 400);
  }

  // The code is used once: only the request that actually deletes the row signs in.
  const used = await db(env).prepare('DELETE FROM email_login_challenges WHERE id = ? RETURNING id').bind(challengeId).first();
  if (!used) return jsonApiError('この確認コードは既に使われました', 400);

  const emailDomain = Number(row.is_free_webmail) ? null : String(row.domain);
  const affiliation = Number(row.is_free_webmail) ? null : String(row.affiliation);
  let user = await db(env).prepare('SELECT * FROM users WHERE email_login_hash = ?').bind(row.email_hash).first();

  if (!user) {
    const newId = crypto.randomUUID();
    const finalName = displayName || (affiliation ? `${affiliation} User` : 'LDAS User');
    await db(env)
      .prepare(
        "INSERT INTO users (id, name, created_at, status, email_login_hash, email_domain, affiliation, affiliation_method, affiliation_verified_at) VALUES (?, ?, ?, 'verified', ?, ?, ?, ?, ?)",
      )
      .bind(
        newId,
        finalName,
        now,
        row.email_hash,
        emailDomain,
        affiliation,
        emailDomain ? 'email-code' : null,
        emailDomain ? now : null,
      )
      .run();
    user = { id: newId, name: finalName, status: 'verified' };
  } else {
    const nextName = displayName || user.name;
    await db(env)
      .prepare(
        'UPDATE users SET name = ?, email_domain = COALESCE(?, email_domain), affiliation = COALESCE(?, affiliation), affiliation_method = COALESCE(?, affiliation_method), affiliation_verified_at = COALESCE(?, affiliation_verified_at) WHERE id = ?',
      )
      .bind(
        nextName,
        emailDomain,
        affiliation,
        emailDomain ? 'email-code' : null,
        emailDomain ? now : null,
        user.id,
      )
      .run();
  }

  return jsonApi(
    { type: 'session', id: user.id, attributes: { ok: true, userId: user.id, status: user.status } },
    { headers: { 'Set-Cookie': await newSession(env, user.id) } },
  );
}

async function grdmStart(request, url, env) {
  const user = await currentUser(request, env);
  if (!env.GRDM_CLIENT_ID || !env.GRDM_CLIENT_SECRET) {
    return Response.redirect(`${url.origin}/${user ? '' : 'login'}?grdm=unconfigured`, 302);
  }
  const state = crypto.randomUUID();
  const nextPath = safeNextPath(url.searchParams.get('next'));
  const mode = user ? 'grdm-link' : 'grdm-login';
  await db(env)
    .prepare('INSERT INTO challenges (id, challenge, user_id, name, expires_at) VALUES (?, ?, ?, ?, ?)')
    .bind(state, mode, user ? user.id : null, nextPath, Date.now() + CHALLENGE_TTL)
    .run();
  const auth = new URL(`${GRDM_ACCOUNTS}/oauth2/authorize`);
  auth.search = new URLSearchParams({
    client_id: env.GRDM_CLIENT_ID,
    response_type: 'code',
    scope: 'osf.full_read',
    redirect_uri: `${url.origin}/auth/grdm/callback`,
    state,
  });
  return new Response(null, { status: 302, headers: { Location: auth.toString(), 'Set-Cookie': cookie('ch', state, CHALLENGE_TTL) } });
}

const FREE_WEBMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.co.jp', 'yahoo.com',
  'icloud.com', 'me.com', 'outlook.com', 'hotmail.com', 'live.com', 'proton.me', 'protonmail.com',
]);

function normalizeGrdmInstitution(inst) {
  if (!inst || !inst.attributes) return null;
  const rawName = String(inst.attributes.name || '').trim();
  const id = String(inst.id || '').toLowerCase();
  const domainList = Array.isArray(inst.attributes.email_domains) ? inst.attributes.email_domains : [];
  let domain = typeof domainList[0] === 'string' && domainList[0].trim() ? domainList[0].trim().toLowerCase() : null;

  if (!domain && typeof inst.attributes.auth_url === 'string') {
    const m = /([a-z0-9-]+\.ac\.jp|[a-z0-9-]+\.edu|[a-z0-9-]+\.ubc\.ca)/i.exec(inst.attributes.auth_url);
    if (m) domain = m[1].toLowerCase();
  }
  if (/東京大学|university of tokyo|utokyo/i.test(rawName) || id.includes('utokyo') || id.includes('u-tokyo')) {
    return { affiliation: 'The University of Tokyo', emailDomain: domain || 'u-tokyo.ac.jp' };
  }
  if (/京都大学|kyoto university/i.test(rawName) || id.includes('kyoto')) {
    return { affiliation: 'Kyoto University', emailDomain: domain || 'kyoto-u.ac.jp' };
  }
  if (/国立情報学研究所|national institute of informatics/i.test(rawName) || id === 'nii') {
    return { affiliation: 'National Institute of Informatics', emailDomain: domain || 'nii.ac.jp' };
  }
  if (domain) {
    const resolved = resolveDomainAffiliation(domain);
    return { affiliation: rawName || resolved.affiliation, emailDomain: resolved.emailDomain };
  }
  return rawName ? { affiliation: rawName, emailDomain: null } : null;
}

async function grdmCallback(request, url, env) {
  const state = url.searchParams.get('state');
  if (!state || state !== cookies(request).ch) throw new Error('state mismatch; start again');
  const ch = await takeChallenge(request, env);
  const isLoginMode = ch.challenge === 'grdm-login' || !ch.user_id;
  if (url.searchParams.get('error')) {
    return Response.redirect(`${url.origin}/${isLoginMode ? 'login' : ''}?grdm=cancelled`, 302);
  }

  const tokenRes = await fetch(`${GRDM_ACCOUNTS}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      client_id: env.GRDM_CLIENT_ID,
      client_secret: env.GRDM_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code: url.searchParams.get('code') || '',
      redirect_uri: `${url.origin}/auth/grdm/callback`,
    }),
  });
  const tokens = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tokens.access_token) {
    throw new Error(`GakuNin RDM token exchange failed: ${tokens.error_description || tokenRes.status}`);
  }

  // Fetch user profile & affiliated institutions using the short-lived access token, then discard the token (never persisted).
  const authHeaders = { Authorization: `Bearer ${tokens.access_token}`, Accept: 'application/json' };
  const meRes = await fetch(`${GRDM_API}/users/me/?embed=institutions`, { headers: authHeaders });
  const meJson = await meRes.json().catch(() => ({}));
  if (!meRes.ok) throw new Error(`GakuNin RDM profile fetch failed (${meRes.status})`);

  let instList = meJson?.data?.embeds?.institutions?.data;
  if (!Array.isArray(instList) || instList.length === 0) {
    const instRes = await fetch(`${GRDM_API}/users/me/institutions/`, { headers: authHeaders }).catch(() => null);
    const instJson = instRes && instRes.ok ? await instRes.json().catch(() => ({})) : {};
    instList = Array.isArray(instJson?.data) ? instJson.data : [];
  }

  const instInfo = normalizeGrdmInstitution(instList[0]);
  let affiliation = instInfo?.affiliation || null;
  let emailDomain = instInfo?.emailDomain || null;

  const grdmEmail = meJson?.data?.attributes?.email;
  if (typeof grdmEmail === 'string' && grdmEmail.includes('@')) {
    const parsed = parseInstitutionalEmail(grdmEmail);
    const isFreeWebmail = FREE_WEBMAIL_DOMAINS.has(parsed.emailDomain);
    if (!emailDomain && !isFreeWebmail) emailDomain = parsed.emailDomain;
    if (!affiliation && !isFreeWebmail) affiliation = parsed.affiliation;
  }

  if (isLoginMode) {
    const grdmId = String(meJson?.data?.id || '').trim();
    if (!grdmId) throw new Error('GakuNin RDM user ID missing');
    const grdmName = String(meJson?.data?.attributes?.full_name || '').trim() || `GakuNin RDM (${grdmId})`;
    const now = Date.now();
    let user = await db(env).prepare('SELECT id FROM users WHERE grdm_id = ?').bind(grdmId).first();
    if (!user) {
      const newId = crypto.randomUUID();
      await db(env)
        .prepare(
          "INSERT INTO users (id, name, created_at, status, grdm_id, email_domain, affiliation, affiliation_method, affiliation_verified_at) VALUES (?, ?, ?, 'verified', ?, ?, ?, ?, ?)",
        )
        .bind(newId, grdmName, now, grdmId, emailDomain, affiliation, affiliation || emailDomain ? 'grdm-oauth' : null, affiliation || emailDomain ? now : null)
        .run();
      user = { id: newId };
    } else {
      await db(env)
        .prepare(
          'UPDATE users SET name = ?, email_domain = COALESCE(?, email_domain), affiliation = COALESCE(?, affiliation), affiliation_method = COALESCE(?, affiliation_method), affiliation_verified_at = COALESCE(?, affiliation_verified_at) WHERE id = ?',
        )
        .bind(grdmName, emailDomain, affiliation, affiliation || emailDomain ? 'grdm-oauth' : null, affiliation || emailDomain ? now : null, user.id)
        .run();
    }
    return new Response(null, {
      status: 302,
      headers: { Location: safeNextPath(ch.name), 'Set-Cookie': await newSession(env, user.id) },
    });
  }

  if (!affiliation && !emailDomain) {
    return Response.redirect(`${url.origin}/?grdm=no_affiliation`, 302);
  }

  await db(env)
    .prepare('UPDATE users SET email_domain = ?, affiliation = ?, affiliation_method = ?, affiliation_verified_at = ? WHERE id = ?')
    .bind(emailDomain, affiliation, 'grdm-oauth', Date.now(), ch.user_id)
    .run();

  return Response.redirect(`${url.origin}/?grdm=linked`, 302);
}

// ---------------------------------------------------------------------------
// Admin: approve or reject people (only ORCID iDs listed in ADMIN_ORCIDS)
// ---------------------------------------------------------------------------

async function requireAdmin(request, env) {
  const user = await currentUser(request, env);
  if (!user || !isAdminOrcid(env, user.orcid)) throw Object.assign(new Error('admin only'), { status: 403 });
  return user;
}

async function adminUsers(request, env) {
  await requireAdmin(request, env);
  const users = await db(env).prepare(
    "SELECT id, name, orcid, wallet, status, affiliation, email_domain, approved_by, approved_at, created_at FROM users WHERE orcid IS NOT NULL ORDER BY status = 'pending' DESC, created_at DESC"
  ).all();
  return jsonApi(
    users.map((u) => ({
      type: 'user',
      id: u.id,
      attributes: {
        name: u.name,
        orcid: u.orcid,
        wallet: u.wallet,
        status: u.status,
        affiliation: u.affiliation,
        email_domain: u.email_domain,
        approved_by: u.approved_by,
        approved_at: u.approved_at,
        created_at: u.created_at,
      },
    })),
    { meta: { count: users.length } },
  );
}

async function adminDecide(request, env) {
  const admin = await requireAdmin(request, env);
  const { id, status } = await request.json();
  if (!['approved', 'rejected', 'pending'].includes(status)) throw new Error('bad status');
  await db(env).prepare('UPDATE users SET status = ?, approved_by = ?, approved_at = ? WHERE id = ?')
    .bind(status, admin.orcid, Date.now(), id).run();
  return jsonApi({ type: 'user', id, attributes: { status } });
}

// ---------------------------------------------------------------------------
// Response helpers:
//   - Standard endpoints (/.well-known/did.json) use json()
//   - App-specific /api/* endpoints use JSON:API v1.1 (jsonApi / jsonApiError)
//     so custom fields are clearly separated inside `data.attributes`.
// ---------------------------------------------------------------------------

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function jsonApi(data, { status = 200, headers = {}, meta } = {}) {
  const body = {
    jsonapi: { version: '1.1' },
    data,
    ...(meta ? { meta } : {}),
  };
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'Content-Type': 'application/vnd.api+json', ...headers },
  });
}

function jsonApiError(title, status = 400, headers = {}) {
  return new Response(
    JSON.stringify({ jsonapi: { version: '1.1' }, errors: [{ status: String(status), title }] }, null, 2),
    {
      status,
      headers: { 'Content-Type': 'application/vnd.api+json', ...headers },
    },
  );
}

function cookie(name, value, ttlMs) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.floor(ttlMs / 1000)}`;
}

function cookies(request) {
  const out = {};
  for (const part of (request.headers.get('Cookie') || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) out[k] = v.join('=');
  }
  return out;
}
