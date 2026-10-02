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
    const url = new URL(request.url);
    try {
      if (url.pathname === '/.well-known/did.json') return await didDocument(url, env);
      if (url.pathname === '/auth/orcid') return await orcidStart(url, env);
      if (url.pathname === '/auth/orcid/callback') return await orcidCallback(request, url, env);
      if (url.pathname.startsWith('/api/')) return await api(request, url, env);
      // The admin page itself is only served to admins (its data API checks again).
      if (url.pathname === '/admin' || url.pathname === '/admin.html') {
        const user = await currentUser(request, env);
        if (!user || !isAdminOrcid(env, user.orcid)) return Response.redirect(`${url.origin}/`, 302);
      }
    } catch (e) {
      console.error(e);
      return json({ error: e.message }, e.status || 400);
    }
    return env.ASSETS.fetch(request);
  },
};

async function api(request, url, env) {
  const route = `${request.method} ${url.pathname}`;
  switch (route) {
    case 'POST /api/register/options': return registerOptions(request, url, env);
    case 'POST /api/register/verify':  return registerVerify(request, url, env);
    case 'POST /api/login/options':    return loginOptions(url, env);
    case 'POST /api/login/verify':     return loginVerify(request, url, env);
    case 'GET /api/me':                return me(request, env);
    case 'POST /api/logout':           return logout(request, env);
    case 'POST /api/credential':       return issueCredential(request, url, env);
    case 'POST /api/wallet/challenge': return walletChallenge(request, url, env);
    case 'POST /api/wallet/verify':    return walletVerify(request, env);
    case 'GET /api/admin/users':       return adminUsers(request, env);
    case 'POST /api/admin/decide':     return adminDecide(request, env);
  }
  return json({ error: 'not found' }, 404);
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
  if (!user) return json({ error: 'sign in with ORCID first' }, 401);
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
  return json({ ok: true });
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
  return json(options, 200, { 'Set-Cookie': cookie('ch', id, CHALLENGE_TTL) });
}

// ---------------------------------------------------------------------------
// Sign in with ORCID (OpenID Connect). ORCID tells us "this person controls ORCID iD X".
// It does not tell us they are a researcher we trust; that is the admin's approval below.
// ---------------------------------------------------------------------------

async function orcidStart(url, env) {
  const state = crypto.randomUUID();
  const nonce = crypto.randomUUID();
  await db(env).prepare('INSERT INTO challenges (id, challenge, user_id, name, expires_at) VALUES (?, ?, NULL, NULL, ?)')
    .bind(state, nonce, Date.now() + CHALLENGE_TTL).run();
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
  return new Response(null, { status: 302, headers: { Location: '/', 'Set-Cookie': await newSession(env, user.id) } });
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
  return json({ ok: true }, 200, { 'Set-Cookie': await newSession(env, userId) });
}

async function currentUser(request, env) {
  const sid = cookies(request).sid;
  if (!sid) return null;
  return db(env).prepare(
    'SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.expires_at > ?'
  ).bind(sid, Date.now()).first();
}

async function me(request, env) {
  const user = await currentUser(request, env);
  if (user) user.isAdmin = isAdminOrcid(env, user.orcid);
  return json({ user });
}

async function logout(request, env) {
  const sid = cookies(request).sid;
  if (sid) await db(env).prepare('DELETE FROM sessions WHERE id = ?').bind(sid).run();
  return json({ ok: true }, 200, { 'Set-Cookie': cookie('sid', '', 0) });
}

// ---------------------------------------------------------------------------
// Verifiable Credential (W3C VC Data Model 2.0, secured as a JWT: "vc+jwt")
// ---------------------------------------------------------------------------

async function issueCredential(request, url, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'log in first' }, 401);
  if (user.status !== 'approved') return json({ error: 'not approved yet' }, 403);
  const did = didFor(url);
  const { privateKey } = await issuerKey(url, env);
  const now = new Date();
  const until = new Date(now.getTime() + VC_TTL_DAYS * 86400 * 1000);
  const credential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'LdasMemberCredential'],
    issuer: did,
    validFrom: now.toISOString(),
    validUntil: until.toISOString(),
    credentialSubject: {
      // With a wallet: the subject is the wallet (did:pkh = "DID of a blockchain account").
      // Without: the subject is the ORCID iD, and the VC is just a bearer string.
      id: user.wallet ? `did:pkh:eip155:${env.WALLET_CHAIN_ID}:${user.wallet}` : `${ORCID}/${user.orcid}`,
      orcid: `${ORCID}/${user.orcid}`,
      name: user.name,
      memberOf: 'LDAS',
    },
    // How the issuer convinced itself before signing. The value of a VC is in this step: say it honestly.
    evidence: [{
      type: ['Evidence'],
      method: user.approved_by ? 'ORCID sign-in, approved by an administrator' : 'ORCID sign-in only (anyone with an ORCID iD)',
      ...(user.approved_by && { approvedBy: `${ORCID}/${user.approved_by}` }),
      ...(user.wallet && { wallet: 'holder signed a one-time message with this wallet (EIP-191)' }),
      checkedAt: new Date(user.approved_at || user.created_at).toISOString(),
    }],
  };
  const jwt = await new SignJWT(credential)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'vc+jwt', kid: `${did}#key-1` })
    .setIssuedAt(Math.floor(now.getTime() / 1000))
    .setExpirationTime(Math.floor(until.getTime() / 1000))
    .sign(privateKey);
  return json({ jwt, credential });
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
  if (!user) return json({ error: 'log in first' }, 401);
  const nonce = crypto.randomUUID();
  const message = walletMessage(url, user, nonce);
  const id = crypto.randomUUID();
  await db(env).prepare('INSERT INTO challenges (id, challenge, user_id, name, expires_at) VALUES (?, ?, ?, NULL, ?)')
    .bind(id, message, user.id, Date.now() + CHALLENGE_TTL).run();
  return json({ message }, 200, { 'Set-Cookie': cookie('ch', id, CHALLENGE_TTL) });
}

async function walletVerify(request, env) {
  const user = await currentUser(request, env);
  if (!user) return json({ error: 'log in first' }, 401);
  const ch = await takeChallenge(request, env);
  if (ch.user_id !== user.id) throw new Error('challenge belongs to another session');
  const { address, signature } = await request.json();
  const signer = recoverAddress(ch.challenge, signature);
  if (signer !== checksum(address)) throw new Error('signature is not from that wallet');
  const taken = await db(env).prepare('SELECT id FROM users WHERE wallet = ? AND id != ?').bind(signer, user.id).first();
  if (taken) throw new Error('this wallet is already linked to another account');
  await db(env).prepare('UPDATE users SET wallet = ? WHERE id = ?').bind(signer, user.id).run();
  return json({ wallet: signer });
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
    "SELECT id, name, orcid, wallet, status, approved_by, approved_at, created_at FROM users WHERE orcid IS NOT NULL ORDER BY status = 'pending' DESC, created_at DESC"
  ).all();
  return json({ users });
}

async function adminDecide(request, env) {
  const admin = await requireAdmin(request, env);
  const { id, status } = await request.json();
  if (!['approved', 'rejected', 'pending'].includes(status)) throw new Error('bad status');
  await db(env).prepare('UPDATE users SET status = ?, approved_by = ?, approved_at = ? WHERE id = ?')
    .bind(status, admin.orcid, Date.now(), id).run();
  return json({ ok: true });
}

// ---------------------------------------------------------------------------

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
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
