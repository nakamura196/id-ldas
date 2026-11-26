#!/usr/bin/env node
// End-to-end check of OID4VCI batch issuance against a local `wrangler dev` (default http://localhost:8787).
// Acts as the person (email sign-in, local dev code) and as a wallet (proofs with fresh P-256 keys).
//
//   npx wrangler dev --port 8787 &   # without RESEND_API_KEY the email code comes back in the response
//   node scripts/test/oid4vci-batch.mjs [origin]
//
// Checks: N copies for N proofs; distinct random status positions in the wallet half of the list;
// `sub` and `ldas_verification` are not always visible; iat on a UTC day boundary; duplicate keys and
// mixed nonces refused; self-revocation sets the copies' bits; the page path still shows `sub`.
import { SignJWT, generateKeyPair, exportJWK, decodeJwt } from 'jose';

const O = process.argv[2] || 'http://localhost:8787';
const N = 3;
let cookie = '';
let failed = 0;
const ok = (cond, label) => { console.log(`${cond ? 'ok  ' : 'FAIL'} ${label}`); if (!cond) failed++; };

async function api(path, body) {
  const r = await fetch(O + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: O, ...(cookie ? { Cookie: cookie } : {}) },
    body: JSON.stringify(body || {}),
  });
  const set = r.headers.getSetCookie?.() || [];
  if (set.length) cookie = set.map((c) => c.split(';')[0]).join('; ');
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${path} ${r.status} ${JSON.stringify(j)}`);
  return j.data?.attributes ?? j;
}

async function walletToken() {
  const offer = await api('/api/oid4vci/offers');
  const offerUrl = decodeURIComponent(offer.offerUri.split('credential_offer_uri=')[1]);
  const doc = await (await fetch(offerUrl)).json();
  const code = doc.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
  const t = await (await fetch(`${O}/oid4vci/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code, tx_code: offer.txCode }),
  })).json();
  return t;
}

async function proof(nonce, key) {
  return new SignJWT({ nonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: key.pub })
    .setAudience(O).setIssuedAt().sign(key.privateKey);
}
async function newKey() {
  const k = await generateKeyPair('ES256');
  return { privateKey: k.privateKey, pub: await exportJWK(k.publicKey) };
}
async function credentialRequest(accessToken, jwts) {
  const r = await fetch(`${O}/oid4vci/credential`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ credential_configuration_id: 'LdasMember_dc+sd-jwt', proofs: { jwt: jwts } }),
  });
  return { status: r.status, body: await r.json() };
}
const disclosedKeys = (sdjwt) => sdjwt.split('~').slice(1).filter(Boolean)
  .map((d) => JSON.parse(Buffer.from(d, 'base64url').toString())[1]);

// 1. Sign in by email (local dev returns the code).
const start = await api('/api/auth/email/start', { email: `batch-test-${Date.now()}@u-tokyo.ac.jp` });
await api('/api/auth/email/verify', { challengeId: start.challengeId, code: start.devCode, name: 'Batch Test' });
ok(!!cookie, 'signed in by email');

// 2. Metadata advertises batch issuance.
const meta = await (await fetch(`${O}/.well-known/openid-credential-issuer`)).json();
ok(meta.batch_credential_issuance?.batch_size >= N, `metadata batch_size = ${meta.batch_credential_issuance?.batch_size}`);

// 3. A batch of N copies.
const t1 = await walletToken();
const keys = await Promise.all(Array.from({ length: N }, newKey));
const res = await credentialRequest(t1.access_token, await Promise.all(keys.map((k) => proof(t1.c_nonce, k))));
ok(res.status === 200 && res.body.credentials?.length === N, `got ${res.body.credentials?.length} copies (status ${res.status})`);
const payloads = res.body.credentials.map((c) => decodeJwt(c.credential.split('~')[0]));
const idx = payloads.map((p) => p.status.status_list.idx);
ok(new Set(idx).size === N, `status positions distinct: ${idx.join(', ')}`);
ok(idx.every((i) => i >= 65536 && i < 131072), 'status positions in the wallet half');
ok(payloads.every((p) => p.sub === undefined), '`sub` not always visible');
ok(payloads.every((p) => p.ldas_verification === undefined), '`ldas_verification` not always visible');
ok(payloads.every((p) => p.iat % 86400 === 0), 'iat on a UTC day boundary');
ok(new Set(payloads.map((p) => p.cnf.jwk.x)).size === N, 'each copy bound to its own key');
const disc = disclosedKeys(res.body.credentials[0].credential);
ok(disc.includes('sub') && disc.includes('ldas_verification'), `holder can still disclose sub (disclosures: ${disc.join(', ')})`);

// 4. Refusals.
const t2 = await walletToken();
const same = await newKey();
const dup = await credentialRequest(t2.access_token, [await proof(t2.c_nonce, same), await proof(t2.c_nonce, same)]);
ok(dup.status === 400, `same key twice refused (${dup.status} ${dup.body.error_description})`);
const t3 = await walletToken();
const mixed = await credentialRequest(t3.access_token, [await proof(t3.c_nonce, await newKey()), await proof('other-nonce', await newKey())]);
ok(mixed.status === 400, `mixed nonces refused (${mixed.status} ${mixed.body.error_description})`);

// 5. Page path unchanged: `sub` stays visible for ds.ldas.jp / pay.ldas.jp.
const page = await api('/api/credential', { format: 'dc+sd-jwt' });
const pagePayload = decodeJwt(page.jwt.split('~')[0]);
ok(typeof pagePayload.sub === 'string' && pagePayload.sub.startsWith('urn:ldas:user:'), `page path keeps sub (${pagePayload.sub})`);

// 6. Self-revocation marks every copy.
await api('/api/credential/revoke');
const sl = decodeJwt(await (await fetch(`${O}/status/token/1`)).text());
const bytes = new Uint8Array(await new Response(
  new Blob([Buffer.from(sl.status_list.lst, 'base64url')]).stream().pipeThrough(new DecompressionStream('deflate')),
).arrayBuffer());
ok(idx.every((i) => (bytes[i >> 3] >> (i & 7)) & 1), 'self-revocation sets the bits of all copies');

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
process.exit(failed ? 1 : 0);
