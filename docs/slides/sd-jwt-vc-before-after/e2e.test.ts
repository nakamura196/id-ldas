// End-to-end: local id.ldas.jp (port 8811) issues a flat SD-JWT VC; dataspace vc.ts verifies it.
import { describe, it, expect } from 'vitest'
import { SignJWT, generateKeyPair, exportJWK, calculateJwkThumbprint } from '/Users/nakamura/git/oi/dataspace-mock/node_modules/jose/dist/webapi/index.js'
import { verifyVcJwt } from '/Users/nakamura/git/oi/dataspace-mock/src/dsp-core/vc'

const BASE = 'http://127.0.0.1:8811'
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const decode = (part: string) => JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/')))

async function login(): Promise<string> {
  const start = await fetch(`${BASE}/api/auth/email/start`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: `e2e-${Date.now()}@u-tokyo.ac.jp` }),
  }).then((r) => r.json())
  const { challengeId, devCode } = start.data.attributes
  const res = await fetch(`${BASE}/api/auth/email/verify`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challengeId, code: devCode, name: 'E2E Flat' }),
  })
  return (res.headers.get('set-cookie') ?? '').split(';')[0]
}

describe('local id.ldas.jp -> dataspace vc.ts', () => {
  it('issues a flat SD-JWT VC that vc.ts accepts, then rejects it after self-revocation', async () => {
    const cookie = await login()
    expect(cookie).toMatch(/^sid=/)
    const holder = await generateKeyPair('ES256', { extractable: true })
    const pub = await exportJWK(holder.publicKey)
    const kid = await calculateJwkThumbprint(pub)
    const issued = await fetch(`${BASE}/api/credential`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', cookie },
      body: JSON.stringify({ format: 'dc+sd-jwt', disclose: ['affiliation', 'emailDomain'], cnfJwk: { ...pub, kid } }),
    }).then((r) => r.json())
    const sd: string = issued.data.attributes.jwt
    const [hdr, body] = sd.split('~')[0].split('.')
    const payload = decode(body)
    console.log('header', decode(hdr))
    console.log('payload', JSON.stringify(payload, null, 1))
    expect(payload.credentialSubject).toBeUndefined()
    expect(payload['@context']).toBeUndefined()
    expect(payload.cnf.jwk.kid).toBe(kid)
    expect(payload.status.status_list.uri).toMatch(/\/status\/token\/1$/)

    const base = sd.endsWith('~') ? sd : `${sd}~`
    const sdHash = b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(base))))
    const kb = await new SignJWT({ nonce: 'e2e', aud: 'https://dataspace.ldas.jp', sd_hash: sdHash })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt', kid }).setIssuedAt().sign(holder.privateKey)
    const opts = {
      // the local server names itself localhost:8787 (dev.host); route those fetches to port 8811
      fetchDidDoc: async () => fetch(`${BASE}/.well-known/did.json`).then((r) => r.json()),
      fetchTokenStatusList: async (u: string) => fetch(u.replace(/^https?:\/\/[^/]+/, BASE)).then((r) => r.text()),
      expectedNonce: 'e2e',
      expectedAudience: 'https://dataspace.ldas.jp',
    }
    const v = await verifyVcJwt(`${base}${kb}`, opts)
    console.log(v.steps.join('\n'))
    expect(v.keyBound).toBe(true)
    expect(v.emailDomain).toBe('u-tokyo.ac.jp')
    expect(v.disclosedClaims).toEqual(['affiliation', 'emailDomain'])

    const rv = await fetch(`${BASE}/api/credential/revoke`, { method: 'POST', headers: { cookie } })
    expect(rv.status).toBe(200)
    await expect(verifyVcJwt(`${base}${kb}`, opts)).rejects.toThrow(/失効済み/)
  })
})
