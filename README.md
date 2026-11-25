# id-ldas — id.ldas.jp

A small ID server for learning DID / Verifiable Credentials on Cloudflare Workers: one Worker and one SQLite-backed Durable Object, on the free plan, with no other servers.

Live: https://id.ldas.jp

- **Sign in with ORCID** (OpenID Connect). Having an ORCID iD is enough; an admin can stop someone afterwards.
- **Verify institutional affiliation** via a 6-digit email code (Resend; raw email is never stored in DB or VC) or **GakuNin RDM** (OAuth2 `osf.full_read`; access token is discarded immediately). Only the normalized `emailDomain` and `affiliation` are stored and selectively disclosable.
- **Link a wallet** by signing a one-time message in MetaMask (EIP-191). No transaction, no gas.
- **Issue a credential** (W3C VC Data Model 2.0 `vc+jwt` or IETF SD-JWT VC `dc+sd-jwt` with `vct`, EdDSA), signed by `did:web:id.ldas.jp`.
  With a linked wallet the subject is `did:pkh:eip155:11155111:<address>`, so only whoever holds that wallet can show it is theirs.
- **OID4VP 1.0 + RFC 9901 Key Binding (`kb+jwt`)** (`/authorize`): parses `dcql_query`, generates an ephemeral P-256 holder key pair in the browser (`cnf.jwk`), signs a Key Binding JWT (`typ: "kb+jwt"`) containing `nonce`, `aud`, and `sd_hash`, and returns a DCQL-compliant JSON object in `#vp_token={"<query_id>":["<sd-jwt+kb>"]}`. (If an API caller omits `cnfJwk`, the server falls back to embedding `nonce`/`aud` in the issuer JWT as a simplified mode.)
- **OID4VCI 1.0, pre-authorized code** (`src/oid4vci.js`): "Add to wallet" on `/` shows a one-time offer (QR code / `openid-credential-offer://` link) and a 6-digit `tx_code`. A wallet app (tested with walt.id wallet-api2 1.2.1) receives the `dc+sd-jwt` with all disclosures, bound (`cnf.jwk`) to the key in its proof JWT (ES256 or EdDSA), and chooses what to disclose when presenting. Codes, tokens and nonces are single-use, expire in 5 minutes and are stored only as SHA-256 hashes; 5 offers per person per day.
- **Signed W3C Bitstring Status List v1.0** (`/status/1`): served as an Ed25519-signed `application/vc+jwt` credential so verifiers authenticate the revocation list with `did:web:id.ldas.jp#key-1` before checking the bitstring. Users can also self-revoke issued VCs immediately from `/`.
- **Verify in the browser** (`/verify`): fetch the issuer's DID document, check the VC signature and signed `/status/1` revocation list, then ask the presenter to sign a fresh message with the wallet (holder check). The ID server's database is never asked.
- **JSON:API v1.1 + OpenAPI 3.1 / Swagger UI** (`/docs`, `/openapi.json`): app-specific `/api/*` endpoints use `application/vnd.api+json` so custom fields stay inside `data.attributes`, cleanly separated from standard W3C/IETF endpoints.
- Passkeys: a signed-in person can add one to come back without ORCID.

## Pages and endpoints

| Path | What |
|---|---|
| `/` | account management: affiliation verification, wallet link, passkey add, manual VC issue, self-revocation |
| `/login` | authentication screen (ORCID or passkey) |
| `/authorize` | OID4VP 1.0 / `return_to` consent screen with SD-JWT selective disclosure + `kb+jwt` |
| `/verify` | verify a VC, signed `/status/1`, and wallet holder in the browser |
| `/docs`, `/openapi.json` | OpenAPI 3.1 specification and Swagger UI |
| `/admin` | list people and stop/allow them (admins only, `ADMIN_ORCIDS`) |
| `/.well-known/did.json` | W3C DID document (Ed25519 public key) |
| `/status/1` | W3C Bitstring Status List v1.0 (Ed25519-signed `application/vc+jwt`) |
| `/.well-known/openid-credential-issuer`, `/.well-known/oauth-authorization-server` | OID4VCI 1.0 issuer metadata and RFC 8414 AS metadata |
| `/oid4vci/offer/<code>`, `/oid4vci/token`, `/oid4vci/nonce`, `/oid4vci/credential` | OID4VCI offer, token (pre-authorized code + `tx_code`), nonce and credential endpoints (OAuth error JSON) |
| `/auth/orcid`, `/auth/orcid/callback` | ORCID sign-in (OIDC) |
| `/auth/grdm`, `/auth/grdm/callback` | GakuNin RDM institutional affiliation link (OAuth2) |
| `/api/*` | App-specific JSON:API v1.1 (`application/vnd.api+json`, custom fields inside `data.attributes`) |

## What is stored where

| Where | What |
|---|---|
| Durable Object SQLite (server) | ORCID iD and name, verified `affiliation` & `email_domain` (never raw email), linked wallet address, status & revocation bit indices, passkey **public** keys, sessions. No passwords, no private keys, no OAuth tokens |
| Worker secrets | issuer private key (`ISSUER_JWK`), email-hash pepper (`EMAIL_HASH_PEPPER`), ORCID (`ORCID_CLIENT_SECRET`), Resend (`RESEND_API_KEY`), GakuNin RDM (`GRDM_CLIENT_ID`, `GRDM_CLIENT_SECRET`) |
| User's device | passkey private key, wallet private key, ephemeral P-256 `kb+jwt` key (never leave the device) |
| User | the VC / SD-JWT string |

A leak of the database exposes no keys and no raw email addresses. It does expose the link "this ORCID person = this wallet address", which makes that wallet's public on-chain history attributable to a name. The page asks people to link a wallet made just for this.

## Local

```
npm ci --ignore-scripts
npm run dev
```

Open http://localhost:8787. Without `ISSUER_JWK`, a throwaway signing key is made per dev process. Without `RESEND_API_KEY` on `localhost`, 6-digit email verification codes are shown in the UI/console for local testing. ORCID sign-in does not work locally (ORCID only accepts the registered HTTPS redirect URI).

To try a wallet app running in Docker (e.g. walt.id), the wallet must reach the same origin the Worker puts in the offer. Run the dev server with that origin as the local upstream and a throwaway issuer key (the dev key is only made for `localhost`):

```
ISSUER_JWK="$(node -e "const {generateKeyPairSync}=require('crypto');console.log(JSON.stringify(generateKeyPairSync('ed25519').privateKey.export({format:'jwk'})))")" CLOUDFLARE_INCLUDE_PROCESS_ENV=true npx wrangler dev --port 8830 --local-upstream host.docker.internal:8830
```

The issuer is then `http://host.docker.internal:8830` (`did:web:host.docker.internal%3A8830`). Verifiers resolve `did:web` over HTTPS only, so the issuer signature check fails locally; that is expected.

## Deploy

```
npm run deploy
zsh scripts/setup/issuer-key.zsh
op read "op://Personal/id-ldas orcid/client_secret" | tr -d '\n' | npx wrangler secret put ORCID_CLIENT_SECRET
op read "op://Personal/id-ldas resend/api_key" | tr -d '\n' | npx wrangler secret put RESEND_API_KEY
op read "op://Personal/id-ldas grdm/client_id" | tr -d '\n' | npx wrangler secret put GRDM_CLIENT_ID
op read "op://Personal/id-ldas grdm/client_secret" | tr -d '\n' | npx wrangler secret put GRDM_CLIENT_SECRET
```

Secrets live in 1Password and are passed straight to Cloudflare; nothing is written to disk. Tables are created and migrated by the Durable Object itself (`src/store.js`).

## Not yet

- Clio-X: let the Ocean Node accept compute jobs from wallets that hold this credential (Ocean Node policy server)
- Usage limits per person
- Periodic re-verification policy for institutional affiliations (e.g. every 6–12 months)

## License

MIT
