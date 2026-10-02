# id-ldas — id.ldas.jp

A small ID server for learning DID / Verifiable Credentials on Cloudflare Workers: one Worker and one SQLite-backed Durable Object, on the free plan, with no other servers.

Live: https://id.ldas.jp

- **Sign in with ORCID** (OpenID Connect). Having an ORCID iD is enough; an admin can stop someone afterwards.
- **Link a wallet** by signing a one-time message in MetaMask (EIP-191). No transaction, no gas.
- **Issue a credential** (W3C VC Data Model 2.0, secured as a JWT: `vc+jwt`, EdDSA), signed by `did:web:id.ldas.jp`.
  With a linked wallet the subject is `did:pkh:eip155:11155111:<address>`, so only whoever holds that wallet can show it is theirs.
- **Verify in the browser** (`/verify`): fetch the issuer's DID document, check the signature, then ask the presenter to sign a fresh message with the wallet (holder check). The ID server's database is never asked.
- Passkeys: a signed-in person can add one to come back without ORCID.

## Pages and endpoints

| Path | What |
|---|---|
| `/` | sign in, link a wallet, add a passkey, issue a VC |
| `/verify` | verify a VC and its holder, in the browser |
| `/admin` | list people and stop/allow them (admins only, `ADMIN_ORCIDS`) |
| `/.well-known/did.json` | the server's DID document (public key) |
| `/auth/orcid`, `/auth/orcid/callback` | ORCID sign-in |
| `/api/*` | JSON API used by the pages |

## What is stored where

| Where | What |
|---|---|
| Durable Object SQLite (server) | ORCID iD and name, linked wallet address, status, passkey **public** keys, sessions. No passwords, no private keys |
| Worker secrets | issuer private key (`ISSUER_JWK`), ORCID client secret (`ORCID_CLIENT_SECRET`) |
| User's device | passkey private key, wallet private key (never leave the device) |
| User | the VC string (JWT) |

A leak of the database exposes no keys. It does expose the link "this ORCID person = this wallet address", which makes that wallet's public on-chain history attributable to a name. The page asks people to link a wallet made just for this.

## Local

```
npm ci --ignore-scripts
npm run dev
```

Open http://localhost:8787. Without `ISSUER_JWK`, a throwaway signing key is made per dev process. ORCID sign-in does not work locally (ORCID only accepts the registered HTTPS redirect URI).

## Deploy

```
npm run deploy
zsh scripts/setup/issuer-key.zsh
op read "op://Personal/id-ldas orcid/client_secret" | tr -d '\n' | npx wrangler secret put ORCID_CLIENT_SECRET
```

Secrets live in 1Password and are passed straight to Cloudflare; nothing is written to disk. Tables are created and migrated by the Durable Object itself (`src/store.js`).

## Not yet

- Clio-X: let the Ocean Node accept compute jobs from wallets that hold this credential (Ocean Node policy server)
- Usage limits per person
- Revocation (status list), selective disclosure (SD-JWT)

## License

MIT
