#!/usr/bin/env zsh
# Make the issuer signing key for id.ldas.jp and hand it to Cloudflare, without writing it to disk.
#
# Needs: op (1Password CLI, signed in), node, wrangler login. Run once, from the repo root:
#   zsh scripts/setup/issuer-key.zsh
#
# 1. Generates an Ed25519 key pair (JWK) in memory
# 2. Saves it to 1Password: Personal / "id-ldas issuer key" / field "jwk"  (the only copy)
# 3. Sets it as the Worker secret ISSUER_JWK
# Re-running makes a NEW key: every VC issued before then stops verifying.
set -euo pipefail

ITEM="id-ldas issuer key"
if op item get "$ITEM" --vault Personal >/dev/null 2>&1; then
  echo "1Password item '$ITEM' already exists. Pushing that key to Cloudflare instead of making a new one."
else
  JWK=$(node -e "const {generateKeyPairSync}=require('crypto');const k=generateKeyPairSync('ed25519').privateKey.export({format:'jwk'});process.stdout.write(JSON.stringify({...k,kid:'key-1'}))")
  op item create --category="API Credential" --vault=Personal --title="$ITEM" "jwk[concealed]=$JWK" "notesPlain=用途: id.ldas.jp の VC 署名鍵 | 使用先: web3/id-ldas (Worker secret ISSUER_JWK) | 範囲: id.ldas.jp" >/dev/null
  unset JWK
  echo "Saved to 1Password: $ITEM"
fi

op read "op://Personal/$ITEM/jwk" | tr -d '\n' | npx wrangler secret put ISSUER_JWK
echo "Done. Check: https://id.ldas.jp/.well-known/did.json"
