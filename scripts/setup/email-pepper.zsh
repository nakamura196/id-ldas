#!/usr/bin/env zsh
# Make the pepper that keys the email hashes on id.ldas.jp and hand it to Cloudflare, without writing it to disk.
#
# Needs: op (1Password CLI, signed in), openssl, wrangler login. Run once, from the repo root:
#   zsh scripts/setup/email-pepper.zsh
#
# 1. Generates 32 random bytes (hex) in memory
# 2. Saves them to 1Password: Personal / "id-ldas email pepper" / field "pepper"  (the only copy)
# 3. Sets them as the Worker secret EMAIL_HASH_PEPPER
# Accounts hashed under the old pepper (ISSUER_JWK) are re-keyed on their next email sign-in, so keep
# ISSUER_JWK unchanged until then. Replacing this pepper later locks every email user out.
set -euo pipefail

ITEM="id-ldas email pepper"
if op item get "$ITEM" --vault Personal >/dev/null 2>&1; then
  echo "1Password item '$ITEM' already exists. Pushing that value to Cloudflare instead of making a new one."
else
  PEPPER=$(openssl rand -hex 32)
  op item create --category="API Credential" --vault=Personal --title="$ITEM" "pepper[concealed]=$PEPPER" "notesPlain=用途: id.ldas.jp のメールアドレスの HMAC の鍵 | 使用先: web3/id-ldas (Worker secret EMAIL_HASH_PEPPER) | 範囲: id.ldas.jp" >/dev/null
  unset PEPPER
  echo "Saved to 1Password: $ITEM"
fi

LEN=$(op read "op://Personal/$ITEM/pepper" | tr -d '\n' | wc -c | tr -d ' ')
[ "$LEN" -eq 64 ] || { echo "Unexpected pepper length $LEN (want 64)"; exit 1; }
op read "op://Personal/$ITEM/pepper" | tr -d '\n' | npx wrangler secret put EMAIL_HASH_PEPPER
echo "Done. EMAIL_HASH_PEPPER is set."
