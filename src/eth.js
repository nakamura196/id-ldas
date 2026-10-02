// Ethereum wallet signatures (MetaMask "personal_sign", EIP-191), checked without any blockchain call.
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.replace(/^0x/, '').match(/../g), (x) => parseInt(x, 16));

// The digest MetaMask signs: keccak256("\x19Ethereum Signed Message:\n" + byteLength + message)
export function personalMessageHash(message) {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  return keccak_256(new Uint8Array([...prefix, ...body]));
}

// Ethereum address = last 20 bytes of keccak256(uncompressed public key without its 0x04 prefix), EIP-55 checksummed
export function addressOf(publicKey) {
  const raw = publicKey.length === 65 ? publicKey.slice(1) : secp256k1.Point.fromBytes(publicKey).toBytes(false).slice(1);
  return checksum(hex(keccak_256(raw).slice(-20)));
}

export function checksum(addr) {
  const a = addr.replace(/^0x/, '').toLowerCase();
  const h = hex(keccak_256(new TextEncoder().encode(a)));
  return '0x' + [...a].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join('');
}

// Signature from MetaMask: 0x + r(32) + s(32) + v(1, 27/28). Returns the address that signed `message`.
export function recoverAddress(message, signatureHex) {
  const sig = unhex(signatureHex);
  if (sig.length !== 65) throw new Error('bad signature length');
  const v = sig[64] >= 27 ? sig[64] - 27 : sig[64];
  const recovered = new Uint8Array([v, ...sig.slice(0, 64)]); // noble's "recovered" layout: recovery byte first
  const pub = secp256k1.recoverPublicKey(recovered, personalMessageHash(message), { prehash: false });
  return addressOf(pub);
}
