// Educational browser simulation; no messages or keys are sent to a server.
// RFC 3526 group 14: a fixed 2048-bit safe prime and generator 2.
const PRIME_HEX = 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff';
export const DH_PRIME = BigInt('0x' + PRIME_HEX);
export const DH_GENERATOR = 2n;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const subtle = () => globalThis.crypto.subtle;
export function modPow(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = result * base % modulus;
    base = base * base % modulus;
    exponent >>= 1n;
  }
  return result;
}
const integer = bytes => BigInt('0x' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''));
const sharedBytes = value => Uint8Array.from(value.toString(16).padStart(512, '0').match(/../g), h => parseInt(h, 16));
const randomSecret = () => integer(crypto.getRandomValues(new Uint8Array(32))) + 2n;
async function aesKey(secret, salt) {
  const material = await subtle().importKey('raw', sharedBytes(secret), 'HKDF', false, ['deriveKey']);
  return subtle().deriveKey({name:'HKDF', hash:'SHA-256', salt, info:encoder.encode('Alfie portfolio messaging demo v1')}, material, {name:'AES-GCM', length:256}, false, ['encrypt', 'decrypt']);
}
export async function createSession(mode) {
  if (mode === 'rsa') {
    const pair = await subtle().generateKey({name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'}, true, ['encrypt','decrypt']);
    const publicJwk = await subtle().exportKey('jwk', pair.publicKey);
    return {mode, pair, publicJwk};
  }
  if (mode !== 'dh') throw new Error('Choose RSA or Diffie–Hellman.');
  const a = randomSecret(), b = randomSecret();
  const A = modPow(DH_GENERATOR, a, DH_PRIME), B = modPow(DH_GENERATOR, b, DH_PRIME);
  const aliceShared = modPow(B, a, DH_PRIME), bobShared = modPow(A, b, DH_PRIME);
  if (aliceShared !== bobShared) throw new Error('Shared-secret check failed.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const [aliceKey, bobKey] = await Promise.all([aesKey(aliceShared,salt), aesKey(bobShared,salt)]);
  return {mode, A, B, salt, aliceKey, bobKey, agreement:true};
}
export async function encryptMessage(session, message) {
  const bytes = encoder.encode(message);
  if (!bytes.length || !message.trim()) throw new Error('Enter a message first.');
  const limit = session.mode === 'rsa' ? 190 : 1000;
  if (bytes.length > limit) throw new Error(`This mode accepts up to ${limit} UTF-8 bytes. Shorten your message.`);
  if (session.mode === 'rsa') {
    const ciphertext = await subtle().encrypt({name:'RSA-OAEP'}, session.pair.publicKey, bytes);
    return {ciphertext:new Uint8Array(ciphertext)};
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle().encrypt({name:'AES-GCM',iv}, session.aliceKey,bytes);
  return {ciphertext:new Uint8Array(ciphertext),iv};
}
export async function decryptMessage(session, packet) {
  const bytes = session.mode === 'rsa'
    ? await subtle().decrypt({name:'RSA-OAEP'},session.pair.privateKey,packet.ciphertext)
    : await subtle().decrypt({name:'AES-GCM',iv:packet.iv},session.bobKey,packet.ciphertext);
  return decoder.decode(bytes);
}
export function alterPacket(packet) {
  const ciphertext = packet.ciphertext.slice();
  ciphertext[Math.floor(ciphertext.length / 2)] ^= 1;
  return {...packet,ciphertext};
}
export const byteLength = message => encoder.encode(message).length;
