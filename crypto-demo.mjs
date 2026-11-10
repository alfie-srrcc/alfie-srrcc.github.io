import {createSession,encryptMessage,decryptMessage,alterPacket,byteLength,DH_PRIME} from './crypto-core.mjs';
const el = id => document.getElementById('crypto-' + id);
let session = null, packet = null, busy = false, altered = false;
const describe = {
 rsa: {button:'1. Generate Bob’s RSA keys', alice:'Alice uses Bob’s public key to encrypt the message.', bob:'Bob keeps his private key and uses it to decrypt.', network:'Only Bob’s public key and the encrypted message cross the simulated channel.', maths:'RSA uses a public modulus n = p × q and exponents e and d. This demo uses RSA-OAEP with a 2048-bit key and SHA-256 padding, rather than insecure textbook RSA.', note:'RSA-OAEP encrypts a short message directly here. With these parameters the limit is 190 UTF-8 bytes. Real messaging protocols usually use hybrid encryption for longer messages.'},
 dh: {button:'1. Establish a shared key', alice:'Alice creates a private value a and shares A = 2ᵃ mod p.', bob:'Bob creates a private value b and shares B = 2ᵇ mod p.', network:'Alice and Bob exchange public values, then derive the same key independently.', maths:'A = gᵃ mod p; B = gᵇ mod p. Alice calculates Bᵃ mod p, while Bob calculates Aᵇ mod p. Both equal gᵃᵇ mod p. Here p is the RFC 3526 2048-bit group 14 prime and g = 2. HKDF-SHA-256 derives an AES-256-GCM key from that shared secret.', note:'Diffie–Hellman agrees a shared secret; it does not encrypt the message itself. AES-GCM encrypts and checks the message. This exchange does not authenticate identities, so it cannot prevent a man-in-the-middle attack.'}
};
const base64 = bytes => btoa(String.fromCharCode(...bytes));
const short = value => value.length > 72 ? value.slice(0,36)+'…'+value.slice(-28) : value;
function state(text, error=false) {
 el('status').textContent=text;
 el('status').classList.toggle('crypto-error',error);
}
function controls() {
 const limit=el('mode').value==='rsa'?190:1000;
 const count=byteLength(el('message').value);
 el('count').textContent=`${count} / ${limit} UTF-8 bytes`;
 el('count').classList.toggle('crypto-error',count>limit);
 el('mode').disabled=busy; el('setup').disabled=busy; el('reset').disabled=busy;
 el('encrypt').disabled=busy||!session||!el('message').value.trim()||count>limit;
 el('decrypt').disabled=busy||!packet;
 el('tamper').disabled=busy||!packet||altered;
}
function reset() {
 session=null;packet=null;altered=false;
 const d=describe[el('mode').value];
 el('setup').textContent=d.button;
 el('alice-explain').textContent=d.alice;
 el('bob-explain').textContent=d.bob;
 el('channel-explain').textContent=d.network;
 el('maths').textContent=d.maths;
 el('limitations').textContent=d.note;
 el('alice-key').textContent='Waiting for keys';el('bob-key').textContent='Waiting for keys';
 el('public').textContent='No public values exchanged yet.';
 el('cipher').textContent='Your encrypted message will appear here.';
 el('received').textContent='Bob has not decrypted a message yet.';
 el('integrity').textContent='Try changing the ciphertext after sending.';
 state('Start by generating keys. All processing stays in this browser.');controls();
}
async function task(action) {
 busy=true;controls();
 try { await action(); }
 catch(error) { state(error.message||'Something went wrong. Reset and try again.',true); }
 finally {busy=false;controls();}
}
el('setup').addEventListener('click',()=>task(async()=>{
 state('Creating fresh keys…');
 session=await createSession(el('mode').value);packet=null;altered=false;
 el('cipher').textContent='Your encrypted message will appear here.';
 el('received').textContent='Bob has not decrypted a message yet.';
 el('integrity').textContent='Try changing the ciphertext after sending.';
 if(session.mode==='rsa') {
  el('alice-key').textContent='Bob’s public key received';
  el('bob-key').textContent='2048-bit RSA key pair ready';
  el('public').textContent=`Public exponent e = 65537\nModulus n (base64url): ${short(session.publicJwk.n)}\nBob’s private key is not shown.`;
 } else {
  el('alice-key').textContent='Shared key derived by Alice';
  el('bob-key').textContent='Same shared key derived by Bob';
  el('public').textContent=`g = 2; p = ${DH_PRIME.toString(2).length} bits\nAlice’s public value A (hex): ${short(session.A.toString(16))}\nBob’s public value B (hex): ${short(session.B.toString(16))}\nShared secrets match: yes. Private values remain local.`;
 }
 state('Keys ready. Write a message, then encrypt and send.');
}));
el('encrypt').addEventListener('click',()=>task(async()=>{
 packet=await encryptMessage(session,el('message').value);altered=false;
 el('cipher').textContent=base64(packet.ciphertext);
 el('received').textContent='Ciphertext received. Choose “Decrypt at Bob”.';
 el('integrity').textContent=session.mode==='rsa'?'RSA-OAEP ciphertext ready.':'AES-GCM ciphertext includes an authentication tag.';
 state('Encrypted message sent across the simulated channel.');
}));
el('decrypt').addEventListener('click',()=>task(async()=>{
 try {
  const plain=await decryptMessage(session,packet);
  el('received').textContent=plain;
  el('integrity').textContent='Decryption succeeded. The original message was recovered.';
  state('Bob recovered the message. Try tampering, or send another message.');
 } catch {
  el('received').textContent='Message rejected. The ciphertext could not be verified and decrypted.';
  el('integrity').textContent='Modified ciphertext detected: no plaintext released.';
  state('Decryption rejected the modified message. Encrypt again to restore it.',true);
 }
}));
el('tamper').addEventListener('click',()=>{
 packet=alterPacket(packet);altered=true;
 el('cipher').textContent=base64(packet.ciphertext);
 el('received').textContent='Ciphertext changed. Decrypt again to see the result.';
 el('integrity').textContent='One bit was flipped in the ciphertext.';
 state('Ciphertext modified. Ask Bob to decrypt it.');controls();
});
el('reset').addEventListener('click',reset);
el('mode').addEventListener('change',reset);
el('message').addEventListener('input',controls);
if (!globalThis.crypto?.subtle) {
 document.querySelectorAll('#cryptography button, #cryptography select').forEach(e=>e.disabled=true);
 state('This demo needs a modern browser on HTTPS or localhost.',true);
} else reset();
