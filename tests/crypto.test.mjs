import assert from 'node:assert/strict';
import {createDiffieHellman,getDiffieHellman} from 'node:crypto';
import {createSession,encryptMessage,decryptMessage,alterPacket,byteLength,DH_PRIME,DH_GENERATOR,modPow} from '../crypto-core.mjs';
// Compare independent DH arithmetic with OpenSSL, not another copy of this implementation.
const group=getDiffieHellman('modp14');
assert.equal(DH_PRIME.toString(16),group.getPrime('hex'));
assert.equal(DH_GENERATOR,2n);
const alice=createDiffieHellman(group.getPrime(),2);
const bob=createDiffieHellman(group.getPrime(),2);
alice.generateKeys();bob.generateKeys();
const a=BigInt('0x'+alice.getPrivateKey('hex'));
const B=BigInt('0x'+bob.getPublicKey('hex'));
assert.equal(modPow(B,a,DH_PRIME).toString(16).padStart(512,'0'),alice.computeSecret(bob.getPublicKey()).toString('hex'));
assert.equal(modPow(5n,6n,23n),8n);
for(const mode of ['rsa','dh']) {
 const session=await createSession(mode);
 for(const message of ['Hello Bob','Maths → security 🔐','<script>alert("test")</script>']) {
  const packet=await encryptMessage(session,message);
  assert.equal(await decryptMessage(session,packet),message);
  await assert.rejects(()=>decryptMessage(session,alterPacket(packet)));
  const other=await createSession(mode);
  await assert.rejects(()=>decryptMessage(other,packet));
  const again=await encryptMessage(session,message);
  assert.notDeepEqual(again.ciphertext,packet.ciphertext);
 }
 const limit=mode==='rsa'?190:1000;
 const edge=await encryptMessage(session,'a'.repeat(limit));
 assert.equal(await decryptMessage(session,edge),'a'.repeat(limit));
 await assert.rejects(()=>encryptMessage(session,'a'.repeat(limit+1)),/UTF-8 bytes/);
 await assert.rejects(()=>encryptMessage(session,'🔐'.repeat(Math.floor(limit/4)+1)),/UTF-8 bytes/);
 await assert.rejects(()=>encryptMessage(session,'   '),/Enter a message/);
 console.log(`${mode}: round trips, Unicode, literal markup, limits, wrong keys, randomised encryption and tamper rejection passed`);
}
assert.equal(byteLength('🔐'),4);
console.log('Diffie–Hellman matches independent OpenSSL computation. All cryptography checks passed.');
