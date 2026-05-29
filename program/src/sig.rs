//! Payload layout per scenario:
//!   ECDSA:  N records of (33-byte SEC1 pubkey || 64-byte raw r||s sig || 32-byte msg digest)
//!   EdDSA:  N records of (32-byte pubkey || 64-byte sig || 32-byte msg)

use ed25519_dalek::{Signature as EdSignature, Verifier, VerifyingKey as EdVerifyingKey};
use k256::ecdsa::{signature::Verifier as _, Signature as EcSignature, VerifyingKey as EcVerifyingKey};

const ECDSA_RECORD: usize = 33 + 64 + 32;
const EDDSA_RECORD: usize = 32 + 64 + 32;

pub fn run_ecdsa(n: usize, payload: &[u8]) {
    assert!(payload.len() >= n * ECDSA_RECORD);
    let mut ok = 0u32;
    for i in 0..n {
        let r = &payload[i * ECDSA_RECORD..(i + 1) * ECDSA_RECORD];
        let pk = EcVerifyingKey::from_sec1_bytes(&r[..33]).expect("ecdsa pubkey decode");
        let sig = EcSignature::from_slice(&r[33..33 + 64]).expect("ecdsa sig decode");
        let msg = &r[33 + 64..];
        if pk.verify(msg, &sig).is_ok() {
            ok += 1;
        }
    }
    sp1_zkvm::io::commit(&ok);
}

pub fn run_eddsa(n: usize, payload: &[u8]) {
    assert!(payload.len() >= n * EDDSA_RECORD);
    let mut ok = 0u32;
    for i in 0..n {
        let r = &payload[i * EDDSA_RECORD..(i + 1) * EDDSA_RECORD];
        let pk_bytes: &[u8; 32] = r[..32].try_into().expect("eddsa pubkey len");
        let pk = EdVerifyingKey::from_bytes(pk_bytes).expect("eddsa pubkey decode");
        let sig_bytes: &[u8; 64] = r[32..96].try_into().expect("eddsa sig len");
        let sig = EdSignature::from_bytes(sig_bytes);
        let msg = &r[96..];
        if pk.verify(msg, &sig).is_ok() {
            ok += 1;
        }
    }
    sp1_zkvm::io::commit(&ok);
}
