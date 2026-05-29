use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

pub fn run_keccak(n: usize, input: &[u8]) {
    assert!(input.len() >= 32);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&input[..32]);
    for _ in 0..n {
        let mut h = Keccak::v256();
        h.update(&buf);
        let mut out = [0u8; 32];
        h.finalize(&mut out);
        buf = out;
    }
    sp1_zkvm::io::commit_slice(&buf);
}

pub fn run_sha256(n: usize, input: &[u8]) {
    assert!(input.len() >= 32);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&input[..32]);
    for _ in 0..n {
        let out = Sha256::digest(buf);
        buf.copy_from_slice(&out);
    }
    sp1_zkvm::io::commit_slice(&buf);
}
