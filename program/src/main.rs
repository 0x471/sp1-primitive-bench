//! Input layout:
//!   stdin chunk 0: bincode-encoded Header { scenario, n }.
//!   stdin chunk 1: raw payload bytes (read via sp1_zkvm::io::read_vec, no
//!     per-byte serde walk — keeps per-op cycle diffs free of IO bias when N
//!     varies but payload-per-record is constant).

#![no_main]
sp1_zkvm::entrypoint!(main);

mod hash;
mod sig;

use serde::Deserialize;

#[derive(Deserialize)]
enum Scenario {
    Keccak,
    Sha256,
    Ecdsa,
    Eddsa,
}

#[derive(Deserialize)]
struct Header {
    scenario: Scenario,
    n: u32,
}

pub fn main() {
    let header: Header = sp1_zkvm::io::read();
    let payload: Vec<u8> = sp1_zkvm::io::read_vec();
    let n = header.n as usize;
    match header.scenario {
        Scenario::Keccak => hash::run_keccak(n, &payload),
        Scenario::Sha256 => hash::run_sha256(n, &payload),
        Scenario::Ecdsa => sig::run_ecdsa(n, &payload),
        Scenario::Eddsa => sig::run_eddsa(n, &payload),
    }
}
