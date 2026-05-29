# research demo bench

SP1 v6.2.2. `client.execute()` only; no proof gen.

Hardware:

- CPU: Apple M4 Pro
- RAM: 24.0 GiB
- OS:  Darwin 24.6.0 arm64

Cycles + prover gas are deterministic for a given (ELF, stdin); spread is zero by construction. Only execution wall-clock varies — `exec_ms_median` is the median of `--runs` host-side timings.

| primitive | N | cycles | prover gas | exec ms | per-op cycles |
|---|---:|---:|---:|---:|---:|
| keccak256 | 1 | 2164 | 5510 | 13 | - |
| keccak256 | 10 | 8671 | 22688 | 9 | - |
| keccak256 | 100 | 73741 | 194468 | 8 | 723 |
| keccak256 | 1000 | 724441 | 1912271 | 20 | - |
| sha256 | 1 | 2194 | 5493 | 7 | - |
| sha256 | 10 | 8485 | 15595 | 7 | - |
| sha256 | 100 | 71395 | 116617 | 8 | 699 |
| sha256 | 1000 | 700495 | 1126836 | 23 | - |
| ecdsa-secp256k1 | 1 | 113010 | 124493 | 18 | - |
| ecdsa-secp256k1 | 10 | 1114189 | 1183111 | 92 | - |
| ecdsa-secp256k1 | 100 | 11117839 | 11763445 | 702 | 111159 |
| ecdsa-secp256k1 | 1000 | 111252786 | 117638381 | 5664 | - |
| eddsa-ed25519 | 1 | 74002 | 103042 | 43 | - |
| eddsa-ed25519 | 10 | 728207 | 952028 | 384 | - |
| eddsa-ed25519 | 100 | 7278388 | 9470213 | 4110 | 72771 |
| eddsa-ed25519 | 1000 | 72764353 | 94603418 | 37586 | - |

Per-op cycles = (cycles at N=100 - cycles at N=1) / 99. Strips program-init + IO + commit overhead (constant in N for hashes; constant in N for sigs too since the payload is read via read_vec, not bincode-walked).
