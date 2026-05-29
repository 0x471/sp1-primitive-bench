# Demo bench

Four primitives, N in {1, 100}, execute-only.

## Cells

| Primitive | N=1 | N=100 |
|---|---|---|
| Keccak256 | x | x |
| SHA-256 | x | x |
| ECDSA secp256k1 verify | x | x |
| EdDSA Ed25519 verify | x | x |

Each cell: N sequential invocations inside a single SP1 program, single `execute()` call.

## Metrics

- Cycles: `report.total_instruction_count()`.
- Prover gas: `report.gas().expect(...)` (v6 cost metric; calculated by default).
- Execute wall-clock: host-side timer.
- Per-op marginal: `(cycles at N=100 - cycles at N=1) / 99`.

Cycles + gas are deterministic for fixed (ELF, stdin). Only wall-clock varies; the harness asserts cycles + gas equality across runs.

## Stdin layout (matters for accuracy)

Two stdin chunks per invocation:
1. Bincode `Header { scenario, n }` — small, constant.
2. Raw payload bytes via `stdin.write_slice` / guest `sp1_zkvm::io::read_vec`.

The raw-byte path avoids per-byte serde walks. For signature cells the payload scales with N, but the per-record IO cost is dominated by a single `READ_VEC` syscall + memcpy, so the per-op derivation isolates the verify cost rather than absorbing IO.

## Run

```
cargo run --release -p bench-host
```

Writes `benches/results/demo.md` and `benches/results/demo.csv`.

## Methodology

- 3 execute runs per cell, median of wall-clock only.
- Cycles + gas are pinned on run 0 and asserted-equal on subsequent runs.
- Test vectors fixed, pre-generated host-side from a deterministic seed.
- Hardware spec (CPU / RAM / OS) is captured at runtime and written into the report header.

## Caveats

- Ed25519 verify internally hashes `R || A || M` with **SHA-512**. SP1 v6 has no SHA-512 precompile; that hashing runs in software. EdDSA cycles therefore include unaccelerated SHA-512 and scale with message length.
- ECDSA verify uses the patched `k256` route. Message is a 32-byte digest (no extra hashing inside the verify path).
- Poseidon is intentionally out of scope here. No SP1 precompile, and a plain-Rust BN254 implementation would lose to precompiled hashes by ~50-100x without informing any decision the current bench targets.

## Risks

| Risk | Mitigation |
|---|---|
| `sp1-patches/*` tag naming drifts | Verify against current SP1 v6 docs |
| ECDSA verify modes (recovery vs full pubkey) | Use full pubkey verify (`k256::ecdsa::VerifyingKey::verify`) |
| Execute cycles include stdin IO overhead | Header chunk is constant size; payload chunk read via `read_vec` (single syscall + memcpy, not per-byte serde) |
