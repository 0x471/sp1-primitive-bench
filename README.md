# Research

SP1 benchmarks for some basic primitives.

## Run the demo

Requires the SP1 toolchain (run `sp1up && sp1up`).

```
cargo run --release -p bench-host
```

Writes `benches/results/demo.md` and `benches/results/demo.csv`.

Per-op marginal cost = (cycles at N=100 - cycles at N=1) / 99. Strips program-setup overhead. Hash payload is constant 32 B; signature payload is delivered via raw `write_slice` / `read_vec` so per-record IO is also constant in N. Cycles + prover gas are deterministic for a given (ELF, stdin) — runs > 1 only sample wall-clock variance.
