//! Runs the demo bench cells, captures cycles + prover gas + exec time,
//! writes Markdown + CSV. Uses execute() only (no proof gen).
//!
//! Stdin layout per cell:
//!   chunk 0: bincode Header { scenario, n }.
//!   chunk 1: raw payload bytes via write_slice (read with read_vec in guest;
//!     avoids per-byte serde walk that polluted earlier per-op diffs).

use std::{fs, path::PathBuf, process::Command, time::Instant};

use anyhow::Result;
use clap::Parser;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use k256::ecdsa::{Signature as EcSignature, SigningKey as EcSigningKey};
use rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sp1_sdk::prelude::*;
use sp1_sdk::ProverClient;

const ELF: Elf = include_elf!("bench-program");
const SP1_VERSION: &str = "6.2.2";

#[derive(Clone, Copy, Debug, Serialize)]
enum Primitive {
    Keccak,
    Sha256,
    Ecdsa,
    Eddsa,
}

impl Primitive {
    fn name(self) -> &'static str {
        match self {
            Self::Keccak => "keccak256",
            Self::Sha256 => "sha256",
            Self::Ecdsa => "ecdsa-secp256k1",
            Self::Eddsa => "eddsa-ed25519",
        }
    }
}

#[derive(Serialize)]
struct Header {
    scenario: ScenarioTag,
    n: u32,
}

// Encoding must mirror `Scenario` in program/src/main.rs (bincode is positional).
#[derive(Serialize)]
#[serde(rename = "Scenario")]
enum ScenarioTag {
    Keccak,
    Sha256,
    Ecdsa,
    Eddsa,
}

impl From<Primitive> for ScenarioTag {
    fn from(p: Primitive) -> Self {
        match p {
            Primitive::Keccak => Self::Keccak,
            Primitive::Sha256 => Self::Sha256,
            Primitive::Ecdsa => Self::Ecdsa,
            Primitive::Eddsa => Self::Eddsa,
        }
    }
}

#[derive(Parser)]
struct Cli {
    #[arg(long, value_delimiter = ',', default_values_t = vec![1u32, 100])]
    n: Vec<u32>,
    #[arg(long, default_value_t = 3)]
    runs: u32,
    #[arg(long, default_value = "benches/results")]
    out: PathBuf,
}

#[derive(Serialize)]
struct Row {
    primitive: String,
    n: u32,
    cycles: u64,
    prover_gas: u64,
    exec_ms_median: u128,
}

#[tokio::main]
async fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let cli = Cli::parse();
    fs::create_dir_all(&cli.out)?;

    let hw = HwSpec::capture();
    println!("Hardware: {}", hw.one_line());

    let primitives = [Primitive::Keccak, Primitive::Sha256, Primitive::Ecdsa, Primitive::Eddsa];

    let client = ProverClient::from_env().await;

    let n_max = cli.n.iter().copied().max().unwrap_or(1);
    let payloads = prepare_payloads(n_max as usize);

    let mut rows = Vec::new();
    for prim in primitives {
        for &n in &cli.n {
            println!("-> {} x {}", prim.name(), n);
            // cycles + gas are deterministic given (ELF, stdin); only ms varies.
            // First run pins both; runs 2..=N exist purely to take ms median.
            let mut ms_samples = Vec::new();
            let mut cycles_pinned: Option<u64> = None;
            let mut gas_pinned: Option<u64> = None;
            for run in 0..cli.runs {
                let payload = payload_for(prim, n as usize, &payloads);
                let mut stdin = SP1Stdin::new();
                stdin.write(&Header { scenario: prim.into(), n });
                stdin.write_slice(payload);
                let t0 = Instant::now();
                let (_out, report) = client.execute(ELF, stdin.clone()).await?;
                let dt = t0.elapsed().as_millis();
                let cycles = report.total_instruction_count();
                let gas = report.gas().expect("gas calculation enabled by default in v6 SDK");
                match (cycles_pinned, gas_pinned) {
                    (None, None) => {
                        cycles_pinned = Some(cycles);
                        gas_pinned = Some(gas);
                    }
                    (Some(c), Some(g)) => {
                        assert_eq!(c, cycles, "cycles drift across runs: ({prim:?}, n={n})");
                        assert_eq!(g, gas, "gas drift across runs: ({prim:?}, n={n})");
                    }
                    _ => unreachable!(),
                }
                println!("   run {run}: {cycles} cycles, gas={gas}, {dt}ms");
                ms_samples.push(dt);
            }
            ms_samples.sort_unstable();
            rows.push(Row {
                primitive: prim.name().to_string(),
                n,
                cycles: cycles_pinned.expect("at least one run"),
                prover_gas: gas_pinned.expect("at least one run"),
                exec_ms_median: ms_samples[ms_samples.len() / 2],
            });
        }
    }

    write_csv(&cli.out.join("demo.csv"), &rows)?;
    write_md(&cli.out.join("demo.md"), &rows, &hw)?;
    println!("\nReports written to {}", cli.out.display());
    Ok(())
}

struct Payloads {
    seed: [u8; 32],
    ecdsa: Vec<u8>,
    eddsa: Vec<u8>,
}

fn prepare_payloads(n_max: usize) -> Payloads {
    let mut seed = [0u8; 32];
    Sha256::digest(b"bench-seed")
        .iter()
        .enumerate()
        .for_each(|(i, b)| seed[i] = *b);
    let mut rng = StdRng::from_seed(seed);

    let mut ecdsa = Vec::with_capacity(n_max * (33 + 64 + 32));
    let ecdsa_sk = EcSigningKey::random(&mut rng);
    let ecdsa_pk = ecdsa_sk.verifying_key().to_sec1_bytes();
    for i in 0..n_max {
        let msg = Sha256::digest([&seed[..], &i.to_le_bytes()].concat());
        let sig: EcSignature = ecdsa_sk.sign(&msg);
        ecdsa.extend_from_slice(&ecdsa_pk);
        ecdsa.extend_from_slice(&sig.to_bytes());
        ecdsa.extend_from_slice(&msg);
    }

    let mut eddsa = Vec::with_capacity(n_max * (32 + 64 + 32));
    let mut sk_bytes = [0u8; 32];
    Sha256::digest([&seed[..], b"eddsa"].concat())
        .iter()
        .enumerate()
        .for_each(|(i, b)| sk_bytes[i] = *b);
    let ed_sk = EdSigningKey::from_bytes(&sk_bytes);
    let ed_pk = ed_sk.verifying_key().to_bytes();
    for i in 0..n_max {
        let msg = Sha256::digest([&seed[..], b"-ed-", &i.to_le_bytes()].concat());
        let sig = ed_sk.sign(&msg);
        eddsa.extend_from_slice(&ed_pk);
        eddsa.extend_from_slice(&sig.to_bytes());
        eddsa.extend_from_slice(&msg);
    }

    Payloads { seed, ecdsa, eddsa }
}

fn payload_for<'a>(prim: Primitive, n: usize, p: &'a Payloads) -> &'a [u8] {
    match prim {
        Primitive::Keccak | Primitive::Sha256 => &p.seed[..],
        Primitive::Ecdsa => &p.ecdsa[..n * (33 + 64 + 32)],
        Primitive::Eddsa => &p.eddsa[..n * (32 + 64 + 32)],
    }
}

fn write_csv(path: &PathBuf, rows: &[Row]) -> Result<()> {
    let mut s = String::from("primitive,n,cycles,prover_gas,exec_ms_median\n");
    for r in rows {
        s.push_str(&format!(
            "{},{},{},{},{}\n",
            r.primitive, r.n, r.cycles, r.prover_gas, r.exec_ms_median
        ));
    }
    fs::write(path, s)?;
    Ok(())
}

fn write_md(path: &PathBuf, rows: &[Row], hw: &HwSpec) -> Result<()> {
    let mut s = String::from("# research demo bench\n\n");
    s.push_str(&format!("SP1 v{SP1_VERSION}. `client.execute()` only; no proof gen.\n\n"));
    s.push_str("Hardware:\n\n");
    s.push_str(&format!("- CPU: {}\n", hw.cpu));
    s.push_str(&format!("- RAM: {}\n", hw.ram));
    s.push_str(&format!("- OS:  {}\n\n", hw.os));
    s.push_str("Cycles + prover gas are deterministic for a given (ELF, stdin); spread is zero by construction. ");
    s.push_str("Only execution wall-clock varies — `exec_ms_median` is the median of ");
    s.push_str("`--runs` host-side timings.\n\n");
    s.push_str("| primitive | N | cycles | prover gas | exec ms | per-op cycles |\n");
    s.push_str("|---|---:|---:|---:|---:|---:|\n");
    let mut by_prim: std::collections::HashMap<String, (Option<u64>, Option<u64>)> = Default::default();
    for r in rows {
        let entry = by_prim.entry(r.primitive.clone()).or_default();
        if r.n == 1 {
            entry.0 = Some(r.cycles);
        } else if r.n == 100 {
            entry.1 = Some(r.cycles);
        }
    }
    for r in rows {
        let per_op = if r.n == 100 {
            by_prim
                .get(&r.primitive)
                .and_then(|(a, b)| match (a, b) {
                    (Some(c1), Some(c100)) => Some(c100.saturating_sub(*c1) / 99),
                    _ => None,
                })
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into())
        } else {
            "-".into()
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            r.primitive, r.n, r.cycles, r.prover_gas, r.exec_ms_median, per_op
        ));
    }
    s.push_str("\nPer-op cycles = (cycles at N=100 - cycles at N=1) / 99. ");
    s.push_str("Strips program-init + IO + commit overhead (constant in N for hashes; ");
    s.push_str("constant in N for sigs too since the payload is read via read_vec, not bincode-walked).\n");
    fs::write(path, s)?;
    Ok(())
}

struct HwSpec {
    cpu: String,
    ram: String,
    os: String,
}

impl HwSpec {
    fn capture() -> Self {
        let cpu = sh("sysctl", &["-n", "machdep.cpu.brand_string"])
            .or_else(|| {
                // Linux fallback: first `model name` line in /proc/cpuinfo
                fs::read_to_string("/proc/cpuinfo").ok().and_then(|s| {
                    s.lines()
                        .find_map(|l| l.strip_prefix("model name").and_then(|rest| rest.split(':').nth(1)))
                        .map(|v| v.trim().to_string())
                })
            })
            .unwrap_or_else(|| "unknown".into());
        let ram = sh("sysctl", &["-n", "hw.memsize"])
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|b| format!("{:.1} GiB", b as f64 / (1024.0 * 1024.0 * 1024.0)))
            .or_else(|| {
                fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
                    s.lines().find_map(|l| {
                        l.strip_prefix("MemTotal:").and_then(|rest| {
                            rest.split_whitespace()
                                .next()
                                .and_then(|n| n.parse::<u64>().ok())
                                .map(|kb| format!("{:.1} GiB", kb as f64 / (1024.0 * 1024.0)))
                        })
                    })
                })
            })
            .unwrap_or_else(|| "unknown".into());
        let os = sh("uname", &["-srm"]).unwrap_or_else(|| "unknown".into());
        Self {
            cpu,
            ram,
            os: os.trim().to_string(),
        }
    }

    fn one_line(&self) -> String {
        format!("{} | {} | {}", self.cpu, self.ram, self.os)
    }
}

fn sh(prog: &str, args: &[&str]) -> Option<String> {
    Command::new(prog)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
