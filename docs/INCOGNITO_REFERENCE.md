# External Incognito benchmark — background evidence only

Source: [official Incognito repository](https://github.com/incognito-sig/incognito),
revision **`d69425999ac75d59b121185673009ae117d42ca5`**.
The existing local clone was inspected and benchmarked without changing its
source or Cargo.lock; its Git worktree was clean after the run. We did not
implement, port or include its Rust source in the Group 5 source package.

## What ran on 2026-10-30

```text
cargo bench --locked --bench bench_incognito -- --sample-size 10 --warm-up-time 1 --measurement-time 2 --noplot
```

This selects the official `bench_incognito` target, covering convert/verify
for ring sizes 32, 64, 128, 256, 512 and 1024. It does not run the separate
wallet/retail/settlement/dualring benchmark targets or emulate network latency.
The [upstream README](https://github.com/incognito-sig/incognito/blob/d69425999ac75d59b121185673009ae117d42ca5/README.md)
provides `cargo bench` and optional Linux `tc` latency experiments; no `tc`
commands or network configuration changes were made on this Windows machine.

Environment: Windows, Intel64 Family 6 Model 170; Rust **1.85.1**,
`x86_64-pc-windows-gnu`, optimized bench profile, Criterion 0.5.1 from the
existing lockfile. Rustup was downloaded from the official static server,
SHA-256 checked and installed under `D:\5163 Ass2\.part-d-tools`; both
RUSTUP_HOME/CARGO_HOME and build output are isolated there. System PATH was
not changed. See the [Rust installation guide](https://rust-lang.org/tools/install/)
and [rustup installation options](https://rust-lang.github.io/rustup/installation/other.html).
That compiler/cache directory is excluded from the source delivery.

Each case uses 10 Criterion samples, a one-second warmup and a two-second
target measurement period. Criterion increased collection time for some
slow cases; the console reported that and some outliers. This short run is
reference evidence, not a high-precision or cross-machine performance claim.
No other project test process was active during these measurement samples.

## Results: Criterion median point estimates

| Ring size | Incognito conversion (ms) | Incognito verification (ms) |
|---|---:|---:|
| 32 | 23.071 | 14.042 |
| 64 | 47.530 | 27.162 |
| 128 | 91.235 | 51.879 |
| 256 | 183.043 | 103.174 |
| 512 | 362.268 | 203.924 |
| 1024 | 713.387 | 398.916 |

The upstream label **"Incognito Signing" actually times `params.convert`**.
The table reports the `median.point_estimate` from Criterion JSON, divided
by 1e6 to convert nanoseconds to milliseconds. The terminal may display a
slope/mean estimate instead; those numbers need not match this median table.

Evidence: [CSV with median confidence intervals](evidence/incognito-summary.csv)
and [source metadata, estimates and raw iteration/timing samples](evidence/incognito-results.json).
Confidence intervals are Criterion's 95% bootstrap intervals, not C's IQR.
The collection script reads official output files and does not generate
synthetic timings:

```powershell
python tools/collect_incognito_results.py --source ../incognito --criterion ../.part-d-tools/incognito-target/criterion
```

When using the isolated Windows rustup proxies, set RUSTUP_HOME, CARGO_HOME
and prepend their `cargo/bin` directory to PATH **in that process only**.
An ordinary existing Rust installation can run the cargo command directly.

## How to use the figures

Label them **external official implementation measured locally**, with
revision and settings. Incognito concerns signer anonymity and uses Rust /
secp256k1 in this benchmark. Our Concealed implementation concerns message
hiding and uses Python / BLS12-381. Their operations, privacy goals and
implementations differ, so these figures are not an apples-to-apples speed
ranking and are not Group 5's Concealed reproduction results.
