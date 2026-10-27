# bench/lab — manifest-driven N-initiator load-test harness (committed, versioned)

Runs the r2dp interop load-test lab on the Fedora exec box
(`yescorp@192.168.0.179`), kept in-repo so the work is versioned and never
lost.

## Design: manifest-driven, no hardcoded initiator names
- `gen_lab_conf.py` is the single generator.  Env: `NINIT` (default 4),
  `OUTER_BASE` (10.77.0.2), `INNER_BASE` (192.0.2.2), `RESP_OUTER` (10.77.0.1),
  `RESP_INNER` (192.0.2.1).  It writes per-initiator racoon2 A configs, one
  multi-remote B config (`racoonBmulti.conf`), and a **`lab.manifest`** — the
  single source of truth.  Every address/name is *derived* from the manifest,
  so N is a free parameter and nothing hardcodes `nsI0..7` / `racoonA{i}`.
- `lab_up.sh`       — bring up responder + N initiators by parsing the manifest.
- `lab_bench.sh`    — broad benchmark: per-initiator single-flow sweep +
                      concurrent aggregate + forwarder per-worker spread.
- `lab_teardown.sh` — PID/PGID-scoped teardown (manifest-driven netns cleanup).
- `bench_spawn3.sh` / `bench_teardown3.sh` — PID/PGID-scoped launcher + teardown
  (copied to the box at `$LB/scripts/`).

## Usage (on .179)
```
python3 bench/lab/gen_lab_conf.py         # default NINIT=4 (or NINIT=8 ...)
sudo NINIT=8 NWORKERS=4 bash bench/lab/lab_up.sh
sudo bash bench/lab/lab_bench.sh
sudo bash bench/lab/lab_teardown.sh
```

## Safety contract (user rule, hard)
- Teardown MUST be PID/PGID-scoped via `bench_teardown3.sh` (records groups
  from `bench_spawn3.sh`), never by process name/path.  The host runs PROD
  systemd `/usr/local/racoon2/sbin/{iked,spmd}` on :500/:4500; a name-based
  `pkill` kills them (NRestarts=4 happened once).
- `lab_up.sh` launches every daemon through `bench_spawn3.sh` (setsid + PGID
  recorded into the run's session file); `lab_teardown.sh` kills exactly those
  and ABORTS if a group leader is under /usr/local/racoon2.  Concurrency-safe:
  parallel runs use separate session files.

## Saturation methodology (why many initiators)
net_tap (AF_PACKET) hashes outer packets to tap queues by 5-tuple (max 64
queues in our source build).  ONE tunnel = one outer flow = one queue = one
worker, so single-flow throughput is worker-count independent (~1280-1500
Mbps, tap-I/O bound — same reason kernel XFRM only spread at `parallel8`).
To saturate the box, run MANY INITIATORS: each with its own outer src IP ->
distinct outer flow -> distinct tap queue -> distinct worker.  Set
`NWORKERS` = forwarder worker count; with N >= NWORKERS every worker's queue
gets flows.  (Confirmed live on .179: 2 initiator flows in-flight landed on 2
distinct workers simultaneously.)
