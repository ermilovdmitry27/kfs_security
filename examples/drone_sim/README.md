# Drone Sim (Cooja)

This scenario simulates drone telemetry collection and sink-side detection over a mesh network.

## Message fields

- `ver`, `drone_id`, `seq`
- `temp`, `vib`, `gas`, `batt_mv`
- `t` (drone time)
- `attack` (detected attack type)
- `hazard` (detected physical hazard)

## Alert flags (`alerts`)

- `0x01` gas
- `0x02` impact/vibration
- `0x04` fire (temp+gas)
- `0x08` low battery
- `0x10` replay/old sequence
- `0x20` packet gap/offline
- `0x40` invalid/spoof-like anomaly
- `0x80` flood (too many packets)
- `0x0100` selective forwarding (node loss >> global loss)
- `0x0200` blackhole (node offline)
- `0x0400` impersonation (valid MAC but sender != claimed ID)

Severity:

- `CRIT`: fire/replay/invalid/impersonation
- `WARN`: other non-zero alerts
- `INFO`: no alerts

Detected attack (`attack` column):

- `spoofing`: `ALERT_INVALID`
- `replay`: `ALERT_REPLAY`
- `jamming`: `ALERT_PKT_GAP`
- `flood`: `ALERT_FLOOD`
- `selective_forwarding`: `ALERT_SELECTIVE`
- `blackhole`: offline timeout (node stops delivering data)
- `impersonation`: msg ID != sender ID
- `none`: no attack detected
Detected hazard (`hazard` column):

- `fire`, `gas`, `impact`, `battery_low`, `multi`, `none`

Notes:

- A simple MAC (FNV1a with shared key) protects against spoofing/tampering.
- Data is sent via Rime mesh (multi-hop). Drones send to sink ID=1 (set sink mote ID to 1 in Cooja, or change `sink_addr` in `drone.c`).
- Optional `relay.c` motes act as dedicated mesh relays.
- Optional `relay_blackhole.c` disables its radio after startup (blackhole).
- Optional `relay_selective.c` toggles radio on/off (selective forwarding).
- Optional `jammer.c` motes flood the base channel (129) to simulate jamming.
- Optional attackers:
  - `attacker_replay.c` (replay)
  - `attacker_flood.c` (flood)
  - `attacker_spoof.c` (spoofing/tamper)
  - `attacker_impersonation.c` (ID spoofing)
- Attacker motes should use IDs >= 200 in Cooja and are excluded from `CSV_DATA` telemetry (only alerts are logged).
- In `attacker_*` files, set `TARGET_ID` / `IMPERSONATE_ID` to an existing drone ID (e.g. 2). Attacks are logged under that drone ID.
- On repeated `ALERT_PKT_GAP` the sink instructs drones to hop channels.

## Output lines

- `DATA,...` normal decoded telemetry
- `ALERT,...` alert event
- `CSV_DATA,...` telemetry in CSV format (includes `attack`, `hazard`)
- `CSV_ALERT,...` alert in CSV format (includes `attack`, `hazard`)
- `CSV_HEADER,...` CSV columns

## Build

```sh
cd ~/contiki/examples/drone_sim
make clean TARGET=cooja
make drone.cooja TARGET=cooja
make sink.cooja TARGET=cooja
make relay.cooja TARGET=cooja
make relay_blackhole.cooja TARGET=cooja
make relay_selective.cooja TARGET=cooja
make jammer.cooja TARGET=cooja
make attacker_replay.cooja TARGET=cooja
make attacker_flood.cooja TARGET=cooja
make attacker_spoof.cooja TARGET=cooja
make attacker_impersonation.cooja TARGET=cooja
```

## Cooja usage

In `Mote output`, use filters:

- `ALERT` -> only alerts
- `CSV_ALERT` -> alert-only CSV
- `CSV_DATA` -> full telemetry CSV stream

Base topology (recommended):

- Sink ID=1
- Drones ID=2..N
- 2 relay motes (use `relay.c`, or swap one for `relay_selective.c`)
- Add attack modules one by one (jammer/attackers) to observe changes

## One-click clean simulation (.csc)

Open this file in Cooja:

- `examples/drone_sim/drone_sim_clean.csc`

It loads a clean network only:

- `sink`
- `drones`
- `2 relays`

Attack motetypes are also preloaded in this scenario, but no attack motes are
created automatically. This means the base network starts immediately, and you
can later add attack modules manually through Cooja as separate motes.

Fast start command (clean, no attack modules instantiated):

```sh
cd ~/diplom_kfs_security/examples/drone_sim
./start_clean.sh
```

`start_clean.sh` also fixes required Cooja user settings automatically:

- `PATH_CONTIKI`
- `PARSE_WITH_COMMAND=true`
- `PARSE_COMMAND=nm -aP -S $(LIBFILE)`
- log auto-append path

### Add attacks later as separate modules

After `./start_clean.sh`:

1. Open `Motes -> Add motes`.
2. Select one of the preloaded types:
   - `attacker_replay`
   - `attacker_flood`
   - `attacker_spoof`
   - `attacker_impersonation`
   - `jammer`
   - `relay_blackhole`
   - `relay_selective`
3. Add the needed number of motes and assign IDs `>= 200` for attacker motes.

This keeps `sink`, `drone`, and `relay` as the base scenario, while attacks are
connected separately as optional modules.

## One-click all modules preloaded

If you want everything already created (no manual "Add motes..." for attack modules), use:

- `examples/drone_sim/drone_sim_all_modules.csc`

This scenario already contains pre-created module motes:

- `attacker_replay` (ID 201)
- `attacker_flood` (ID 202)
- `attacker_spoof` (ID 203)
- `attacker_impersonation` (ID 204)
- `jammer` (ID 205)
- `relay_blackhole` (ID 206)
- `relay_selective` (ID 207)

Fast start command:

```sh
cd ~/diplom_kfs_security/examples/drone_sim
./start_all_modules.sh
```

## Export CSV to files (no copy/paste)

1. In Cooja `Mote output` window: `File -> Append to file`.
2. Choose log file path, e.g. `~/contiki/examples/drone_sim/output/mote_output.log`.
3. Run simulation.
4. CSV files are written automatically while simulation runs:

- `output/run_<YYYYMMDD_HHMMSS>/all/telemetry.csv`
- `output/run_<YYYYMMDD_HHMMSS>/all/telemetry_data.csv`
- `output/run_<YYYYMMDD_HHMMSS>/all/telemetry_alert.csv`
- `output/run_<YYYYMMDD_HHMMSS>/<drone_id>/telemetry.csv`
- `output/run_<YYYYMMDD_HHMMSS>/<drone_id>/telemetry_data.csv`
- `output/run_<YYYYMMDD_HHMMSS>/<drone_id>/telemetry_alert.csv`

### Optional: enable auto-append at startup (no dialog every run)

Add these lines to `~/.cooja.user.properties`:

```ini
LOG_LISTENER_APPENDFILE=/home/user/diplom_kfs_security/examples/drone_sim/output/mote_output.log
LOG_LISTENER_AUTO_APPEND=true
```

5. Optional: offline re-export from raw log:

```sh
cd ~/contiki/examples/drone_sim
./export_csv.sh output/mote_output.log output
```
