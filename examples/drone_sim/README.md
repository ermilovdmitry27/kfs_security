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

Severity:

- `CRIT`: fire/replay/invalid
- `WARN`: other non-zero alerts
- `INFO`: no alerts

Detected attack (`attack` column):

- `spoofing`: `ALERT_INVALID`
- `replay`: `ALERT_REPLAY`
- `jamming`: `ALERT_PKT_GAP`
- `flood`: `ALERT_FLOOD`
- `selective_forwarding`: `ALERT_SELECTIVE`
- `impersonation`: msg ID != sender ID
- `none`: no attack detected
Detected hazard (`hazard` column):

- `fire`, `gas`, `impact`, `battery_low`, `multi`, `none`

Notes:

- A simple MAC (FNV1a with shared key) protects against spoofing/tampering.
- Data is sent via Rime mesh (multi-hop). Drones send to sink ID=1 (set sink mote ID to 1 in Cooja, or change `sink_addr` in `drone.c`).
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
```

## Cooja usage

In `Mote output`, use filters:

- `ALERT` -> only alerts
- `CSV_ALERT` -> alert-only CSV
- `CSV_DATA` -> full telemetry CSV stream

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
