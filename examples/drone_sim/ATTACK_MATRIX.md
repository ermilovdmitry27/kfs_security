# Drone Sim Attack Matrix

## Base files

- `all/telemetry.csv` - all telemetry and alert rows
- `all/telemetry_alert.csv` - only alert rows
- `all/security_decisions.csv` - Security Manager decisions
- `all/security_summary.csv` - summary counters for the run

## Attack map

| Attack | Add in Cooja / headless name | Detection in sink | Main response | What to expect in CSV | Main summary counters |
|---|---|---|---|---|---|
| `replay` | `Attacker replay` / `replay` | repeated or old `seq` | `quarantine` | `attack=replay`, `reason=replay`, `apply_quarantine` | `quarantines`, `quarantine_releases` |
| `flood` | `Attacker flood` / `flood` | too many packets in short window | `rate_limit` | `attack=flood`, `reason=flood`, `apply_rate_limit` | `rate_limits`, `rate_limit_releases` |
| `spoofing` | `Attacker spoof` / `spoof` | invalid MAC or tampered fields | `quarantine` | `attack=spoofing`, `reason=spoofing`, `apply_quarantine` | `quarantines`, `quarantine_releases` |
| `impersonation` | `Attacker impersonation` / `impersonation` | sender does not match `drone_id` | `quarantine` | `attack=impersonation`, `reason=impersonation`, `apply_quarantine` | `quarantines`, `quarantine_releases` |
| `jamming` | `Jammer` / `jammer` | packet-gap / radio disruption | `channel_hop` | `attack=jamming`, `apply_channel_hop` | `channel_hops` |
| `blackhole` | `Relay blackhole` / `blackhole` | relay drops traffic completely | `isolate_relay` | `attack=blackhole`, `apply_isolate_relay` | `isolate_relay_actions` |
| `selective_forwarding` | `Relay selective` / `selective` | relay drops traffic selectively | `reroute` | `attack=selective_forwarding`, `apply_reroute` | `reroutes` |

## Minimal verification checklist

### Replay

- `security_decisions.csv` contains `replay`
- `security_decisions.csv` contains `apply_quarantine`
- `security_summary.csv` has `quarantines > 0`

### Flood

- `security_decisions.csv` contains `flood`
- `security_decisions.csv` contains `apply_rate_limit`
- `security_summary.csv` has `rate_limits > 0`
- no false `blackhole` in a flood-only run

### Spoofing

- `security_decisions.csv` contains `spoofing`
- `security_decisions.csv` contains `apply_quarantine`
- `security_summary.csv` has `quarantines > 0`

### Impersonation

- `security_decisions.csv` contains `impersonation`
- `security_decisions.csv` contains `apply_quarantine`
- `security_summary.csv` has `quarantines > 0`

### Jamming

- `telemetry.csv` contains `attack=jamming`
- `security_decisions.csv` contains `apply_channel_hop`
- `security_summary.csv` has `channel_hops > 0`

### Blackhole

- `telemetry.csv` contains `attack=blackhole`
- `security_decisions.csv` contains `apply_isolate_relay`
- `security_summary.csv` has `isolate_relay_actions > 0`

### Selective forwarding

- `telemetry.csv` contains `attack=selective_forwarding`
- `security_decisions.csv` contains `apply_reroute`
- `security_summary.csv` has `reroutes > 0`

## Headless examples

```sh
cd /home/user/diplom_kfs_security/examples/drone_sim

./run_attack_headless.sh replay 40
./run_attack_headless.sh flood 40
./run_attack_headless.sh spoof 40
./run_attack_headless.sh impersonation 40
./run_attack_headless.sh jammer 40
./run_attack_headless.sh blackhole 40
./run_attack_headless.sh selective 40
```

## Notes for the diploma

- `telemetry.csv` shows what happened in the CPS
- `security_decisions.csv` shows what the Security Manager decided
- `security_summary.csv` is the best file for comparison tables between scenarios
- a combined "all attacks" run is useful for stress testing, but separate runs are better for clean attack-by-attack evaluation
