# Матрица Атак Drone Sim

## Основные файлы

- `all/telemetry.csv` - общий журнал телеметрии и событий атак
- `all/telemetry_alert.csv` - только строки с тревогами
- `all/security_decisions.csv` - решения Security Manager
- `all/security_summary.csv` - сводные показатели по запуску

## Таблица атак

| Атака | Как запускается в Cooja / headless | Как обнаруживается в sink | Основная реакция | Что должно быть в CSV | Главные счётчики в summary |
|---|---|---|---|---|---|
| `replay` | `Attacker replay` / `replay` | повторный или старый `seq` | `quarantine` | `attack=replay`, `reason=replay`, `apply_quarantine` | `quarantines`, `quarantine_releases` |
| `flood` | `Attacker flood` / `flood` | слишком много пакетов за короткое окно | `rate_limit` | `attack=flood`, `reason=flood`, `apply_rate_limit` | `rate_limits`, `rate_limit_releases` |
| `spoofing` | `Attacker spoof` / `spoof` | неверный MAC или подмена полей | `quarantine` | `attack=spoofing`, `reason=spoofing`, `apply_quarantine` | `quarantines`, `quarantine_releases` |
| `impersonation` | `Attacker impersonation` / `impersonation` | sender не совпадает с `drone_id` | `quarantine` | `attack=impersonation`, `reason=impersonation`, `apply_quarantine` | `quarantines`, `quarantine_releases` |
| `jamming` | `Jammer` / `jammer` | packet-gap / радиопомеха | `channel_hop` | `attack=jamming`, `apply_channel_hop` | `channel_hops` |
| `blackhole` | `Relay blackhole` / `blackhole` | relay полностью перестаёт пропускать трафик | `isolate_relay` | `attack=blackhole`, `apply_isolate_relay` | `isolate_relay_actions` |
| `selective_forwarding` | `Relay selective` / `selective` | relay выборочно дропает пакеты | `reroute` | `attack=selective_forwarding`, `apply_reroute` | `reroutes` |

## Минимальный чек-лист проверки

### Replay

- в `security_decisions.csv` есть `replay`
- в `security_decisions.csv` есть `apply_quarantine`
- в `security_summary.csv` значение `quarantines > 0`

### Flood

- в `security_decisions.csv` есть `flood`
- в `security_decisions.csv` есть `apply_rate_limit`
- в `security_summary.csv` значение `rate_limits > 0`
- в отдельном flood-only прогоне не должно быть ложного `blackhole`

### Spoofing

- в `security_decisions.csv` есть `spoofing`
- в `security_decisions.csv` есть `apply_quarantine`
- в `security_summary.csv` значение `quarantines > 0`

### Impersonation

- в `security_decisions.csv` есть `impersonation`
- в `security_decisions.csv` есть `apply_quarantine`
- в `security_summary.csv` значение `quarantines > 0`

### Jamming

- в `telemetry.csv` есть `attack=jamming`
- в `security_decisions.csv` есть `apply_channel_hop`
- в `security_summary.csv` значение `channel_hops > 0`

### Blackhole

- в `telemetry.csv` есть `attack=blackhole`
- в `security_decisions.csv` есть `apply_isolate_relay`
- в `security_summary.csv` значение `isolate_relay_actions > 0`

### Selective forwarding

- в `telemetry.csv` есть `attack=selective_forwarding`
- в `security_decisions.csv` есть `apply_reroute`
- в `security_summary.csv` значение `reroutes > 0`

## Примеры headless-запуска

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
