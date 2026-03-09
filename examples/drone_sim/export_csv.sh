#!/usr/bin/env sh
set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "Usage: $0 <mote_output_log.txt> [output_dir]" >&2
  exit 1
fi

infile="$1"
outdir="${2:-.}"

if [ ! -f "$infile" ]; then
  echo "Input file not found: $infile" >&2
  exit 1
fi

mkdir -p "$outdir"

run_dir="$outdir/run_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$run_dir"

all_dir="$run_dir/all"
mkdir -p "$all_dir"

all_csv="$all_dir/telemetry.csv"
data_csv="$all_dir/telemetry_data.csv"
alert_csv="$all_dir/telemetry_alert.csv"
attacker_min_id=200

default_header="sim_t,severity,drone_id,seq,temp,vib,gas,batt_mv,alerts,missed_total,data_count,alert_count,warn_count,crit_count,attack,hazard"

header="$(awk -F '\t' '
{
  msg = $3
  for (i = 4; i <= NF; i++) {
    msg = msg "\t" $i
  }
  if (index(msg, "CSV_HEADER,") == 1) {
    print substr(msg, 12)
    exit
  }
}
' "$infile")"

if [ -z "$header" ]; then
  header="$default_header"
fi

case "$header" in
  type,*) echo "$header" > "$all_csv" ;;
  *) echo "type,$header" > "$all_csv" ;;
esac
echo "$header" > "$data_csv"
echo "$header" > "$alert_csv"

awk -F '\t' '
function rewrite_payload_for_drone(payload, drone_id, cols, n, i, out) {
  n = split(payload, cols, ",")
  cols[3] = drone_id
  out = cols[1]
  for (i = 2; i <= n; i++) {
    out = out "," cols[i]
  }
  return out
}

function append_module_alert_to_drone(drone_id, payload, rewritten) {
  if (!(drone_id in drone_init)) {
    return
  }
  rewritten = rewrite_payload_for_drone(payload, drone_id)
  print "ALERT," rewritten >> drone_all[drone_id]
  print rewritten >> drone_alert[drone_id]
}

function append_module_alert_to_all_and_drone(drone_id, payload, rewritten) {
  if (!(drone_id in drone_init)) {
    return
  }
  rewritten = rewrite_payload_for_drone(payload, drone_id)
  print "ALERT," rewritten >> all_file
  print rewritten >> alert_file
  print "ALERT," rewritten >> drone_all[drone_id]
  print rewritten >> drone_alert[drone_id]
}

function init_drone(id,    dir, cmd) {
  j = 0
  if (id == "" || id in drone_init) {
    return
  }
  if (id in module_ids) {
    return
  }
  if (id >= attacker_min) {
    return
  }
  dir = out_dir "/" id
  cmd = "mkdir -p \"" dir "\""
  system(cmd)
  drone_all[id] = dir "/telemetry.csv"
  drone_data[id] = dir "/telemetry_data.csv"
  drone_alert[id] = dir "/telemetry_alert.csv"
  print "type," csv_header > drone_all[id]
  print csv_header > drone_data[id]
  print csv_header > drone_alert[id]
  drone_init[id] = 1
  for (j = 1; j <= module_alert_count; j++) {
    append_module_alert_to_drone(id, module_alert_payload[j])
  }
}

{
  raw_id = $2
  sub(/^ID:/, "", raw_id)

  msg = $3
  for (i = 4; i <= NF; i++) {
    msg = msg "\t" $i
  }

  if (index(msg, "ALERT,") == 1 && index(msg, "source=module") > 0) {
    module_ids[raw_id] = 1
  } else if (index(msg, "CSV_DATA,") == 1) {
    payload = substr(msg, 10)
    split(payload, cols, ",")
    id = cols[3]
    init_drone(id)
    if (id < attacker_min && !(id in module_ids)) {
      print "DATA," payload >> all_file
      print payload >> data_file
      if (id in drone_init) {
        print "DATA," payload >> drone_all[id]
        print payload >> drone_data[id]
      }
    }
  } else if (index(msg, "CSV_ALERT,") == 1) {
    payload = substr(msg, 11)
    split(payload, cols, ",")
    id = cols[3]
    init_drone(id)
    if (id in module_ids) {
      module_alert_payload[++module_alert_count] = payload
      for (drone_id in drone_init) {
        append_module_alert_to_all_and_drone(drone_id, payload)
      }
    } else if (id < attacker_min && (id in drone_init)) {
      print payload >> alert_file
      print "ALERT," payload >> all_file
      print "ALERT," payload >> drone_all[id]
      print payload >> drone_alert[id]
    }
  }
}
' all_file="$all_csv" data_file="$data_csv" alert_file="$alert_csv" out_dir="$run_dir" csv_header="$header" attacker_min="$attacker_min_id" "$infile"

echo "Written:"
echo "  $all_csv"
echo "  $data_csv"
echo "  $alert_csv"
echo "  Per-drone folders: $run_dir/<drone_id>/"
