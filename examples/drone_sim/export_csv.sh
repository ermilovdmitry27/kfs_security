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
function init_drone(id,    dir, cmd) {
  if (id == "" || id in drone_init) {
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
}

{
  msg = $3
  for (i = 4; i <= NF; i++) {
    msg = msg "\t" $i
  }

  if (index(msg, "CSV_DATA,") == 1) {
    payload = substr(msg, 10)
    split(payload, cols, ",")
    id = cols[3]
    init_drone(id)
    print "DATA," payload >> all_file
    print payload >> data_file
    if (id in drone_init) {
      print "DATA," payload >> drone_all[id]
      print payload >> drone_data[id]
    }
  } else if (index(msg, "CSV_ALERT,") == 1) {
    payload = substr(msg, 11)
    split(payload, cols, ",")
    id = cols[3]
    init_drone(id)
    print "ALERT," payload >> all_file
    print payload >> alert_file
    if (id in drone_init) {
      print "ALERT," payload >> drone_all[id]
      print payload >> drone_alert[id]
    }
  }
}
' all_file="$all_csv" data_file="$data_csv" alert_file="$alert_csv" out_dir="$run_dir" csv_header="$header" "$infile"

echo "Written:"
echo "  $all_csv"
echo "  $data_csv"
echo "  $alert_csv"
echo "  Per-drone folders: $run_dir/<drone_id>/"
