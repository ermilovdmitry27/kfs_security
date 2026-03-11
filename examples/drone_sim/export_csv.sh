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
decision_csv="$all_dir/security_decisions.csv"
summary_csv="$all_dir/security_summary.csv"
attacker_min_id=200

default_header="sim_t,severity,drone_id,seq,temp,vib,gas,batt_mv,alerts,missed_total,data_count,alert_count,warn_count,crit_count,attack,hazard,risk,state,response"
default_decision_header="sim_t,drone_id,prev_state,state,prev_response,response,risk,reason,alerts,attack"
summary_header="drones,data_rows,alert_rows,decision_rows,attacked_drones,recovered_drones,recovery_rate_pct,max_risk,channel_hops,rate_limits,rate_limit_releases,quarantines,quarantine_releases,reroutes,isolate_relay_actions,crit_alerts,warn_alerts"

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

decision_header="$(awk -F '\t' '
{
  msg = $3
  for (i = 4; i <= NF; i++) {
    msg = msg "\t" $i
  }
  if (index(msg, "CSV_DECISION_HEADER,") == 1) {
    print substr(msg, 21)
    exit
  }
}
' "$infile")"

if [ -z "$header" ]; then
  header="$default_header"
fi
if [ -z "$decision_header" ]; then
  decision_header="$default_decision_header"
fi

case "$header" in
  type,*) echo "$header" > "$all_csv" ;;
  *) echo "type,$header" > "$all_csv" ;;
esac
echo "$header" > "$data_csv"
echo "$header" > "$alert_csv"
echo "$decision_header" > "$decision_csv"

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

function module_decision_reason_from_response(response) {
  if (response == "channel_hop") {
    return "apply_channel_hop"
  }
  if (response == "reroute") {
    return "apply_reroute"
  }
  if (response == "isolate_relay") {
    return "apply_isolate_relay"
  }
  return "module_alert"
}

function module_decision_payload_from_alert(payload, drone_id, cols, n, sim_t, risk, state, response, alerts, attack) {
  n = split(payload, cols, ",")
  sim_t = cols[1]
  alerts = cols[9]
  attack = cols[15]
  risk = cols[17]
  state = cols[18]
  response = cols[19]
  return sim_t "," drone_id ",NORMAL," state ",none," response "," \
         risk "," module_decision_reason_from_response(response) "," alerts "," attack
}

function append_module_alert_to_drone(drone_id, payload, rewritten) {
  decision_payload = ""
  if (!(drone_id in drone_init)) {
    return
  }
  rewritten = rewrite_payload_for_drone(payload, drone_id)
  print "ALERT," rewritten >> drone_all[drone_id]
  print rewritten >> drone_alert[drone_id]
  decision_payload = module_decision_payload_from_alert(payload, drone_id)
  print decision_payload >> drone_decision[drone_id]
}

function append_module_alert_to_all_and_drone(drone_id, payload, rewritten, decision_payload) {
  if (!(drone_id in drone_init)) {
    return
  }
  rewritten = rewrite_payload_for_drone(payload, drone_id)
  print "ALERT," rewritten >> all_file
  print rewritten >> alert_file
  decision_payload = module_decision_payload_from_alert(payload, drone_id)
  print decision_payload >> decision_file
  print "ALERT," rewritten >> drone_all[drone_id]
  print rewritten >> drone_alert[drone_id]
  print decision_payload >> drone_decision[drone_id]
}

function trim_embedded_payload(payload,    markers, count, i, pos, cut) {
  count = split("CSV_DATA,|CSV_ALERT,|CSV_DECISION,|DATA,|ALERT,|DECISION,", markers, "|")
  cut = 0
  for (i = 1; i <= count; i++) {
    pos = index(payload, markers[i])
    if (pos > 1 && (cut == 0 || pos < cut)) {
      cut = pos
    }
  }
  if (cut > 0) {
    payload = substr(payload, 1, cut - 1)
    sub(/[ \t]+$/, "", payload)
  }
  return payload
}

function normalize_known_token(token, known_csv,    known, count, i, matched) {
  gsub(/^[ \t]+|[ \t]+$/, "", token)
  if (token == "") {
    return token
  }
  count = split(known_csv, known, "|")
  matched = ""
  for (i = 1; i <= count; i++) {
    if (known[i] == token) {
      return token
    }
    if (index(known[i], token) == 1) {
      if (matched != "") {
        return token
      }
      matched = known[i]
    }
  }
  if (matched != "") {
    return matched
  }
  return token
}

function sanitize_payload(type, payload,    cols, n, i, out) {
  payload = trim_embedded_payload(payload)
  n = split(payload, cols, ",")
  if (type == "DECISION") {
    if (n >= 10) {
      cols[3] = normalize_known_token(cols[3], "NORMAL|SUSPICIOUS|UNDER_ATTACK|ISOLATED|RECOVERING|RECOVERED")
      cols[4] = normalize_known_token(cols[4], "NORMAL|SUSPICIOUS|UNDER_ATTACK|ISOLATED|RECOVERING|RECOVERED")
      cols[5] = normalize_known_token(cols[5], "none|observe|channel_hop|rate_limit|quarantine|reroute|isolate_relay")
      cols[6] = normalize_known_token(cols[6], "none|observe|channel_hop|rate_limit|quarantine|reroute|isolate_relay")
      cols[10] = normalize_known_token(cols[10], "none|replay|flood|spoofing|impersonation|jamming|blackhole|selective_forwarding")
    }
  } else if (n >= 19) {
    cols[2] = normalize_known_token(cols[2], "INFO|WARN|CRIT")
    cols[15] = normalize_known_token(cols[15], "none|replay|flood|spoofing|impersonation|jamming|blackhole|selective_forwarding")
    cols[18] = normalize_known_token(cols[18], "NORMAL|SUSPICIOUS|UNDER_ATTACK|ISOLATED|RECOVERING|RECOVERED")
    cols[19] = normalize_known_token(cols[19], "none|observe|channel_hop|rate_limit|quarantine|reroute|isolate_relay")
  }
  out = cols[1]
  for (i = 2; i <= n; i++) {
    out = out "," cols[i]
  }
  return out
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
  drone_decision[id] = dir "/security_decisions.csv"
  print "type," csv_header > drone_all[id]
  print csv_header > drone_data[id]
  print csv_header > drone_alert[id]
  print decision_header > drone_decision[id]
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
    payload = sanitize_payload("DATA", substr(msg, 10))
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
    payload = sanitize_payload("ALERT", substr(msg, 11))
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
  } else if (index(msg, "CSV_DECISION,") == 1) {
    payload = sanitize_payload("DECISION", substr(msg, 14))
    split(payload, cols, ",")
    id = cols[2]
    init_drone(id)
    if (id < attacker_min && (id in drone_init)) {
      print payload >> decision_file
      print payload >> drone_decision[id]
    }
  }
}
' all_file="$all_csv" data_file="$data_csv" alert_file="$alert_csv" decision_file="$decision_csv" out_dir="$run_dir" csv_header="$header" decision_header="$decision_header" attacker_min="$attacker_min_id" "$infile"

awk -F',' '
FILENAME == telemetry_file {
  if($1 == "type") {
    next
  }
  if($1 == "DATA") {
    data_rows++
  } else if($1 == "ALERT") {
    alert_rows++
    if($3 == "CRIT") {
      crit_alerts++
    } else if($3 == "WARN") {
      warn_alerts++
    }
  } else {
    next
  }

  drone_id = $4
  if(drone_id != "") {
    drones[drone_id] = 1
  }
  if($16 != "none" && drone_id != "") {
    attacked[drone_id] = 1
  }
  risk = $18 + 0
  if(risk > max_risk) {
    max_risk = risk
  }
  next
}
FILENAME == decision_file {
  if($1 == "sim_t") {
    next
  }
  decision_rows++
  drone_id = $2
  if(drone_id != "") {
    drones[drone_id] = 1
  }
  if($10 != "none" && drone_id != "") {
    attacked[drone_id] = 1
  }
  risk = $7 + 0
  if(risk > max_risk) {
    max_risk = risk
  }
  if($4 == "RECOVERED" && drone_id != "") {
    recovered[drone_id] = 1
  }
  if($8 == "recovered" && drone_id != "") {
    recovered[drone_id] = 1
  }
  if($8 == "apply_rate_limit") {
    rate_limits++
  } else if($8 == "rate_limit_released") {
    rate_limit_releases++
  } else if($8 == "apply_quarantine") {
    quarantines++
  } else if($8 == "quarantine_released") {
    quarantine_releases++
  } else if($8 == "apply_reroute") {
    reroutes++
  } else if($8 == "apply_isolate_relay") {
    isolate_relay_actions++
  }
  if($6 == "channel_hop") {
    channel_hops++
  }
}
END {
  drone_count = 0
  attacked_count = 0
  recovered_count = 0
  for(id in drones) {
    drone_count++
  }
  for(id in attacked) {
    attacked_count++
  }
  for(id in recovered) {
    recovered_count++
  }
  recovery_rate = 0
  if(attacked_count > 0) {
    recovery_rate = int((recovered_count * 100) / attacked_count)
  }
  print drone_count "," (0 + data_rows) "," (0 + alert_rows) "," (0 + decision_rows) "," \
        attacked_count "," recovered_count "," recovery_rate "," (0 + max_risk) "," \
        (0 + channel_hops) "," (0 + rate_limits) "," (0 + rate_limit_releases) "," \
        (0 + quarantines) "," (0 + quarantine_releases) "," (0 + reroutes) "," \
        (0 + isolate_relay_actions) "," (0 + crit_alerts) "," (0 + warn_alerts)
}
' telemetry_file="$all_csv" decision_file="$decision_csv" \
   "$all_csv" "$decision_csv" > "$summary_csv.tmp"

{
  echo "$summary_header"
  cat "$summary_csv.tmp"
} > "$summary_csv"
rm -f "$summary_csv.tmp"

echo "Written:"
echo "  $all_csv"
echo "  $data_csv"
echo "  $alert_csv"
echo "  $decision_csv"
echo "  $summary_csv"
echo "  Per-drone folders: $run_dir/<drone_id>/"
