#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"
CONTIKI_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "Usage: $0 <attack> [duration_sec]" >&2
  echo "Attacks: replay flood spoof impersonation jammer blackhole selective" >&2
  exit 1
fi

attack_name="$1"
duration_sec="${2:-60}"

case "$attack_name" in
  replay)
    attack_identifier="attacker_replay"
    attack_id="201"
    attack_x="70.0"
    attack_y="10.0"
    ;;
  flood)
    attack_identifier="attacker_flood"
    attack_id="202"
    attack_x="70.0"
    attack_y="20.0"
    ;;
  spoof)
    attack_identifier="attacker_spoof"
    attack_id="203"
    attack_x="35.0"
    attack_y="25.0"
    ;;
  impersonation)
    attack_identifier="attacker_impersonation"
    attack_id="204"
    attack_x="70.0"
    attack_y="40.0"
    ;;
  jammer)
    attack_identifier="jammer"
    attack_id="205"
    attack_x="70.0"
    attack_y="50.0"
    ;;
  blackhole)
    attack_identifier="relay_blackhole"
    attack_id="206"
    attack_x="32.0"
    attack_y="32.0"
    ;;
  selective)
    attack_identifier="relay_selective"
    attack_id="207"
    attack_x="36.0"
    attack_y="36.0"
    ;;
  *)
    echo "Unknown attack: $attack_name" >&2
    exit 1
    ;;
esac

JAVA_HOME_DEFAULT=/usr/lib/jvm/java-11-openjdk-amd64
if [ -z "${JAVA_HOME:-}" ]; then
  export JAVA_HOME="$JAVA_HOME_DEFAULT"
fi
export PATH="$JAVA_HOME/bin:$PATH"

if [ ! -f ../../tools/cooja/dist/cooja.jar ]; then
  (cd ../../tools/cooja && ant jar)
fi

mkdir -p output/tmp
sh ./ensure_cooja_user_props.sh "$SCRIPT_DIR/output/mote_output.log" "$CONTIKI_ROOT"
: > output/mote_output.log
rm -f org/contikios/cooja/corecomm/Lib*.java org/contikios/cooja/corecomm/Lib*.class 2>/dev/null || true
# Headless runs should start from a clean temporary mote type set. Otherwise Cooja
# may spend a very long time scanning thousands of stale mtype artifacts.
find obj_cooja -maxdepth 1 -type f -name 'mtype*' -delete 2>/dev/null || true

tmp_csc=$(mktemp "$SCRIPT_DIR/output/tmp/${attack_name}_XXXXXX.csc")
headless_log="/tmp/drone_sim_headless_${attack_name}.log"
export_log="/tmp/drone_sim_export_${attack_name}.log"
test_log="$SCRIPT_DIR/COOJA.testlog"
cleanup() {
  if [ "${keep_tmp_csc:-0}" -ne 1 ]; then
    rm -f "$tmp_csc"
  fi
}
trap cleanup EXIT INT TERM

mote_block=$(cat <<EOF
    <mote>
      <interface_config>
        org.contikios.cooja.interfaces.Position
        <x>${attack_x}</x>
        <y>${attack_y}</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        org.contikios.cooja.contikimote.interfaces.ContikiMoteID
        <id>${attack_id}</id>
      </interface_config>
      <interface_config>
        org.contikios.cooja.contikimote.interfaces.ContikiRadio
        <bitrate>250.0</bitrate>
      </interface_config>
      <motetype_identifier>${attack_identifier}</motetype_identifier>
    </mote>
EOF
)

script_block=$(cat <<EOF
  <plugin>
    org.contikios.cooja.plugins.ScriptRunner
    <plugin_config>
      <script><![CDATA[
GENERATE_MSG(${duration_sec} * 1000, "headless-stop");
while (true) {
  YIELD();
  if (msg.equals("headless-stop")) {
    log.testOK();
  }
  log.log(
    time +
    String.fromCharCode(9) +
    'ID:' + id +
    String.fromCharCode(9) +
    msg +
    String.fromCharCode(10)
  );
}
      ]]></script>
      <active>true</active>
    </plugin_config>
  </plugin>
EOF
)

awk -v mote_block="$mote_block" -v script_block="$script_block" '
  /<\/simulation>/ {
    printf "%s\n", mote_block
    print
    printf "%s\n", script_block
    next
  }
  { print }
' "$SCRIPT_DIR/drone_sim_clean.csc" > "$tmp_csc"

rm -f "$test_log"
rm -f "$headless_log" "$export_log"

java_status=0
timeout "$((duration_sec + 120))" \
  java -Duser.language=en -Duser.country=US -mx512m \
  -jar ../../tools/cooja/dist/cooja.jar \
  -nogui="$tmp_csc" \
  -contiki="$CONTIKI_ROOT" >"$headless_log" 2>&1 || java_status=$?

if [ ! -f "$test_log" ]; then
  keep_tmp_csc=1
  echo "Headless run did not produce COOJA.testlog" >&2
  echo "Java exit status: $java_status" >&2
  echo "Scenario: $tmp_csc" >&2
  echo "Headless log: $headless_log" >&2
  tail -n 80 "$headless_log" >&2 || true
  exit 1
fi

./export_csv.sh "$test_log" output >"$export_log" 2>&1 || {
  keep_tmp_csc=1
  echo "CSV export failed" >&2
  echo "Scenario: $tmp_csc" >&2
  echo "Headless log: $headless_log" >&2
  echo "Export log: $export_log" >&2
  tail -n 80 "$export_log" >&2 || true
  exit 1
}

latest_run=$(ls -1dt output/run_* 2>/dev/null | head -n 1 || true)
if [ -n "$latest_run" ]; then
  echo "$latest_run"
else
  echo "No run directory produced" >&2
  exit 1
fi
