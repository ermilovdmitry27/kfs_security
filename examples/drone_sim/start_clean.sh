#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"
CONTIKI_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

JAVA_HOME_DEFAULT=/usr/lib/jvm/java-11-openjdk-amd64
if [ -z "${JAVA_HOME:-}" ]; then
  export JAVA_HOME="$JAVA_HOME_DEFAULT"
fi
export PATH="$JAVA_HOME/bin:$PATH"

if [ ! -f ../../tools/cooja/dist/cooja.jar ]; then
  (cd ../../tools/cooja && ant jar)
fi

mkdir -p output
sh ./ensure_cooja_user_props.sh "$SCRIPT_DIR/output/mote_output.log" "$CONTIKI_ROOT"
if [ "${RESET_LOG:-1}" = "1" ]; then
  : > output/mote_output.log
fi
# Remove stale generated JNI bridge classes from previous failed runs.
rm -f org/contikios/cooja/corecomm/Lib*.java org/contikios/cooja/corecomm/Lib*.class 2>/dev/null || true

exec java -Duser.language=en -Duser.country=US -mx512m \
  -jar ../../tools/cooja/dist/cooja.jar \
  -quickstart='drone_sim_clean.csc' \
  -contiki="$CONTIKI_ROOT"
