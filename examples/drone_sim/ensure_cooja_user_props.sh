#!/usr/bin/env sh
set -eu

LOG_FILE=$1
CONTIKI_ROOT=$2
PROPS_FILE="${HOME}/.cooja.user.properties"
PARSE_SCRIPT="${CONTIKI_ROOT}/tools/cooja/config/parse_symbols.sh"

ensure_prop() {
  key=$1
  value=$2
  tmp_file="${PROPS_FILE}.tmp"

  if [ -f "$PROPS_FILE" ]; then
    awk -v key="$key" -v value="$value" '
      BEGIN { updated = 0 }
      index($0, key "=") == 1 {
        print key "=" value
        updated = 1
        next
      }
      { print }
      END {
        if (!updated) {
          print key "=" value
        }
      }
    ' "$PROPS_FILE" > "$tmp_file"
  else
    {
      printf "#Cooja External Tools (User specific)\n"
      printf "%s=%s\n" "$key" "$value"
    } > "$tmp_file"
  fi

  mv "$tmp_file" "$PROPS_FILE"
}

mkdir -p "$(dirname "$PROPS_FILE")"

ensure_prop "PATH_CONTIKI" "$CONTIKI_ROOT"
ensure_prop "PARSE_WITH_COMMAND" "true"
ensure_prop "PARSE_COMMAND" "sh ${PARSE_SCRIPT} \$(LIBFILE)"
ensure_prop "COMMAND_VAR_NAME_ADDRESS_SIZE" '^([^.][^ ]*)[ \t]+<SECTION>[ \t]+([0-9a-fA-F]+)(?:[ \t]+([0-9a-fA-F]+))?.*$'
ensure_prop "COMMAND_VAR_SEC_DATA" '[DdGg]'
ensure_prop "COMMAND_VAR_SEC_BSS" '[Bb]'
ensure_prop "COMMAND_VAR_SEC_COMMON" '[C]'
ensure_prop "COMMAND_VAR_SEC_READONLY" '[Rr]'
ensure_prop "COMMAND_DATA_START" '^.data[ \t]d[ \t]([0-9A-Fa-f]*)[ \t]*$'
ensure_prop "COMMAND_DATA_END" '^_edata[ \t]A[ \t]([0-9A-Fa-f]*)[ \t]*$'
ensure_prop "COMMAND_BSS_START" '^__bss_start[ \t]A[ \t]([0-9A-Fa-f]*)[ \t]*$'
ensure_prop "COMMAND_BSS_END" '^_end[ \t]A[ \t]([0-9A-Fa-f]*)[ \t]*$'
ensure_prop "LOG_LISTENER_APPENDFILE" "$LOG_FILE"
ensure_prop "LOG_LISTENER_AUTO_APPEND" "true"
