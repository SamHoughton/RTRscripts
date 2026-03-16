#!/bin/bash
# Recent File Changes - macOS — files created or modified in the last N hours
# IR Phase: Identification | Permission: Active Responder

HOURS=${1:-24}
echo "===== RECENT FILE CHANGES (last ${HOURS}h) ====="
echo "Host: $(hostname) | Since: $(date -v-${HOURS}H '+%Y-%m-%d %H:%M:%S')"

SUSPICIOUS_EXTS="\.sh|\.py|\.rb|\.pl|\.dylib|\.so|\.kext|\.pkg|\.dmg|\.app|\.scpt|\.osax"

scan_dir() {
  local dir="$1"
  local depth="${2:-3}"
  [ -d "$dir" ] || return
  echo ""
  echo "--- $dir ---"
  find "$dir" -maxdepth "$depth" -type f \
    \( -newer /tmp/.rtr_time_marker 2>/dev/null \) \
    -not -path "*/\.*" \
    2>/dev/null | sort | while read -r f; do
      size=$(stat -f "%z" "$f" 2>/dev/null)
      mtime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$f" 2>/dev/null)
      ext="${f##*.}"
      if echo "$f" | grep -qE "$SUSPICIOUS_EXTS"; then
        flag="[!]"
      else
        flag="   "
      fi
      printf "  %s %-60s %8d bytes  %s\n" "$flag" "${f:${#dir}}" "$size" "$mtime"
  done
}

# Create a time marker file for -newer comparison
touch -t "$(date -v-${HOURS}H '+%Y%m%d%H%M.%S')" /tmp/.rtr_time_marker 2>/dev/null

scan_dir "/Library/LaunchDaemons"     2
scan_dir "/Library/LaunchAgents"      2
scan_dir "$HOME/Library/LaunchAgents" 2
scan_dir "/private/tmp"               3
scan_dir "/var/tmp"                   3
scan_dir "/usr/local/bin"             2
scan_dir "/Library/Application Support" 3
scan_dir "$HOME/Downloads"            2
scan_dir "$HOME/Desktop"              2

echo ""
echo "===== RECENTLY MODIFIED EXECUTABLES IN /usr/local ====="
find /usr/local -maxdepth 4 -type f -perm +111 \
  -newer /tmp/.rtr_time_marker 2>/dev/null | while read -r f; do
    mtime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$f" 2>/dev/null)
    printf "  [!] %-60s %s\n" "$f" "$mtime"
done

echo ""
echo "===== WORLD-WRITABLE FILES MODIFIED RECENTLY (in /tmp, /var/tmp) ====="
find /private/tmp /var/tmp -maxdepth 3 -type f -perm -o+w \
  -newer /tmp/.rtr_time_marker 2>/dev/null | while read -r f; do
    printf "  [!] %s\n" "$f"
done

rm -f /tmp/.rtr_time_marker
echo "===== END RECENT FILE CHANGES ====="
