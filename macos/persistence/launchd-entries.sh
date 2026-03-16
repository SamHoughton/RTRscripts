#!/bin/bash
# LaunchD Persistence - Enumerate LaunchDaemons, LaunchAgents, login items, cron
# IR Phase: Identification | Permission: Active Responder
#
# NOTE: LaunchDaemons and LaunchAgents are the primary macOS persistence mechanism.
# Any plist not from Apple or a known vendor should be investigated.

echo "===== LAUNCHD PERSISTENCE ANALYSIS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"

# Known-safe vendor prefixes (add to this list as appropriate)
SAFE_PREFIXES="com.apple com.crowdstrike com.sentinelone com.microsoft com.google com.adobe com.zoom"

flag_entry() {
  local name="$1"
  for prefix in $SAFE_PREFIXES; do
    [[ "$name" == $prefix* ]] && return 1
  done
  return 0
}

scan_plist_dir() {
  local dir="$1"
  local label="$2"
  echo ""
  echo "===== $label ====="
  echo "  Path: $dir"
  if [ ! -d "$dir" ]; then echo "  [not found]"; return; fi
  echo ""
  printf "  %-5s %-55s %s\n" "Flag" "Label / File" "Program"
  echo "  -----------------------------------------------------------------------"
  for plist in "$dir"/*.plist; do
    [ -f "$plist" ] || continue
    filename=$(basename "$plist")
    label_val=$(defaults read "$plist" Label 2>/dev/null || echo "[no label]")
    prog=$(defaults read "$plist" Program 2>/dev/null || \
           defaults read "$plist" ProgramArguments 2>/dev/null | head -1 | tr -d '(",' || echo "")
    mtime=$(stat -f "%Sm" -t "%Y-%m-%d" "$plist" 2>/dev/null)
    if flag_entry "$label_val"; then
      flag="[!]"
    else
      flag="   "
    fi
    printf "  %-5s %-55s %s  [%s]\n" "$flag" "$label_val" "$prog" "$mtime"
  done
}

scan_plist_dir "/Library/LaunchDaemons"       "LAUNCH DAEMONS (System, all users)"
scan_plist_dir "/Library/LaunchAgents"        "LAUNCH AGENTS (System, all users)"
scan_plist_dir "$HOME/Library/LaunchAgents"   "LAUNCH AGENTS (Current user)"
scan_plist_dir "/System/Library/LaunchDaemons" "LAUNCH DAEMONS (Apple — for reference)"

# Login Items
echo ""
echo "===== LOGIN ITEMS ====="
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null \
  || echo "  Could not enumerate login items via osascript"
echo ""

# Cron jobs
echo "===== CRON JOBS ====="
echo "  Current user crontab:"
crontab -l 2>/dev/null || echo "  [none]"
echo ""
echo "  /etc/cron.d and /etc/cron.*:"
ls /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null | \
  while read f; do echo "  $f"; done
echo ""

# Periodic tasks
echo "===== PERIODIC TASKS (/etc/periodic) ====="
ls /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null

# At jobs
echo ""
echo "===== AT JOBS ====="
atq 2>/dev/null || echo "  [none or atq unavailable]"

echo "===== END LAUNCHD PERSISTENCE ====="
