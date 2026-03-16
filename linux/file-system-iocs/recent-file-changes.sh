#!/bin/bash
# Recent File Changes - Linux — files created or modified in the last N hours
# IR Phase: Identification | Permission: Active Responder

HOURS=${1:-24}
echo "===== RECENT FILE CHANGES (last ${HOURS}h) ====="
echo "Host: $(hostname) | Since: $(date -d "-${HOURS} hours" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v-${HOURS}H '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"

MINUTES=$((HOURS * 60))
SUSPICIOUS_EXTS="\.(sh|py|rb|pl|so|ko|elf|out|cgi|php|jsp)$"

scan_dir() {
  local dir="$1"
  local depth="${2:-3}"
  [ -d "$dir" ] || return
  echo ""
  echo "--- $dir ---"
  find "$dir" -maxdepth "$depth" -type f -mmin "-${MINUTES}" 2>/dev/null | \
    sort | while read -r f; do
      size=$(stat -c "%s" "$f" 2>/dev/null || stat -f "%z" "$f" 2>/dev/null)
      mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d. -f1)
      if echo "$f" | grep -qE "$SUSPICIOUS_EXTS"; then
        flag="[!]"
      else
        flag="   "
      fi
      printf "  %s %-60s %8d bytes  %s\n" "$flag" "${f:${#dir}}" "${size:-0}" "$mtime"
    done
}

scan_dir "/tmp"              3
scan_dir "/var/tmp"          3
scan_dir "/dev/shm"          2
scan_dir "/etc"              2
scan_dir "/etc/cron.d"       2
scan_dir "/etc/systemd"      3
scan_dir "/usr/local/bin"    2
scan_dir "/usr/local/sbin"   2
scan_dir "/home"             3
scan_dir "/root"             3

echo ""
echo "===== RECENTLY MODIFIED SETUID/SETGID BINARIES ====="
find /usr /bin /sbin -maxdepth 4 -type f \( -perm -4000 -o -perm -2000 \) \
  -mmin "-${MINUTES}" 2>/dev/null | while read -r f; do
    perms=$(stat -c "%a" "$f" 2>/dev/null)
    mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d. -f1)
    printf "  [!!] %-50s perms=%s  %s\n" "$f" "$perms" "$mtime"
done

echo ""
echo "===== RECENTLY MODIFIED /etc/passwd, /etc/shadow, /etc/sudoers ====="
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  mtime_min=$(find "$f" -mmin "-${MINUTES}" 2>/dev/null)
  if [ -n "$mtime_min" ]; then
    mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d. -f1)
    printf "  [!!] %-40s modified: %s\n" "$f" "$mtime"
  fi
done

echo "===== END RECENT FILE CHANGES ====="
