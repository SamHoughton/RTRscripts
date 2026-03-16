#!/bin/bash
# Systemd Persistence - Enumerate services, timers, cron, rc.local, at jobs
# IR Phase: Identification | Permission: Active Responder

echo "===== LINUX PERSISTENCE ANALYSIS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Systemd service units from non-standard paths
echo "===== SYSTEMD SERVICES — NON-STANDARD PATHS ====="
echo "  (Services whose ExecStart is not in /usr, /bin, /sbin, /lib)"
systemctl list-units --type=service --all --no-pager 2>/dev/null | \
  awk '/\.service/ {print $1}' | while read -r svc; do
    execstart=$(systemctl show "$svc" -p ExecStart 2>/dev/null | \
      grep -oP 'path=\K[^;]+' | head -1)
    if [ -n "$execstart" ] && \
       ! echo "$execstart" | grep -qE "^/usr|^/bin|^/sbin|^/lib|^/opt/(crowdstrike|sentinel|microsoft)"; then
      state=$(systemctl is-active "$svc" 2>/dev/null)
      printf "  [!] %-45s %-10s %s\n" "$svc" "$state" "$execstart"
    fi
done
echo ""

# All enabled services
echo "===== ALL ENABLED SYSTEMD SERVICES ====="
systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -60
echo ""

# Systemd timers (can be used for persistence like cron)
echo "===== SYSTEMD TIMERS ====="
systemctl list-timers --all --no-pager 2>/dev/null
echo ""

# Custom unit files in writable locations
echo "===== CUSTOM UNIT FILES (non-package paths) ====="
for dir in /etc/systemd/system /run/systemd/system ~/.config/systemd/user; do
  if [ -d "$dir" ]; then
    echo "--- $dir ---"
    ls -la "$dir"/*.service "$dir"/*.timer 2>/dev/null | grep -v "^total"
  fi
done
echo ""

# Cron
echo "===== CRONTABS ====="
echo "  Root crontab:"
crontab -u root -l 2>/dev/null || echo "  [none or no access]"
echo ""
echo "  /etc/crontab:"
cat /etc/crontab 2>/dev/null || echo "  [not found]"
echo ""
echo "  /etc/cron.d/:"
ls -la /etc/cron.d/ 2>/dev/null && for f in /etc/cron.d/*; do
  echo "  --- $f ---"; cat "$f" 2>/dev/null; echo ""; done
echo ""
echo "  User crontabs (/var/spool/cron):"
ls /var/spool/cron/crontabs/ 2>/dev/null || ls /var/spool/cron/ 2>/dev/null || echo "  [none]"
echo ""

# rc.local
echo "===== RC.LOCAL ====="
cat /etc/rc.local 2>/dev/null || echo "  Not present"
echo ""

# /etc/init.d scripts (SysV)
echo "===== INIT.D SCRIPTS (non-standard) ====="
ls /etc/init.d/ 2>/dev/null | while read -r s; do
  if ! dpkg -S "/etc/init.d/$s" &>/dev/null 2>&1 && \
     ! rpm -qf "/etc/init.d/$s" &>/dev/null 2>&1; then
    echo "  [!] $s (not owned by any package)"
  fi
done

# At jobs
echo ""
echo "===== AT JOBS ====="
atq 2>/dev/null || echo "  [none or at not installed]"

echo "===== END SYSTEMD PERSISTENCE ====="
