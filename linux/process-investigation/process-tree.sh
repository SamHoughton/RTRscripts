#!/usr/bin/env bash
# =============================================================================
# Linux Process Tree — RTR / IR Script
# IR Phase   : Identification
# Platform   : Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
# Permission : Active Responder
# =============================================================================
# PURPOSE
#   Build a full parent → child process hierarchy and flag suspicious
#   relationships. Common attacker patterns include: web servers spawning
#   shells, containers escaping to host, scripts running from /tmp or /dev/shm,
#   and processes with deleted or anonymously mapped binaries.
#
# USAGE
#   runscript -CloudFile="linux/process-investigation/process-tree.sh"
# =============================================================================

set -uo pipefail

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

echo "===== LINUX PROCESS TREE ====="
echo "Host     : $HOSTNAME"
echo "Operator : $CURRENT_USER"
echo "Time     : $TIMESTAMP"
echo ""

# Prefer pstree for visual output, fall back to ps
if command -v pstree &>/dev/null; then
  echo "===== PROCESS TREE (pstree) ====="
  pstree -p -u -l 2>/dev/null | head -200 || true
  echo ""
fi

# =============================================================================
# SECTION 1 — Full process list
# =============================================================================
echo "===== FULL PROCESS LIST (pid / ppid / user / cmd) ====="
ps -eo pid=,ppid=,user=,stat=,lstart=,cmd= --sort=ppid 2>/dev/null | \
  awk 'NR==1{print "  PID    PPID   USER           STAT  STARTED                CMD"; next}
       {printf "  %-6s %-6s %-14s %-5s %-22s %s\n",$1,$2,$3,$4,$5" "$6" "$7" "$8" "$9,$10}' | \
  head -200 || true
echo ""

# =============================================================================
# SECTION 2 — Suspicious parent → child relationships
# =============================================================================
echo "===== SUSPICIOUS PARENT → CHILD PAIRS ====="

SUSPICIOUS_CHILDREN="bash|zsh|sh|ksh|dash|python[23]?|perl|ruby|php|nc|ncat|nmap|curl|wget|socat|openssl"
# Common legitimate parents that should not spawn shells
SUSPICIOUS_PARENTS="nginx|apache2|httpd|php-fpm|mysql|postgres|redis-server|node|java|tomcat"

declare -A CMDMAP
while IFS= read -r line; do
  pid=$(echo "$line" | awk '{print $1}')
  cmd=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf $i" "; print ""}')
  CMDMAP["$pid"]="${cmd:-unknown}"
done < <(ps -eo pid=,cmd= 2>/dev/null) || true

FOUND=0
while IFS= read -r line; do
  pid=$(echo  "$line" | awk '{print $1}')
  ppid=$(echo "$line" | awk '{print $2}')
  cmd=$(echo  "$line" | awk '{for(i=3;i<=NF;i++) printf $i" "; print ""}')
  parent_cmd="${CMDMAP[$ppid]:-unknown}"

  child_match=false; parent_match=false
  echo "$cmd"        | grep -qiE "(^|/)($SUSPICIOUS_CHILDREN)( |$)" && child_match=true
  echo "$parent_cmd" | grep -qiE "(^|/)($SUSPICIOUS_PARENTS)"       && parent_match=true

  if $child_match && $parent_match; then
    echo "  [!] ALERT: Suspicious spawn"
    echo "      Parent (PID $ppid): $parent_cmd"
    echo "      Child  (PID $pid):  $cmd"
    echo ""
    FOUND=$((FOUND+1))
  fi
done < <(ps -eo pid=,ppid=,cmd= 2>/dev/null | tail -n +2) || true

[ "$FOUND" -eq 0 ] && echo "  [+] No suspicious parent/child relationships detected"
echo ""

# =============================================================================
# SECTION 3 — Processes running from deleted binaries (memfd, deleted-on-disk)
# Classic technique: write binary to disk, exec, delete — binary lives in memory
# /proc/<pid>/exe will show " (deleted)" suffix
# =============================================================================
echo "===== PROCESSES WITH DELETED BINARIES ====="
FOUND2=0
for pid in /proc/[0-9]*/; do
  PIDNUM=$(basename "$pid")
  EXE_LINK="$pid/exe"
  if [ -L "$EXE_LINK" ]; then
    TARGET=$(readlink "$EXE_LINK" 2>/dev/null || true)
    if echo "$TARGET" | grep -q '(deleted)'; then
      CMD=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200 || true)
      USR=$(stat -c '%U' "$pid" 2>/dev/null || true)
      echo "  [!] PID $PIDNUM ($USR): $CMD"
      echo "      Binary: $TARGET"
      echo ""
      FOUND2=$((FOUND2+1))
    fi
    # Also flag memfd-based execution (fileless)
    if echo "$TARGET" | grep -qE '^/memfd:|^/dev/shm/'; then
      CMD=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200 || true)
      USR=$(stat -c '%U' "$pid" 2>/dev/null || true)
      echo "  [!] MEMFD/SHM EXEC — PID $PIDNUM ($USR): $TARGET"
      echo "      Cmdline: $CMD"
      echo ""
      FOUND2=$((FOUND2+1))
    fi
  fi
done 2>/dev/null || true
[ "$FOUND2" -eq 0 ] && echo "  [+] No processes with deleted binaries found"
echo ""

# =============================================================================
# SECTION 4 — Processes running from suspicious paths
# /tmp, /dev/shm, /var/tmp are world-writable and frequently used for staging
# =============================================================================
echo "===== PROCESSES IN SUSPICIOUS PATHS ====="
FOUND3=0
for pid in /proc/[0-9]*/; do
  PIDNUM=$(basename "$pid")
  EXE_LINK="$pid/exe"
  [ -L "$EXE_LINK" ] || continue
  TARGET=$(readlink "$EXE_LINK" 2>/dev/null || true)
  if echo "$TARGET" | grep -qE '^/tmp/|^/var/tmp/|^/dev/shm/|^/run/user/|/\.'; then
    CMD=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200 || true)
    USR=$(stat -c '%U' "$pid" 2>/dev/null || true)
    echo "  [!] PID $PIDNUM ($USR): $TARGET"
    echo "      Cmdline: $CMD"
    FOUND3=$((FOUND3+1))
  fi
done 2>/dev/null || true
[ "$FOUND3" -eq 0 ] && echo "  [+] No processes found in high-risk paths"
echo ""

# =============================================================================
# SECTION 5 — Processes with no executable path (kernel threads excluded)
# =============================================================================
echo "===== PROCESSES WITH MISSING /proc/exe ====="
FOUND4=0
for pid in /proc/[0-9]*/; do
  PIDNUM=$(basename "$pid")
  EXE_LINK="$pid/exe"
  # Skip kernel threads (no exe link at all, not just unreadable)
  if [ ! -e "$EXE_LINK" ] 2>/dev/null; then
    COMM=$(cat "$pid/comm" 2>/dev/null || true)
    USR=$(stat -c '%U' "$pid" 2>/dev/null || true)
    # Skip root/kernel processes
    [ "$USR" = "root" ] && continue
    echo "  PID $PIDNUM ($USR) — $COMM (no exe)"
    FOUND4=$((FOUND4+1))
  fi
done 2>/dev/null | head -20 || true
[ "$FOUND4" -eq 0 ] && echo "  [+] No unexpected exe-less user processes found"
echo ""

# =============================================================================
# SECTION 6 — High CPU / Memory consumers
# =============================================================================
echo "===== TOP CPU / MEMORY CONSUMERS ====="
echo "  --- Top 10 CPU ---"
ps -eo pid=,user=,pcpu=,pmem=,cmd= --sort=-pcpu 2>/dev/null | head -10 | \
  awk '{printf "  PID %-6s %-14s CPU:%-6s MEM:%-6s %s\n",$1,$2,$3,$4,$5}' || true
echo ""
echo "  --- Top 10 Memory ---"
ps -eo pid=,user=,pcpu=,pmem=,cmd= --sort=-pmem 2>/dev/null | head -10 | \
  awk '{printf "  PID %-6s %-14s CPU:%-6s MEM:%-6s %s\n",$1,$2,$3,$4,$5}' || true
echo ""

echo "===== END LINUX PROCESS TREE ====="
