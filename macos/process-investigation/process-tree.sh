#!/usr/bin/env bash
# =============================================================================
# macOS Process Tree — RTR / IR Script
# IR Phase   : Identification
# Platform   : macOS 12+
# Permission : Active Responder
# =============================================================================
# PURPOSE
#   Build a full parent → child process hierarchy and highlight suspicious
#   process relationships — e.g. browsers spawning shells, Office spawning
#   curl, or processes running from temp/Downloads paths.
#
# USAGE
#   runscript -CloudFile="macos/process-investigation/process-tree.sh"
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

echo "===== macOS PROCESS TREE ====="
echo "Host     : $HOSTNAME"
echo "Operator : $CURRENT_USER"
echo "Time     : $TIMESTAMP"
echo ""

# =============================================================================
# SECTION 1 — Full process snapshot with PPID
# ps -axo outputs: PID, PPID, USER, %CPU, %MEM, VSZ, STAT, START, TIME, COMM, ARGS
# =============================================================================
echo "===== ALL PROCESSES (pid / ppid / user / cmd) ====="
ps -axo pid=,ppid=,user=,stat=,lstart=,args= 2>/dev/null | \
  awk 'NR==1{print "  PID    PPID   USER           STAT  STARTED                COMMAND"; next}
       {printf "  %-6s %-6s %-14s %-5s %-22s %s\n", $1,$2,$3,$4,$5" "$6" "$7" "$8" "$9,$10}' | \
  head -200 || true
echo ""

# =============================================================================
# SECTION 2 — Suspicious parent/child pairs
# Attackers often abuse legitimate apps to spawn shells or download tools.
# =============================================================================
echo "===== SUSPICIOUS PARENT → CHILD RELATIONSHIPS ====="

# Build a PID→command map for parent lookup
declare -A CMDMAP
while IFS= read -r line; do
  pid=$(echo "$line" | awk '{print $1}')
  cmd=$(echo "$line" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}')
  CMDMAP[$pid]="${cmd:-unknown}"
done < <(ps -axo pid=,ppid=,user=,stat=,args= 2>/dev/null)

SUSPICIOUS_CHILDREN="bash|zsh|sh|python|python3|perl|ruby|osascript|curl|wget|nc|ncat|nmap"
SUSPICIOUS_PARENTS="Safari|firefox|Google Chrome|Microsoft Word|Microsoft Excel|Microsoft PowerPoint|Outlook|Teams|zoom|Slack"

FOUND=0
while IFS= read -r line; do
  pid=$(echo  "$line" | awk '{print $1}')
  ppid=$(echo "$line" | awk '{print $2}')
  cmd=$(echo  "$line" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}')
  parent_cmd="${CMDMAP[$ppid]:-unknown}"

  child_match=false; parent_match=false
  echo "$cmd"         | grep -qiE "$SUSPICIOUS_CHILDREN" && child_match=true
  echo "$parent_cmd"  | grep -qiE "$SUSPICIOUS_PARENTS"  && parent_match=true

  if $child_match && $parent_match; then
    echo "  [!] ALERT: Suspicious spawn"
    echo "      Parent (PID $ppid): $parent_cmd"
    echo "      Child  (PID $pid):  $cmd"
    echo ""
    FOUND=$((FOUND+1))
  fi
done < <(ps -axo pid=,ppid=,user=,stat=,args= 2>/dev/null) || true

[ "$FOUND" -eq 0 ] && echo "  [+] No suspicious parent/child relationships detected"
echo ""

# =============================================================================
# SECTION 3 — Processes running from suspicious paths
# /tmp, /var/folders (user temp), ~/Downloads, ~/Desktop are common staging dirs
# =============================================================================
echo "===== PROCESSES IN SUSPICIOUS PATHS ====="
RISKY_PATHS="/tmp/|/var/folders/|/private/tmp/|Downloads/|Desktop/|/Users/Shared/"
FOUND2=0
while IFS= read -r line; do
  pid=$(echo "$line" | awk '{print $1}')
  usr=$(echo "$line" | awk '{print $3}')
  cmd=$(echo "$line" | awk '{for(i=5;i<=NF;i++) printf $i" "; print ""}')
  if echo "$cmd" | grep -qE "$RISKY_PATHS"; then
    echo "  [!] PID $pid ($usr): $cmd"
    FOUND2=$((FOUND2+1))
  fi
done < <(ps -axo pid=,ppid=,user=,stat=,args= 2>/dev/null) || true
[ "$FOUND2" -eq 0 ] && echo "  [+] No processes found in suspicious paths"
echo ""

# =============================================================================
# SECTION 4 — Processes with no controlling terminal (hidden/daemon-like)
# Attackers sometimes detach from terminal to avoid visibility
# =============================================================================
echo "===== DETACHED / NO-TTY NON-SYSTEM PROCESSES ====="
FOUND3=0
while IFS= read -r line; do
  tty=$(echo  "$line" | awk '{print $2}')
  pid=$(echo  "$line" | awk '{print $1}')
  usr=$(echo  "$line" | awk '{print $3}')
  cmd=$(echo  "$line" | awk '{for(i=4;i<=NF;i++) printf $i" "; print ""}')
  # ?? = no controlling terminal; skip obvious system processes
  if [ "$tty" = "??" ] && ! echo "$cmd" | grep -qE "^(launchd|kernel_task|syslogd|configd|mds|mdworker|WindowServer|coreaudiod|AirPlayXPCHelper)"; then
    [ "$usr" != "root" ] && [ "$usr" != "_" ] && {
      echo "  PID $pid ($usr): $cmd"
      FOUND3=$((FOUND3+1))
    }
  fi
done < <(ps -axo pid=,tty=,user=,args= 2>/dev/null | tail -n +2) || true
[ "$FOUND3" -eq 0 ] && echo "  [+] No suspicious detached processes found"
echo ""

# =============================================================================
# SECTION 5 — High CPU / Memory consumers (could indicate cryptominer or loop)
# =============================================================================
echo "===== TOP CPU / MEMORY CONSUMERS ====="
echo "  --- Top 10 by CPU ---"
ps -axo pid=,user=,pcpu=,pmem=,args= 2>/dev/null | sort -rn -k3 | head -10 | \
  awk '{printf "  PID %-6s %-14s CPU: %-6s MEM: %-6s %s\n", $1,$2,$3,$4,$5}' || true
echo ""
echo "  --- Top 10 by Memory ---"
ps -axo pid=,user=,pcpu=,pmem=,args= 2>/dev/null | sort -rn -k4 | head -10 | \
  awk '{printf "  PID %-6s %-14s CPU: %-6s MEM: %-6s %s\n", $1,$2,$3,$4,$5}' || true
echo ""

echo "===== END macOS PROCESS TREE ====="
