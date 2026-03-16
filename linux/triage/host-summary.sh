#!/bin/bash
# Host Summary - Linux rapid triage snapshot.
# IR Phase: Identification | Permission: Active Responder

echo "===== HOST SUMMARY ====="
echo "Hostname     : $(hostname)"
echo "FQDN         : $(hostname -f 2>/dev/null || echo 'n/a')"
echo "Current Time : $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo ""

# OS info
echo "===== OS / KERNEL ====="
if [ -f /etc/os-release ]; then
  . /etc/os-release
  echo "  Distribution : $PRETTY_NAME"
fi
echo "  Kernel       : $(uname -r)"
echo "  Architecture : $(uname -m)"
echo ""

# Hardware
echo "===== HARDWARE ====="
if command -v dmidecode &>/dev/null; then
  dmidecode -s system-manufacturer 2>/dev/null | xargs -I{} echo "  Manufacturer : {}"
  dmidecode -s system-product-name 2>/dev/null | xargs -I{} echo "  Model        : {}"
  dmidecode -s system-serial-number 2>/dev/null | xargs -I{} echo "  Serial       : {}"
else
  cat /sys/class/dmi/id/sys_vendor 2>/dev/null | xargs -I{} echo "  Vendor : {}"
  cat /sys/class/dmi/id/product_name 2>/dev/null | xargs -I{} echo "  Model  : {}"
fi
echo ""

# Uptime
echo "===== UPTIME ====="
uptime
echo "  Last boot: $(who -b 2>/dev/null | awk '{print $3, $4}' || uptime -s 2>/dev/null)"
echo ""

# Network interfaces
echo "===== NETWORK INTERFACES ====="
if command -v ip &>/dev/null; then
  ip addr show | grep -E "^[0-9]|inet " | awk '
    /^[0-9]/ { iface=$2 }
    /inet /  { printf "  %-15s %s\n", iface, $2 }
  '
else
  ifconfig 2>/dev/null | grep -E "^[a-z]|inet " | awk '/^[a-z]/{i=$1} /inet /{print i, $2}'
fi
echo ""

# Current users
echo "===== LOGGED-ON USERS ====="
who
echo ""

# Local admins (uid 0 + sudo group)
echo "===== PRIVILEGED USERS ====="
echo "  UID 0 accounts:"
awk -F: '$3 == 0 {print "   ", $1}' /etc/passwd
echo "  sudo group members:"
getent group sudo 2>/dev/null || getent group wheel 2>/dev/null || grep -E "^sudo:|^wheel:" /etc/group
echo ""

# Security agents
echo "===== SECURITY AGENTS ====="
for agent in falcon-sensor sentinelone cbdaemon wdavdaemon; do
  if pgrep -x "$agent" &>/dev/null; then
    echo "  [+] $agent is running"
  fi
done

echo "===== END HOST SUMMARY ====="
