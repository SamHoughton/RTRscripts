#!/bin/bash
# Host Summary - macOS rapid triage snapshot.
# IR Phase: Identification | Permission: Active Responder

echo "===== HOST SUMMARY ====="
echo "Hostname     : $(hostname)"
echo "OS Version   : $(sw_vers -productName) $(sw_vers -productVersion) (Build $(sw_vers -buildVersion))"
echo "Architecture : $(uname -m)"
echo "Kernel       : $(uname -r)"
echo "Serial No.   : $(system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial Number/ {print $NF}')"
echo "Model        : $(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name/ {print $2}')"
echo "Current Time : $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo ""

# Uptime
echo "===== UPTIME ====="
uptime
BOOT_TIME=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[={,]' '{print $2}' | xargs -I{} date -r {} '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
echo "Last Boot    : ${BOOT_TIME:-unknown}"
echo ""

# Users
echo "===== LOGGED-ON USERS ====="
who
echo ""

# Local admins
echo "===== LOCAL ADMIN USERS ====="
dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //'
echo ""

# Network interfaces
echo "===== NETWORK INTERFACES ====="
ifconfig | awk '/^[a-z]/{iface=$1} /inet /{print iface, $2}'
echo ""

# EDR / Security agents
echo "===== SECURITY AGENTS ====="
declare -A agents=(
  ["CrowdStrike"]="com.crowdstrike.falcond"
  ["SentinelOne"]="com.sentinelone.sentinel-agent"
  ["Microsoft Defender"]="com.microsoft.wdav.daemon"
  ["Carbon Black"]="com.carbonblack.cbsensor"
)
for name in "${!agents[@]}"; do
  if launchctl list 2>/dev/null | grep -q "${agents[$name]}"; then
    echo "  [+] $name is running (${agents[$name]})"
  fi
done
echo ""

# FileVault status
echo "===== FILEVAULT STATUS ====="
fdesetup status 2>/dev/null || echo "  fdesetup not available"
echo ""

# SIP status
echo "===== SYSTEM INTEGRITY PROTECTION (SIP) ====="
csrutil status 2>/dev/null || echo "  csrutil not available"

echo "===== END HOST SUMMARY ====="
