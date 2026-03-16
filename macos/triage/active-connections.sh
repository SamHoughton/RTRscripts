#!/bin/bash
# Active Network Connections - macOS
# IR Phase: Identification | Permission: Active Responder

echo "===== ACTIVE NETWORK CONNECTIONS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Established connections with process info
echo "===== ESTABLISHED CONNECTIONS ====="
echo "Proto  Local Address          Foreign Address        PID    Process"
echo "-----  ---------------------  ---------------------  -----  -------"
lsof -i -nP 2>/dev/null | awk '
  /ESTABLISHED/ {
    split($9, addr, "->")
    printf "%-6s %-22s %-22s %-6s %s\n", $8, addr[1], addr[2], $2, $1
  }
' | sort -k5
echo ""

# Listening ports
echo "===== LISTENING PORTS ====="
echo "Proto  Address                Port   PID    Process"
echo "-----  ---------------------  -----  -----  -------"
lsof -i -nP 2>/dev/null | awk '
  /LISTEN/ {
    n = split($9, parts, ":")
    port = parts[n]
    split($9, addr, ":")
    printf "%-6s %-22s %-6s %-6s %s\n", $8, $9, port, $2, $1
  }
' | sort -k1
echo ""

# DNS resolver config
echo "===== DNS CONFIGURATION ====="
cat /etc/resolv.conf 2>/dev/null || scutil --dns 2>/dev/null | grep -E "nameserver|domain" | head -10
echo ""

# Routing table (condensed)
echo "===== ROUTING TABLE (default routes) ====="
netstat -rn 2>/dev/null | grep -E "^default|^0\.0\.0\.0"
echo ""

# ARP cache — look for unusual MAC addresses
echo "===== ARP CACHE ====="
arp -a 2>/dev/null
echo ""

# Active firewall rules
echo "===== APPLICATION FIREWALL STATUS ====="
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null
/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null

echo "===== END ACTIVE CONNECTIONS ====="
