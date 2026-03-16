#!/bin/bash
# Active Network Connections - Linux
# IR Phase: Identification | Permission: Active Responder

echo "===== ACTIVE NETWORK CONNECTIONS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Prefer ss over netstat
if command -v ss &>/dev/null; then
  echo "===== ESTABLISHED CONNECTIONS (ss) ====="
  ss -antp state established 2>/dev/null | head -50
  echo ""
  echo "===== LISTENING PORTS (ss) ====="
  ss -lntp 2>/dev/null
else
  echo "===== ESTABLISHED CONNECTIONS (netstat) ====="
  netstat -antp 2>/dev/null | grep ESTABLISHED | head -50
  echo ""
  echo "===== LISTENING PORTS (netstat) ====="
  netstat -lntp 2>/dev/null
fi
echo ""

# Map connections to processes with lsof
echo "===== CONNECTIONS WITH PROCESS DETAILS (lsof) ====="
if command -v lsof &>/dev/null; then
  lsof -i -nP 2>/dev/null | grep -E "ESTABLISHED|LISTEN" | \
    awk 'NR==1 || /ESTABLISHED|LISTEN/' | head -40
else
  echo "  lsof not available — install with: apt/yum install lsof"
fi
echo ""

# DNS config
echo "===== DNS CONFIGURATION ====="
cat /etc/resolv.conf 2>/dev/null
echo ""

# Default routes
echo "===== DEFAULT ROUTES ====="
if command -v ip &>/dev/null; then
  ip route show default
else
  route -n 2>/dev/null | grep '^0\.0\.0\.0'
fi
echo ""

# ARP cache
echo "===== ARP CACHE ====="
if command -v ip &>/dev/null; then
  ip neigh show
else
  arp -n 2>/dev/null
fi
echo ""

# Firewall rules summary
echo "===== FIREWALL STATUS ====="
if command -v ufw &>/dev/null; then
  ufw status 2>/dev/null
elif command -v firewall-cmd &>/dev/null; then
  firewall-cmd --state 2>/dev/null
  firewall-cmd --list-all 2>/dev/null
elif command -v iptables &>/dev/null; then
  iptables -L -n --line-numbers 2>/dev/null | head -40
fi

echo "===== END ACTIVE CONNECTIONS ====="
