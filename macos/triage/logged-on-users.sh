#!/bin/bash
# Logged-On Users - macOS — current sessions, recent logins, auth events
# IR Phase: Identification | Permission: Active Responder

echo "===== LOGGED-ON USER ANALYSIS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Currently logged-in users
echo "===== CURRENT SESSIONS (who) ====="
who
echo ""

# Detailed session info
echo "===== ACTIVE SESSIONS (w) ====="
w 2>/dev/null
echo ""

# Last logins
echo "===== RECENT LOGINS (last 20) ====="
last -20 2>/dev/null
echo ""

# Failed auth attempts
echo "===== FAILED AUTH ATTEMPTS (last 24h) ====="
log show --predicate 'process == "loginwindow" && eventMessage CONTAINS "failed"' \
  --last 24h 2>/dev/null | tail -20 \
  || grep -i "failed" /var/log/system.log 2>/dev/null | tail -20 \
  || echo "  No auth failure log access (may need sudo)"
echo ""

# SSH sessions
echo "===== SSH SESSIONS ====="
echo "  Active SSH connections:"
lsof -i :22 -nP 2>/dev/null | grep ESTABLISHED || echo "  None"
echo ""
echo "  Recent SSH auth events:"
log show --predicate 'process == "sshd"' --last 2h 2>/dev/null | tail -20 \
  || grep "sshd" /var/log/system.log 2>/dev/null | tail -10 \
  || echo "  No sshd log access"
echo ""

# Console user
echo "===== CONSOLE USER ====="
stat -f '%Su' /dev/console 2>/dev/null
echo ""

# Users with shells
echo "===== USERS WITH LOGIN SHELLS ====="
dscl . list /Users UserShell 2>/dev/null | grep -v "nologin\|false\|git-shell" | \
  awk '{printf "  %-20s %s\n", $1, $2}'

echo "===== END LOGGED-ON USERS ====="
