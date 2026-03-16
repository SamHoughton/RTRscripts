#!/usr/bin/env bash
# =============================================================================
# Linux Credential Indicators — RTR / IR Script
# IR Phase   : Identification
# Platform   : Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
# Permission : Active Responder
# =============================================================================
# PURPOSE
#   Identify signs of credential access, harvesting, or theft on a Linux host.
#   Checks for: unusual passwd/shadow access, SSH key anomalies, credential
#   files in unexpected locations, memory-scraping processes, browser credential
#   stores, and suspicious SUID binaries that could facilitate privilege escalation.
#
# USAGE
#   runscript -CloudFile="linux/credential-indicators/credential-files.sh"
# =============================================================================

set -uo pipefail

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

echo "===== LINUX CREDENTIAL INDICATORS ====="
echo "Host     : $HOSTNAME"
echo "Operator : $CURRENT_USER"
echo "Time     : $TIMESTAMP"
echo ""

# =============================================================================
# SECTION 1 — /etc/passwd and /etc/shadow — modification times + new entries
# Attackers may add backdoor accounts or modify existing ones
# =============================================================================
echo "===== /etc/passwd and /etc/shadow STATUS ====="

for f in /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  MOD=$(stat -c '%y' "$f" 2>/dev/null || stat -f '%Sm' "$f" 2>/dev/null || echo "unknown")
  PERM=$(stat -c '%A %U:%G' "$f" 2>/dev/null || stat -f '%Sp %Su:%Sg' "$f" 2>/dev/null || echo "unknown")
  echo "  $f"
  echo "    Modified : $MOD"
  echo "    Perms    : $PERM"
done
echo ""

# Recent passwd/shadow/sudoers changes (within 7 days)
echo "  --- Files modified in last 7 days ---"
find /etc -name 'passwd' -o -name 'shadow' -o -name 'sudoers' -o -name 'sudoers.d' \
  2>/dev/null | xargs -I{} find {} -newer /tmp -mtime -7 2>/dev/null | while read -r f; do
  echo "  [!] Recently modified: $f"
done || true

# Accounts with UID 0 (root-equivalent — should be only root)
echo ""
echo "  --- UID 0 accounts (should be only 'root') ---"
awk -F: '$3==0 {print "  [!] UID 0: "$1" shell="$7}' /etc/passwd 2>/dev/null || true

# Accounts with shells that are not nologin/false (can log in)
echo ""
echo "  --- Accounts with login shells ---"
awk -F: '$7 !~ /nologin|false|sync/ && $1 != "#" {print "  " $1 " (" $7 ")"}' /etc/passwd 2>/dev/null || true
echo ""

# =============================================================================
# SECTION 2 — SSH key files — look for new/unusual keys
# =============================================================================
echo "===== SSH KEYS ====="

echo "  --- authorized_keys files ---"
find /root /home -name 'authorized_keys' 2>/dev/null | while read -r akf; do
  OWNER=$(stat -c '%U' "$akf" 2>/dev/null || true)
  MOD=$(stat -c '%y' "$akf" 2>/dev/null || true)
  COUNT=$(wc -l < "$akf" 2>/dev/null || echo "?")
  echo "  $akf (owner: $OWNER, modified: $MOD, keys: $COUNT)"
  # Print each key fingerprint + comment
  while read -r keyline; do
    [ -z "$keyline" ] && continue
    echo "$keyline" | grep -q '^#' && continue
    # Extract key type and comment
    TYPE=$(echo "$keyline" | awk '{print $1}')
    COMMENT=$(echo "$keyline" | awk '{print $3}')
    echo "    Key: $TYPE  Comment: $COMMENT"
  done < "$akf"
done || echo "  No authorized_keys files found"
echo ""

echo "  --- Private key files in home dirs (unexpected locations) ---"
KEYFILES_FOUND=0
# Look for PEM headers in readable files
find /home /root /tmp /var/tmp 2>/dev/null -type f \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' \) | while read -r kf; do
  OWNER=$(stat -c '%U' "$kf" 2>/dev/null || true)
  echo "  [!] Private key: $kf (owner: $OWNER)"
  KEYFILES_FOUND=$((KEYFILES_FOUND+1))
done || true
echo ""

# =============================================================================
# SECTION 3 — .bash_history and credential exposure
# Attackers sometimes issue commands with passwords inline; check for exposed creds
# =============================================================================
echo "===== SHELL HISTORY — CREDENTIAL EXPOSURE ====="
CRED_PATTERNS="password|passwd|secret|token|api_key|apikey|Authorization|Bearer|--password|:password@|-p "

for HISTFILE in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do
  [ -f "$HISTFILE" ] || continue
  OWNER=$(stat -c '%U' "$HISTFILE" 2>/dev/null || true)
  MATCHES=$(grep -inE "$CRED_PATTERNS" "$HISTFILE" 2>/dev/null | tail -20 || true)
  if [ -n "$MATCHES" ]; then
    echo "  [!] Potential credentials in $HISTFILE (owner: $OWNER):"
    echo "$MATCHES" | sed 's/^/    /'
    echo ""
  fi
done || true
echo "  [i] Credential keyword scan complete"
echo ""

# =============================================================================
# SECTION 4 — Unusual SUID/SGID binaries
# SUID binaries run as their owner (often root) — a common privesc vector
# =============================================================================
echo "===== UNUSUAL SUID / SGID BINARIES ====="

# Known-good SUID binaries baseline
KNOWN_SUID="ping|ping6|sudo|su|passwd|newgrp|chfn|chsh|mount|umount|pkexec|ssh-agent|Xorg|at|crontab|gpasswd|traceroute|write|wall|chage|expiry|polkit|dbus-daemon-launch-helper"

SUID_FOUND=0
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r f; do
  BASE=$(basename "$f")
  if ! echo "$BASE" | grep -qiE "^($KNOWN_SUID)$"; then
    OWNER=$(stat -c '%U:%G' "$f" 2>/dev/null || true)
    MOD=$(stat -c '%y' "$f" 2>/dev/null || true)
    echo "  [!] Unusual SUID: $f (owner: $OWNER, modified: $MOD)"
    SUID_FOUND=$((SUID_FOUND+1))
  fi
done
echo ""

# =============================================================================
# SECTION 5 — Memory scraping / LSASS-equivalent (process accessing /proc/mem)
# On Linux, /proc/<pid>/mem is the in-memory read target for credential scrapers
# =============================================================================
echo "===== PROCESSES ACCESSING /proc/*/mem (credential scraping indicator) ====="
# Check open file descriptors for any process reading another process's mem
MEM_FOUND=0
for pid in /proc/[0-9]*/fd/; do
  PIDNUM=$(echo "$pid" | grep -o '[0-9]*' | head -1)
  if ls -la "$pid" 2>/dev/null | grep -q '/proc/.*/mem'; then
    CMD=$(cat "/proc/$PIDNUM/cmdline" 2>/dev/null | tr '\0' ' ' | head -c 200 || true)
    USR=$(stat -c '%U' "/proc/$PIDNUM" 2>/dev/null || true)
    echo "  [!] PID $PIDNUM ($USR) reading process memory: $CMD"
    MEM_FOUND=$((MEM_FOUND+1))
  fi
done 2>/dev/null || true
[ "$MEM_FOUND" -eq 0 ] && echo "  [+] No processes detected accessing /proc/<pid>/mem"
echo ""

# =============================================================================
# SECTION 6 — Browser credential stores (plaintext or encrypted DB)
# =============================================================================
echo "===== BROWSER CREDENTIAL STORES ====="
for USERDIR in /home/*/; do
  UNAME=$(basename "$USERDIR")
  # Chrome / Chromium Login Data
  for LOGINDB in "$USERDIR/.config/google-chrome/"*/Login\ Data \
                 "$USERDIR/.config/chromium/"*/Login\ Data; do
    [ -f "$LOGINDB" ] || continue
    MOD=$(stat -c '%y' "$LOGINDB" 2>/dev/null || true)
    echo "  [i] Chrome Login Data: $LOGINDB (user: $UNAME, modified: $MOD)"
  done
  # Firefox logins.json
  for FFLOGINS in "$USERDIR/.mozilla/firefox/"*/logins.json; do
    [ -f "$FFLOGINS" ] || continue
    MOD=$(stat -c '%y' "$FFLOGINS" 2>/dev/null || true)
    COUNT=$(python3 -c "import json,sys; d=json.load(open('$FFLOGINS')); print(len(d.get('logins',[])))" 2>/dev/null || echo "?")
    echo "  [i] Firefox logins: $FFLOGINS (user: $UNAME, entries: $COUNT, modified: $MOD)"
  done
done || true
echo ""

# =============================================================================
# SECTION 7 — Credential-related files in temp/unusual locations
# =============================================================================
echo "===== CREDENTIAL FILES IN HIGH-RISK LOCATIONS ====="
CRED_FILE_PATTERNS="*.cred *.credentials *.credential *.vault password.txt passwords.txt creds.txt"
CRED_FOUND=0
for PATTERN in $CRED_FILE_PATTERNS; do
  find /tmp /var/tmp /dev/shm /home /root 2>/dev/null -name "$PATTERN" -type f 2>/dev/null | while read -r cf; do
    OWNER=$(stat -c '%U' "$cf" 2>/dev/null || true)
    MOD=$(stat -c '%y' "$cf" 2>/dev/null || true)
    echo "  [!] $cf (owner: $OWNER, modified: $MOD)"
    CRED_FOUND=$((CRED_FOUND+1))
  done
done
[ "$CRED_FOUND" -eq 0 ] && echo "  [+] No credential files found in high-risk paths"
echo ""

echo "===== END LINUX CREDENTIAL INDICATORS ====="
