#!/usr/bin/env bash
# =============================================================================
# Linux Kernel Modules — RTR / IR Script
# IR Phase   : Identification
# Platform   : Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
# Permission : Active Responder
# =============================================================================
# PURPOSE
#   Rootkits and kernel-level backdoors often load as kernel modules (LKM).
#   This script enumerates all loaded modules, checks for modules not present
#   in the package manager database (unsigned/unknown), flags modules loaded
#   from unusual paths, and checks for signs of module hiding techniques.
#
#   Note: A sophisticated rootkit may hide itself from lsmod output; this
#   script cross-references /proc/modules with /sys/module for discrepancies.
#
# USAGE
#   runscript -CloudFile="linux/persistence/kernel-modules.sh"
# =============================================================================

set -uo pipefail

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

echo "===== LINUX KERNEL MODULES ====="
echo "Host     : $HOSTNAME"
echo "Operator : $CURRENT_USER"
echo "Time     : $TIMESTAMP"
echo "Kernel   : $(uname -r)"
echo ""

# =============================================================================
# SECTION 1 — All loaded modules (lsmod)
# =============================================================================
echo "===== ALL LOADED MODULES ====="
if command -v lsmod &>/dev/null; then
  lsmod 2>/dev/null | head -100
else
  echo "  [!] lsmod not available, reading /proc/modules"
  awk '{print $1, $2, $3}' /proc/modules 2>/dev/null | head -100
fi
echo ""

# =============================================================================
# SECTION 2 — Total count and size statistics
# =============================================================================
TOTAL_MODS=$(lsmod 2>/dev/null | tail -n +2 | wc -l || awk 'END{print NR}' /proc/modules)
echo "===== MODULE STATISTICS ====="
echo "  Total loaded modules : $TOTAL_MODS"
echo "  Kernel version       : $(uname -r)"
echo "  Module directory     : /lib/modules/$(uname -r)"
echo ""

# =============================================================================
# SECTION 3 — Modules NOT in package manager (potential rogues)
# Legitimate modules ship with kernel packages or DKMS.
# An unknown module has no corresponding .ko file on disk.
# =============================================================================
echo "===== MODULES WITHOUT .ko FILE ON DISK (potential rogue modules) ====="
MOD_DIR="/lib/modules/$(uname -r)"
ROGUE=0
while IFS= read -r line; do
  modname=$(echo "$line" | awk '{print $1}' | tr '-' '_')
  [ "$modname" = "Module" ] && continue

  # Find .ko file (may be compressed as .ko.xz or .ko.gz)
  found=$(find "$MOD_DIR" -name "${modname}.ko" -o -name "${modname}.ko.xz" -o -name "${modname}.ko.gz" 2>/dev/null | head -1)

  if [ -z "$found" ]; then
    # Double-check with modname substitution (dashes vs underscores)
    modname2=$(echo "$modname" | tr '_' '-')
    found=$(find "$MOD_DIR" -name "${modname2}.ko" -o -name "${modname2}.ko.xz" 2>/dev/null | head -1)
  fi

  if [ -z "$found" ]; then
    echo "  [!!] Module '$modname' has NO .ko file in $MOD_DIR"
    # Check if it's a known in-tree built-in
    if grep -q "^$modname$" /lib/modules/$(uname -r)/modules.builtin 2>/dev/null; then
      echo "       (built-in to kernel — likely OK)"
    else
      ROGUE=$((ROGUE+1))
    fi
  fi
done < <(lsmod 2>/dev/null || awk '{print $1}' /proc/modules)

[ "$ROGUE" -eq 0 ] && echo "  [+] All loaded modules have corresponding .ko files"
echo ""

# =============================================================================
# SECTION 4 — Modules loaded from non-standard paths
# Standard: /lib/modules/<kernel-version>/
# Suspicious: /tmp, /dev/shm, /home, /var/tmp, or relative paths
# =============================================================================
echo "===== MODULES FROM UNUSUAL LOAD PATHS ====="
UNUSUAL=0
# /proc/modules column 6 is the live file path (not always populated)
while IFS= read -r line; do
  modname=$(echo "$line" | awk '{print $1}')
  modpath=$(echo "$line" | awk '{print $6}')  # may be empty
  [ -z "$modpath" ] || [ "$modpath" = "-" ] && continue
  if ! echo "$modpath" | grep -qE "^/lib/modules/|^/usr/lib/modules/"; then
    echo "  [!!] $modname loaded from: $modpath"
    UNUSUAL=$((UNUSUAL+1))
  fi
done < /proc/modules 2>/dev/null || true
[ "$UNUSUAL" -eq 0 ] && echo "  [+] All modules loaded from standard paths"
echo ""

# =============================================================================
# SECTION 5 — /sys/module vs /proc/modules discrepancy (rootkit hiding check)
# A rootkit hiding itself from lsmod may still appear in /sys/module or vice versa
# =============================================================================
echo "===== /proc/modules vs /sys/module CROSS-CHECK ====="
if [ -d /sys/module ]; then
  PROC_MODS=$(awk '{print $1}' /proc/modules 2>/dev/null | tr '-' '_' | sort)
  SYS_MODS=$(ls /sys/module/ 2>/dev/null | tr '-' '_' | sort)

  # Modules in /sys/module but not in /proc/modules
  HIDDEN=$(comm -23 <(echo "$SYS_MODS") <(echo "$PROC_MODS") 2>/dev/null | head -20)
  if [ -n "$HIDDEN" ]; then
    echo "  [!!] Modules in /sys/module but NOT in /proc/modules (possible hiding):"
    echo "$HIDDEN" | while read -r m; do echo "    $m"; done
  else
    echo "  [+] No discrepancy between /proc/modules and /sys/module"
  fi
else
  echo "  [i] /sys/module not accessible"
fi
echo ""

# =============================================================================
# SECTION 6 — Recently loaded modules (dmesg timestamp)
# =============================================================================
echo "===== RECENTLY LOADED MODULES (dmesg, last boot) ====="
if command -v dmesg &>/dev/null; then
  dmesg 2>/dev/null | grep -iE "module|insmod|modprobe|loading" | \
    grep -v "# " | tail -30 | while read -r line; do
    echo "  $line"
  done || echo "  [i] No module load messages in dmesg"
else
  echo "  [i] dmesg not available"
fi
echo ""

# =============================================================================
# SECTION 7 — DKMS modules (third-party kernel modules)
# DKMS compiles modules for each kernel — legitimate use includes VirtualBox,
# Nvidia drivers, etc. Unknown DKMS entries are worth investigating.
# =============================================================================
echo "===== DKMS MODULES (third-party compiled) ====="
if command -v dkms &>/dev/null; then
  dkms status 2>/dev/null | while read -r line; do
    echo "  $line"
  done || echo "  [i] No DKMS modules found"
else
  echo "  [i] dkms not installed"
  # Check DKMS tree directly
  if [ -d /var/lib/dkms ]; then
    ls /var/lib/dkms/ 2>/dev/null | while read -r d; do
      echo "  $d"
    done
  fi
fi
echo ""

# =============================================================================
# SECTION 8 — Module signing status
# On Secure Boot systems, unsigned modules should not load.
# =============================================================================
echo "===== MODULE SIGNING / SECURE BOOT ====="
if [ -f /proc/sys/kernel/modules_disabled ]; then
  MODDIS=$(cat /proc/sys/kernel/modules_disabled)
  echo "  kernel.modules_disabled : $MODDIS $([ "$MODDIS" = "1" ] && echo '(no new modules can load)')"
fi

if command -v mokutil &>/dev/null; then
  SB=$(mokutil --sb-state 2>/dev/null || echo "unavailable")
  echo "  Secure Boot state       : $SB"
fi

# Check if any loaded modules are unsigned
if [ -f /proc/sys/kernel/unsupported_modules ] 2>/dev/null; then
  echo "  Unsupported modules     : $(cat /proc/sys/kernel/unsupported_modules)"
fi

# Check dmesg for signature warnings
dmesg 2>/dev/null | grep -iE "module.*signature|unsigned module|required key" | \
  tail -10 | while read -r line; do
  echo "  [!] $line"
done || true
echo ""

# =============================================================================
# SECTION 9 — Notable high-risk modules (known rootkit module names)
# =============================================================================
echo "===== KNOWN ROOTKIT MODULE NAME CHECK ====="
ROOTKIT_NAMES="reptile|diamorphine|drovorub|adore|knark|rkit|azazel|necurs|suterusu|average|rooty"
FOUND_RK=0
while IFS= read -r line; do
  modname=$(echo "$line" | awk '{print $1}')
  if echo "$modname" | grep -iqE "$ROOTKIT_NAMES"; then
    echo "  [!!!] KNOWN ROOTKIT MODULE NAME: $modname"
    FOUND_RK=$((FOUND_RK+1))
  fi
done < <(lsmod 2>/dev/null || awk '{print $1}' /proc/modules) || true
[ "$FOUND_RK" -eq 0 ] && echo "  [+] No modules matching known rootkit names"
echo ""

echo "===== END LINUX KERNEL MODULES ====="
