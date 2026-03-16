#!/usr/bin/env bash
# =============================================================================
# macOS Unsigned / Suspicious Binaries — RTR / IR Script
# IR Phase   : Identification
# Platform   : macOS 12+
# Permission : Active Responder
# =============================================================================
# PURPOSE
#   Identify running processes whose binaries are unsigned, ad-hoc signed only,
#   or lack a valid Apple / developer signature. On macOS, Gatekeeper requires
#   signatures for downloaded applications — unsigned binaries running from
#   non-system paths are a strong indicator of living-off-the-land or
#   custom malware execution.
#
#   Uses `codesign -dv` and `spctl --assess` to evaluate each unique binary.
#
# USAGE
#   runscript -CloudFile="macos/process-investigation/unsigned-binaries.sh"
# =============================================================================

set -uo pipefail

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

echo "===== macOS UNSIGNED / SUSPICIOUS BINARIES ====="
echo "Host     : $HOSTNAME"
echo "Operator : $CURRENT_USER"
echo "Time     : $TIMESTAMP"
echo ""

# =============================================================================
# SECTION 1 — Collect unique binary paths from running processes
# =============================================================================
echo "===== RUNNING PROCESS BINARIES ====="

declare -A CHECKED
TOTAL=0; UNSIGNED=0; ADHOC=0; SUSPICIOUS_PATH=0

while IFS= read -r line; do
  pid=$(echo  "$line" | awk '{print $1}')
  usr=$(echo  "$line" | awk '{print $2}')
  bin=$(echo  "$line" | awk '{print $3}')

  # Skip empty, kernel placeholders, and already-checked binaries
  [ -z "$bin" ] && continue
  echo "$bin" | grep -qE '^(\?|kernel_task|-|smd)' && continue
  [ "${CHECKED[$bin]+_}" ] && continue
  CHECKED["$bin"]=1

  TOTAL=$((TOTAL+1))

  # Resolve symlinks
  REAL_BIN=$(realpath "$bin" 2>/dev/null || echo "$bin")

  # --- Signature check ---
  SIG_OUT=$(codesign -dv "$REAL_BIN" 2>&1 || true)
  AUTHORITY=$(echo "$SIG_OUT" | grep -i 'Authority=' | head -1 || true)
  ADHOC_FLAG=$(echo "$SIG_OUT" | grep -i 'adhoc' || true)
  CODE_DIR=$(echo "$SIG_OUT" | grep 'CodeDirectory' || true)

  IS_UNSIGNED=false
  IS_ADHOC=false

  if echo "$SIG_OUT" | grep -q 'code object is not signed'; then
    IS_UNSIGNED=true
    UNSIGNED=$((UNSIGNED+1))
  elif [ -n "$ADHOC_FLAG" ] || ([ -z "$AUTHORITY" ] && [ -n "$CODE_DIR" ]); then
    IS_ADHOC=true
    ADHOC=$((ADHOC+1))
  fi

  # --- Path risk scoring ---
  PATH_RISK=""
  echo "$REAL_BIN" | grep -qE '/tmp/|/var/folders/|/private/tmp/|/Users/.*/Downloads/|/Users/.*/Desktop/|/Users/Shared/' && \
    PATH_RISK=" [HIGH-RISK PATH]" && SUSPICIOUS_PATH=$((SUSPICIOUS_PATH+1))

  # Only report unsigned, adhoc, or high-risk-path binaries
  if $IS_UNSIGNED || $IS_ADHOC || [ -n "$PATH_RISK" ]; then
    if $IS_UNSIGNED; then
      STATUS="[UNSIGNED]"
    elif $IS_ADHOC; then
      STATUS="[AD-HOC]"
    else
      STATUS="[SIGNED]"
    fi

    echo "  $STATUS$PATH_RISK"
    echo "    PID    : $pid"
    echo "    User   : $usr"
    echo "    Binary : $REAL_BIN"
    [ -n "$AUTHORITY" ] && echo "    Signer : $AUTHORITY"

    # Gatekeeper assessment (only for non-system paths)
    if ! echo "$REAL_BIN" | grep -qE '^/System/|^/usr/bin/|^/usr/sbin/|^/bin/|^/sbin/'; then
      SPCTL=$(spctl --assess --verbose=4 "$REAL_BIN" 2>&1 || true)
      SPCTL_RESULT=$(echo "$SPCTL" | head -1)
      echo "    GK     : $SPCTL_RESULT"
    fi

    # File metadata
    if [ -f "$REAL_BIN" ]; then
      FILE_INFO=$(file "$REAL_BIN" 2>/dev/null || true)
      CREATED=$(GetFileInfo -d "$REAL_BIN" 2>/dev/null || stat -f '%SB' "$REAL_BIN" 2>/dev/null || true)
      echo "    Type   : $FILE_INFO"
      [ -n "$CREATED" ] && echo "    Created: $CREATED"
    fi
    echo ""
  fi

done < <(ps -axo pid=,user=,comm= 2>/dev/null) || true

# =============================================================================
# SECTION 2 — Summary
# =============================================================================
echo "===== SUMMARY ====="
echo "  Unique binaries checked : $TOTAL"
echo "  Unsigned                : $UNSIGNED"
echo "  Ad-hoc signed only      : $ADHOC"
echo "  High-risk path          : $SUSPICIOUS_PATH"
echo ""

# =============================================================================
# SECTION 3 — Dylib injection check (DYLD_INSERT_LIBRARIES)
# Malware can inject dylibs into legitimate processes
# =============================================================================
echo "===== DYLD INJECTION (DYLD_INSERT_LIBRARIES in env) ====="
INJECT_FOUND=0
while IFS= read -r line; do
  pid=$(echo "$line" | awk '{print $1}')
  if [ -f "/proc/$pid/environ" ] 2>/dev/null; then
    # Linux fallback — not applicable on macOS but harmless
    true
  else
    # macOS: use ps to check environment (limited without elevated perms)
    ENV_CHECK=$(ps -p "$pid" -Eww -o args= 2>/dev/null || true)
    if echo "$ENV_CHECK" | grep -q 'DYLD_INSERT_LIBRARIES'; then
      echo "  [!] DYLD_INSERT_LIBRARIES found for PID $pid: $ENV_CHECK"
      INJECT_FOUND=$((INJECT_FOUND+1))
    fi
  fi
done < <(ps -axo pid= 2>/dev/null | tail -n +2) || true

[ "$INJECT_FOUND" -eq 0 ] && echo "  [+] No DYLD_INSERT_LIBRARIES injection detected in process args"
echo ""

# =============================================================================
# SECTION 4 — Hidden / dot-prefixed executables running
# =============================================================================
echo "===== HIDDEN EXECUTABLE NAMES ====="
HIDDEN_FOUND=0
while IFS= read -r line; do
  pid=$(echo "$line" | awk '{print $1}')
  cmd=$(echo "$line" | awk '{print $2}')
  base=$(basename "$cmd" 2>/dev/null || echo "$cmd")
  if echo "$base" | grep -q '^\.' ; then
    echo "  [!] PID $pid: $cmd"
    HIDDEN_FOUND=$((HIDDEN_FOUND+1))
  fi
done < <(ps -axo pid=,comm= 2>/dev/null) || true
[ "$HIDDEN_FOUND" -eq 0 ] && echo "  [+] No dot-prefixed (hidden) executables running"
echo ""

echo "===== END macOS UNSIGNED / SUSPICIOUS BINARIES ====="
