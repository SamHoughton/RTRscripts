#!/usr/bin/env bash
# =============================================================================
# Linux Container Indicators — RTR / IR Script
# IR Phase   : Identification
# Platform   : Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
# Permission : Active Responder
# =============================================================================
# PURPOSE
#   Detect container presence, container escape indicators, exposed Docker sockets,
#   privileged containers, abnormal mounts, and unusual capabilities. Useful both
#   when responding on a container host (find rogue containers) and when the
#   compromised host itself may be inside a container (determine escape risk).
#
# USAGE
#   runscript -CloudFile="linux/triage/container-indicators.sh"
# =============================================================================

set -uo pipefail

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

echo "===== LINUX CONTAINER INDICATORS ====="
echo "Host     : $HOSTNAME"
echo "Operator : $CURRENT_USER"
echo "Time     : $TIMESTAMP"
echo ""

# =============================================================================
# SECTION 1 — Am I running inside a container?
# =============================================================================
echo "===== CONTAINER SELF-DETECTION ====="
IN_CONTAINER=false

# .dockerenv file
if [ -f /.dockerenv ]; then
  echo "  [!!] /.dockerenv present — this host IS a container"
  IN_CONTAINER=true
fi

# /run/.containerenv (Podman/OCI)
if [ -f /run/.containerenv ]; then
  echo "  [!!] /run/.containerenv present — Podman/OCI container"
  IN_CONTAINER=true
  cat /run/.containerenv 2>/dev/null | head -10 | sed 's/^/    /'
fi

# cgroup check
if grep -q docker /proc/1/cgroup 2>/dev/null; then
  echo "  [!!] /proc/1/cgroup contains 'docker'"
  IN_CONTAINER=true
fi
if grep -q kubepods /proc/1/cgroup 2>/dev/null; then
  echo "  [!!] /proc/1/cgroup contains 'kubepods' — Kubernetes pod"
  IN_CONTAINER=true
fi
if grep -q 'lxc\|containerd' /proc/1/environ 2>/dev/null; then
  echo "  [!!] LXC/containerd environment detected"
  IN_CONTAINER=true
fi

# PID 1 binary
PID1_EXE=$(readlink /proc/1/exe 2>/dev/null || true)
if echo "$PID1_EXE" | grep -qE "pause|tini|dumb-init|s6-svscan"; then
  echo "  [!!] PID 1 is '$PID1_EXE' — typical container init process"
  IN_CONTAINER=true
fi

if [ "$IN_CONTAINER" = "false" ]; then
  echo "  [+] This host does NOT appear to be running inside a container"
fi
echo ""

# =============================================================================
# SECTION 2 — Docker daemon status and version
# =============================================================================
echo "===== DOCKER DAEMON ====="
if command -v docker &>/dev/null; then
  echo "  Docker CLI: $(docker --version 2>/dev/null)"
  if systemctl is-active docker &>/dev/null 2>&1; then
    echo "  Docker daemon: RUNNING"
    docker info 2>/dev/null | grep -E "Server Version|Containers:|Running:|Paused:|Stopped:|Images:|Storage Driver:|Security Options:" | \
      sed 's/^/  /'
  else
    echo "  Docker daemon: NOT RUNNING (or not systemd-managed)"
  fi
else
  echo "  [i] Docker CLI not found"
fi
echo ""

# =============================================================================
# SECTION 3 — Exposed Docker socket (critical privilege escalation vector)
# An exposed /var/run/docker.sock inside a container = full host compromise
# =============================================================================
echo "===== DOCKER SOCKET EXPOSURE ====="
for SOCK in /var/run/docker.sock /run/docker.sock /tmp/docker.sock; do
  if [ -S "$SOCK" ]; then
    PERMS=$(stat -c '%A %U:%G' "$SOCK" 2>/dev/null || stat -f '%Sp %Su:%Sg' "$SOCK" 2>/dev/null)
    echo "  [!!] Docker socket found: $SOCK  ($PERMS)"
    echo "       This allows full container escape if writable"
    # Check if current user can access it
    if [ -r "$SOCK" ] || [ -w "$SOCK" ]; then
      echo "       [!!!] Current user ($CURRENT_USER) CAN ACCESS this socket"
    fi
  fi
done
# Also look for socket bind-mounts
if grep -q 'docker.sock' /proc/mounts 2>/dev/null; then
  echo "  [!!] docker.sock appears in /proc/mounts (bind-mounted into container)"
  grep 'docker.sock' /proc/mounts | sed 's/^/    /'
fi
[ ! -S /var/run/docker.sock ] && [ ! -S /run/docker.sock ] && echo "  [+] No Docker socket found at standard paths"
echo ""

# =============================================================================
# SECTION 4 — Running containers
# =============================================================================
echo "===== RUNNING CONTAINERS ====="
if command -v docker &>/dev/null && systemctl is-active docker &>/dev/null 2>&1; then
  RUNNING=$(docker ps --no-trunc --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}\t{{.Ports}}' 2>/dev/null || true)
  if [ -n "$RUNNING" ]; then
    echo "$RUNNING" | sed 's/^/  /'
  else
    echo "  [i] No running containers"
  fi
  echo ""
  echo "  All containers (including stopped):"
  docker ps -a --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}' 2>/dev/null | sed 's/^/  /' || true
elif command -v crictl &>/dev/null; then
  echo "  (using crictl — likely Kubernetes node)"
  crictl ps 2>/dev/null | sed 's/^/  /' || true
elif command -v podman &>/dev/null; then
  echo "  (using podman)"
  podman ps -a 2>/dev/null | sed 's/^/  /' || true
else
  echo "  [i] No container runtime CLI found (docker/crictl/podman)"
fi
echo ""

# =============================================================================
# SECTION 5 — Privileged containers (escape risk)
# =============================================================================
echo "===== PRIVILEGED CONTAINERS ====="
if command -v docker &>/dev/null && systemctl is-active docker &>/dev/null 2>&1; then
  PRIV_FOUND=0
  docker ps -q 2>/dev/null | while read -r cid; do
    PRIV=$(docker inspect "$cid" --format '{{.HostConfig.Privileged}}' 2>/dev/null || true)
    NAME=$(docker inspect "$cid" --format '{{.Name}}' 2>/dev/null | tr -d '/')
    IMAGE=$(docker inspect "$cid" --format '{{.Config.Image}}' 2>/dev/null || true)
    if [ "$PRIV" = "true" ]; then
      echo "  [!!] PRIVILEGED: $cid  name=$NAME  image=$IMAGE"
      PRIV_FOUND=$((PRIV_FOUND+1))
    fi
    # Check for dangerous capabilities even if not fully privileged
    CAPS=$(docker inspect "$cid" --format '{{.HostConfig.CapAdd}}' 2>/dev/null || true)
    if echo "$CAPS" | grep -qiE "SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|DAC_READ_SEARCH"; then
      echo "  [!] DANGEROUS CAPS: $cid  name=$NAME  caps=$CAPS"
    fi
  done || true
  [ "$PRIV_FOUND" -eq 0 ] && echo "  [+] No privileged containers found" || true
else
  echo "  [i] Docker not running"
fi
echo ""

# =============================================================================
# SECTION 6 — Suspicious mounts (escape indicators)
# Mounting host / or /proc or /sys inside a container enables escape
# =============================================================================
echo "===== SUSPICIOUS MOUNTS ====="
SUSP_MOUNT=0
while IFS= read -r line; do
  src=$(echo "$line" | awk '{print $1}')
  dst=$(echo "$line" | awk '{print $2}')
  # Flag mounts of root filesystem, proc, sys, dev, cgroups
  if echo "$dst" | grep -qE "^/host|^/mnt/host"; then
    echo "  [!!] Host filesystem mount: $line"; SUSP_MOUNT=$((SUSP_MOUNT+1))
  fi
  # Writable /proc or /sys
  if echo "$dst $src" | grep -qE "/proc/sys|/proc/sysrq"; then
    echo "  [!] Sensitive proc mount: $line"; SUSP_MOUNT=$((SUSP_MOUNT+1))
  fi
done < /proc/mounts 2>/dev/null || true
[ "$SUSP_MOUNT" -eq 0 ] && echo "  [+] No obviously suspicious mounts"
echo ""

# =============================================================================
# SECTION 7 — Current process capabilities
# CAP_SYS_ADMIN essentially grants root; combinations can enable escape
# =============================================================================
echo "===== CURRENT PROCESS CAPABILITIES ====="
if [ -f /proc/self/status ]; then
  grep -E "^Cap(Inh|Prm|Eff|Bnd|Amb):" /proc/self/status 2>/dev/null | while read -r line; do
    label=$(echo "$line" | cut -d: -f1)
    hex=$(echo "$line" | cut -d: -f2 | tr -d ' ')
    # Non-zero effective capabilities = elevated
    if [ "$hex" != "0000000000000000" ] && [ -n "$hex" ]; then
      echo "  [!] $label: 0x$hex (non-zero)"
      if command -v capsh &>/dev/null; then
        capsh --decode="$hex" 2>/dev/null | sed 's/^/      /'
      fi
    else
      echo "  $label: 0x$hex"
    fi
  done
fi
echo ""

# =============================================================================
# SECTION 8 — Kubernetes indicators
# =============================================================================
echo "===== KUBERNETES INDICATORS ====="
K8S_FOUND=false
# Service account token (all K8s pods have this by default)
SA_TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"
if [ -f "$SA_TOKEN" ]; then
  echo "  [!!] Kubernetes service account token found: $SA_TOKEN"
  echo "       Namespace: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || 'unknown')"
  K8S_FOUND=true
fi
# KUBERNETES_SERVICE_HOST env var
if env 2>/dev/null | grep -q KUBERNETES_SERVICE_HOST; then
  echo "  [!!] KUBERNETES_SERVICE_HOST set — running in a K8s pod"
  env | grep -E "^KUBERNETES_|^K8S_" | sed 's/^/    /'
  K8S_FOUND=true
fi
# kubectl
if command -v kubectl &>/dev/null; then
  echo "  kubectl present: $(kubectl version --client 2>/dev/null | head -1)"
  echo "  Can we access API server?"
  kubectl get pods --all-namespaces 2>&1 | head -5 | sed 's/^/  /'
fi
[ "$K8S_FOUND" = "false" ] && echo "  [+] No Kubernetes indicators detected"
echo ""

echo "===== END LINUX CONTAINER INDICATORS ====="
