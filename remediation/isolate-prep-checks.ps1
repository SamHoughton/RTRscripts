<#
.SYNOPSIS
    Isolate Prep Checks - Validate a host is safe to network-isolate before pulling the cord.

.DESCRIPTION
    Network isolation is a powerful containment action but can cause collateral damage
    if you isolate a host that:
      • Is a critical server (DC, SQL, file server) currently being used
      • Has an active remote desktop session from a legitimate admin
      • Is running services that other hosts depend on
      • Has pending data that hasn't been committed (DB writes, etc.)

    This script runs a pre-isolation checklist and gives a GO / CAUTION / NO-GO
    recommendation so the analyst can make an informed decision.

    Note: Isolation itself is done in the Falcon console (Host Management → Isolate),
    NOT via RTR script. This script only does the pre-flight checks.

.IR_PHASE
    Containment

.RTR_PERMISSION
    Active Responder

.EXAMPLE
    runscript -CloudFile="remediation/isolate-prep-checks.ps1"
#>

$warnings = [System.Collections.Generic.List[string]]::new()
$blockers = [System.Collections.Generic.List[string]]::new()

Write-Output "===== ISOLATION PRE-FLIGHT CHECKS ====="
Write-Output "Host: $($env:COMPUTERNAME)"
Write-Output "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""

# ── CHECK 1: Is this a Domain Controller? ─────────────────────────────────────
# Isolating a DC will break authentication for every machine in the domain
Write-Output "[CHECK 1] Domain Controller role..."
try {
    $domainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
    # DomainRole: 0=Standalone, 1=Member, 4=Backup DC, 5=Primary DC
    if ($domainRole -ge 4) {
        $blockers.Add("HOST IS A DOMAIN CONTROLLER (DomainRole=$domainRole). Isolation will break domain auth for all joined machines.")
        Write-Output "  [BLOCKER] This is a Domain Controller."
    } else {
        Write-Output "  [OK] Not a DC (DomainRole=$domainRole)"
    }
} catch {
    $warnings.Add("Could not determine DomainRole: $_")
    Write-Output "  [WARN] Could not check DC status."
}

# ── CHECK 2: Active RDP / Console Sessions ────────────────────────────────────
# Isolating mid-session cuts off legitimate admins and analysts
Write-Output ""
Write-Output "[CHECK 2] Active user sessions..."
try {
    $sessions = query session 2>&1
    $activeSessions = $sessions | Select-String "Active|Actif" | Where-Object { $_ -notmatch "Services|console.*0" }
    if ($activeSessions) {
        $warnings.Add("Active user sessions detected. Isolation will cut them off.")
        Write-Output "  [WARN] Active sessions found:"
        $activeSessions | ForEach-Object { Write-Output "         $_" }
    } else {
        Write-Output "  [OK] No active interactive sessions."
    }
} catch {
    Write-Output "  [WARN] Could not enumerate sessions: $_"
}

# ── CHECK 3: Critical Windows Roles ──────────────────────────────────────────
# File servers, DNS, DHCP servers etc. — isolation = service outage
Write-Output ""
Write-Output "[CHECK 3] Installed Windows Server roles..."
try {
    $roles = Get-WindowsFeature -ErrorAction Stop | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq 'Role' }
    $criticalRoles = $roles | Where-Object {
        $_.Name -in @("AD-Domain-Services","DNS","DHCP","FS-FileServer","Web-Server","WAS","MSMQ","NPAS","RemoteAccess")
    }
    if ($criticalRoles) {
        foreach ($role in $criticalRoles) {
            $warnings.Add("Critical role installed: $($role.DisplayName)")
        }
        Write-Output "  [WARN] Critical server roles detected:"
        $criticalRoles | Select-Object DisplayName, Name | Format-Table -AutoSize
    } else {
        Write-Output "  [OK] No critical server roles detected."
    }
} catch {
    # Get-WindowsFeature only available on Server SKUs; skip on workstations
    Write-Output "  [OK] Get-WindowsFeature N/A (workstation OS or module not installed)."
}

# ── CHECK 4: CrowdStrike Sensor Status ────────────────────────────────────────
# If the sensor is unhealthy, isolation may not work as expected
Write-Output ""
Write-Output "[CHECK 4] CrowdStrike sensor health..."
try {
    $csService = Get-Service -Name "CSFalconService" -ErrorAction Stop
    if ($csService.Status -eq "Running") {
        Write-Output "  [OK] CSFalconService is Running."
    } else {
        $blockers.Add("CSFalconService is NOT running (Status: $($csService.Status)). Isolation commands may not reach the host.")
        Write-Output "  [BLOCKER] CSFalconService status: $($csService.Status)"
    }
} catch {
    $blockers.Add("Could not find CSFalconService. Sensor may not be installed.")
    Write-Output "  [BLOCKER] CSFalconService not found."
}

# ── CHECK 5: Disk Activity / Open Transactions ────────────────────────────────
# Check for DB services that may have uncommitted transactions
Write-Output ""
Write-Output "[CHECK 5] Database services with potential open transactions..."
$dbServices = @("MSSQLSERVER","MSSQL`$*","MySQL","OracleService*","postgresql*","mongod")
$runningDb = foreach ($svcName in $dbServices) {
    Get-Service -Name $svcName -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
}
if ($runningDb) {
    foreach ($svc in $runningDb) {
        $warnings.Add("Database service running: $($svc.DisplayName). Isolation may corrupt open transactions.")
    }
    Write-Output "  [WARN] Database services running:"
    $runningDb | Select-Object DisplayName, Status | Format-Table -AutoSize
} else {
    Write-Output "  [OK] No database services detected."
}

# ── CHECK 6: Current RTR Connection ──────────────────────────────────────────
# Isolation kills the RTR session — ensure you've collected what you need
Write-Output ""
Write-Output "[CHECK 6] RTR session reminder..."
Write-Output "  [INFO] Isolation will TERMINATE this RTR session immediately."
Write-Output "  [INFO] Ensure you have collected all required evidence BEFORE isolating."
Write-Output "  [INFO] Post-isolation RTR access requires the CrowdStrike backend tunnel."

# ── SUMMARY ───────────────────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== ISOLATION RECOMMENDATION ====="

if ($blockers.Count -gt 0) {
    Write-Output "[NO-GO] DO NOT ISOLATE — blockers found:"
    $blockers | ForEach-Object { Write-Output "  !! $_" }
} elseif ($warnings.Count -gt 0) {
    Write-Output "[CAUTION] REVIEW WARNINGS before isolating:"
    $warnings | ForEach-Object { Write-Output "  >> $_" }
    Write-Output ""
    Write-Output "If the risk is accepted, proceed with isolation via Falcon console."
} else {
    Write-Output "[GO] No blockers or warnings. Host appears safe to isolate."
    Write-Output "Proceed via: Falcon Console → Hosts → [host] → Isolate Host"
}

Write-Output ""
Write-Output "===== END ISOLATE PREP CHECKS ====="
