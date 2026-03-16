<#
.SYNOPSIS
    Host Summary - Rapid triage snapshot of a target host.

.DESCRIPTION
    Collects key host identity and health indicators in a single pass.
    Designed as the first script to run during the Identification phase of IR —
    gives you enough context to decide whether deeper investigation is warranted.

.IR_PHASE
    Identification

.RTR_PERMISSION
    Active Responder (read-only cmdlets only)

.NOTES
    Safe to run on any Windows host. No artefacts written to disk.
    Execution time: ~5 seconds.

.EXAMPLE
    Run in RTR session:
        runscript -CloudFile="triage/host-summary.ps1"
#>

# ── System Identity ───────────────────────────────────────────────────────────
# Pulling from CIM rather than WMI for speed and modern compatibility
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS

Write-Output "===== HOST SUMMARY ====="
Write-Output "Hostname       : $($env:COMPUTERNAME)"
Write-Output "Domain         : $($cs.Domain)"
Write-Output "OS             : $($os.Caption) [$($os.Version)]"
Write-Output "Architecture   : $($os.OSArchitecture)"
Write-Output "Serial / UUID  : $($bios.SerialNumber)"
Write-Output "Last Boot      : $($os.LastBootUpTime)"
Write-Output "Current Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC$(([System.TimeZone]::CurrentTimeZone).GetUtcOffset((Get-Date)))"
Write-Output ""

# ── Uptime ────────────────────────────────────────────────────────────────────
# Long uptime can indicate a host that hasn't received patches in a while
$uptime = (Get-Date) - $os.LastBootUpTime
Write-Output "Uptime         : $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
Write-Output ""

# ── Local Admins ──────────────────────────────────────────────────────────────
# Unexpected members here are a classic persistence / privilege escalation indicator
Write-Output "===== LOCAL ADMINISTRATORS ====="
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $admins | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize
} catch {
    Write-Output "  [!] Could not enumerate local admins: $_"
}

# ── Installed AV / EDR Products ───────────────────────────────────────────────
# Confirms sensor health and flags any unexpected security tools
Write-Output "===== SECURITY PRODUCTS (SecurityCenter2) ====="
try {
    $av = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
    if ($av) {
        $av | Select-Object displayName, productState | Format-Table -AutoSize
    } else {
        Write-Output "  [!] No AV products found in SecurityCenter2"
    }
} catch {
    Write-Output "  [!] SecurityCenter2 query failed (may be a server OS): $_"
}

# ── Patch Level ───────────────────────────────────────────────────────────────
# Stale patch level narrows the exploit window to investigate
Write-Output "===== LAST 5 INSTALLED UPDATES ====="
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 |
    Select-Object HotFixID, InstalledOn, Description | Format-Table -AutoSize

Write-Output "===== END HOST SUMMARY ====="
