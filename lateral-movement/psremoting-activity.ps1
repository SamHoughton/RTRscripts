<#
.SYNOPSIS
    PSRemoting Activity - Audit WinRM, active remote sessions, and remoting events.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== POWERSHELL REMOTING AUDIT ====="
Write-Output "Host: $($env:COMPUTERNAME)  |  Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# -- WinRM Service State ------------------------------------------------------
Write-Output ""
Write-Output "===== WINRM SERVICE ====="
$winrm = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
if ($winrm) {
    Write-Output "  Status   : $($winrm.Status)"
    Write-Output "  StartType: $($winrm.StartType)"
    if ($winrm.Status -eq "Running") {
        Write-Output "  [!] WinRM is running - PS Remoting is available inbound"
    }
} else {
    Write-Output "  WinRM service not found."
}

# -- WinRM Listener Config ----------------------------------------------------
Write-Output ""
Write-Output "===== WINRM LISTENERS ====="
try {
    $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop
    $listeners | ForEach-Object {
        $name = $_.Name
        Write-Output "  Listener: $name"
        Get-ChildItem $_.PSPath | ForEach-Object {
            Write-Output "    $($_.Name) = $($_.Value)"
        }
    }
} catch {
    Write-Output "  [!] Could not enumerate WinRM listeners: $_"
}

# -- Active PS Sessions -------------------------------------------------------
Write-Output ""
Write-Output "===== ACTIVE POWERSHELL REMOTE SESSIONS (outbound from this host) ====="
try {
    $sessions = Get-PSSession -ErrorAction Stop
    if ($sessions) {
        $sessions | Select-Object Id, Name, ComputerName, State, ConfigurationName | Format-Table -AutoSize
    } else {
        Write-Output "  No active outbound PS remote sessions."
    }
} catch { Write-Output "  [!] Get-PSSession failed: $_" }

# -- PS Script Block Events (4104) -------------------------------------------
Write-Output ""
Write-Output "===== POWERSHELL SCRIPT BLOCK EVENTS (4104, last 10, 24h) ====="
try {
    $sbEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4104
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 10 -ErrorAction Stop
    $sbEvents | ForEach-Object {
        $preview = $_.Message -replace '\s+', ' '
        if ($preview.Length -gt 200) { $preview = $preview.Substring(0,200) + "..." }
        Write-Output "  $($_.TimeCreated)  $preview"
    }
} catch { Write-Output "  [!] No PS 4104 events (Script Block logging may be disabled)" }

# -- WinRM Operational Events ------------------------------------------------
Write-Output ""
Write-Output "===== WS-MANAGEMENT OPERATIONAL (connection events, last 10) ====="
try {
    $wsmEvents = Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -MaxEvents 50 -ErrorAction Stop |
        Where-Object { $_.Id -in @(6, 8, 11, 12, 91, 169) } |
        Select-Object -First 10
    $wsmEvents | ForEach-Object {
        $msg = ($_.Message -split "`n")[0]
        Write-Output "  $($_.TimeCreated)  ID=$($_.Id)  $msg"
    }
} catch { Write-Output "  [!] WinRM Operational log unavailable: $_" }

Write-Output "===== END PSREMOTING ACTIVITY ====="
