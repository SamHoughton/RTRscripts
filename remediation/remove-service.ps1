#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stop and delete a malicious Windows service.

.DESCRIPTION
    Finds a service by its service name (not display name), logs the full
    service configuration (binary path, account, start type), stops it,
    and removes it from the registry. Optionally deletes the binary.
    Use 'suspicious-services.ps1' first to identify the exact service name.

.IR_PHASE
    Eradication

.RTR_PERMISSION
    RTR Admin

.PARAMETER ServiceName
    The service name (sc name) — NOT the display name. These differ.
    Find it with: Get-Service | Where DisplayName -like '*name*'

.PARAMETER DeleteBinary
    If $true, also deletes the service binary from disk after removal.
    WARNING: Irreversible. Ensure forensic capture is complete first.

.EXAMPLE
    runscript -CloudFile="remediation/remove-service.ps1" `
      -CommandLine="-ServiceName 'evilsvc'"
    runscript -CloudFile="remediation/remove-service.ps1" `
      -CommandLine="-ServiceName 'evilsvc' -DeleteBinary `$true"
#>
param(
    [Parameter(Mandatory=$true)][string]$ServiceName = "",
    [bool]$DeleteBinary = $false
)

Write-Output "===== REMOVE SERVICE ====="
Write-Output "Host     : $env:COMPUTERNAME"
Write-Output "Operator : $env:USERDOMAIN\$env:USERNAME"
Write-Output "Time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""

if (-not $ServiceName) {
    Write-Output "[ERROR] -ServiceName is required"
    exit 1
}

# ── Find the service ───────────────────────────────────────────────────────
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Output "[ERROR] Service not found: '$ServiceName'"
    Write-Output "  Hint: service name (sc name) is case-insensitive but exact."
    Write-Output "  Use: Get-Service | Where-Object { `$_.DisplayName -like '*partial*' }"
    exit 1
}

# Get full config from registry
$regPath  = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$regEntry = Get-ItemProperty $regPath -ErrorAction SilentlyContinue

Write-Output "===== SERVICE DETAILS (pre-deletion record) ====="
Write-Output "  Service Name  : $($svc.ServiceName)"
Write-Output "  Display Name  : $($svc.DisplayName)"
Write-Output "  Status        : $($svc.Status)"
Write-Output "  Start Type    : $($svc.StartType)"
if ($regEntry) {
    Write-Output "  Binary Path   : $($regEntry.ImagePath)"
    Write-Output "  ObjectName    : $($regEntry.ObjectName)"
    Write-Output "  Description   : $($regEntry.Description)"
    Write-Output "  Type          : $($regEntry.Type)"
}
Write-Output ""

$binPath = ""
if ($regEntry -and $regEntry.ImagePath) {
    # Strip service arguments to get just the executable path
    $raw = $regEntry.ImagePath -replace '"',''
    $binPath = ($raw -split ' ')[0]
}

# ── Stop the service ───────────────────────────────────────────────────────
Write-Output "===== STOPPING SERVICE ====="
if ($svc.Status -eq 'Running') {
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        Write-Output "  [+] Service stopped: $ServiceName"
    } catch {
        Write-Output "  [!] Could not stop service gracefully: $($_.Exception.Message)"
        Write-Output "  Attempting sc.exe stop..."
        & sc.exe stop $ServiceName 2>&1
    }
    Start-Sleep -Seconds 2
} else {
    Write-Output "  [i] Service was already stopped ($($svc.Status))"
}

# ── Delete the service ─────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== DELETING SERVICE REGISTRATION ====="
try {
    & sc.exe delete $ServiceName 2>&1 | ForEach-Object { Write-Output "  $_" }
    Write-Output "  [+] sc.exe delete completed for: $ServiceName"
} catch {
    Write-Output "  [!] sc.exe delete failed: $($_.Exception.Message)"
}

# Verify removal
Start-Sleep -Milliseconds 500
$verify = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($verify) {
    Write-Output "  [!] WARNING: Service still registered — may need reboot to fully remove"
} else {
    Write-Output "  [+] Confirmed: service no longer registered"
}

# ── Optional: delete binary ────────────────────────────────────────────────
if ($DeleteBinary -and $binPath) {
    Write-Output ""
    Write-Output "===== DELETING BINARY ====="
    Write-Output "  Path: $binPath"
    if (Test-Path $binPath) {
        try {
            Remove-Item -Path $binPath -Force -ErrorAction Stop
            Write-Output "  [+] Deleted: $binPath"
        } catch {
            Write-Output "  [!] Could not delete '$binPath': $($_.Exception.Message)"
            Write-Output "      Manual step: del /f /q `"$binPath`""
        }
    } else {
        Write-Output "  [?] Binary not found at path — may have already been removed"
    }
} elseif ($binPath) {
    Write-Output ""
    Write-Output "  Binary path (not deleted — use -DeleteBinary `$true to remove):"
    Write-Output "    $binPath"
}

Write-Output ""
Write-Output "===== END REMOVE SERVICE ====="
