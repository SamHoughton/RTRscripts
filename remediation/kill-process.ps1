#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Kill a running process by name or PID. Optionally delete the binary.

.DESCRIPTION
    Locates processes by name or PID, logs full details (path, owner, parent,
    start time) before taking action, then terminates them. If -DeleteBinary
    is $true, removes the executable from disk after killing.
    CONFIRM the correct target before running. Take a forensic copy first.

.IR_PHASE
    Eradication

.RTR_PERMISSION
    RTR Admin

.EXAMPLE
    runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-ProcessName 'malware.exe'"
    runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-ProcessId 4812 -DeleteBinary `$true"
#>
param(
    [string]$ProcessName  = "",
    [int]   $ProcessId    = 0,
    [bool]  $DeleteBinary = $false
)

Write-Output "===== KILL PROCESS ====="
Write-Output "Host     : $env:COMPUTERNAME"
Write-Output "Operator : $env:USERDOMAIN\$env:USERNAME"
Write-Output "Time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""

if (-not $ProcessName -and $ProcessId -eq 0) {
    Write-Output "[ERROR] Supply -ProcessName <name> or -ProcessId <pid>"
    exit 1
}

# ── Locate targets ─────────────────────────────────────────────────────────
$targets = if ($ProcessId -gt 0) {
    @(Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
} else {
    @(Get-Process -Name ($ProcessName -replace '\.exe$','') -ErrorAction SilentlyContinue)
}

if ($targets.Count -eq 0) {
    $label = if ($ProcessId -gt 0) { "PID $ProcessId" } else { "'$ProcessName'" }
    Write-Output "[ERROR] No process found matching $label"
    exit 1
}

# ── Log details BEFORE killing ────────────────────────────────────────────
Write-Output "===== TARGETS ($($targets.Count) found) ====="
$binaries = @()

foreach ($p in $targets) {
    $binPath  = try { $p.MainModule.FileName } catch { "n/a (access denied)" }
    $owner    = try {
        $o = (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)").GetOwner()
        "$($o.Domain)\$($o.User)"
    } catch { "n/a" }
    $parentId = try { (Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)").ParentProcessId } catch { "n/a" }

    Write-Output "  Name       : $($p.ProcessName)"
    Write-Output "  PID        : $($p.Id)"
    Write-Output "  Owner      : $owner"
    Write-Output "  Parent PID : $parentId"
    Write-Output "  Binary     : $binPath"
    Write-Output "  Started    : $($p.StartTime)"
    Write-Output ""

    if ($binPath -ne "n/a (access denied)" -and $binPath) { $binaries += $binPath }
}

# ── Kill ───────────────────────────────────────────────────────────────────
Write-Output "===== KILLING ====="
foreach ($p in $targets) {
    try {
        $p.Kill()
        $p.WaitForExit(3000) | Out-Null
        Write-Output "  [+] Killed $($p.ProcessName) (PID $($p.Id))"
    } catch {
        Write-Output "  [!] Failed to kill PID $($p.Id): $($_.Exception.Message)"
    }
}

# ── Optional: delete binary ────────────────────────────────────────────────
if ($DeleteBinary) {
    Write-Output ""
    Write-Output "===== DELETING BINARIES ====="
    foreach ($bin in ($binaries | Sort-Object -Unique)) {
        if (-not (Test-Path $bin)) { Write-Output "  [?] Already gone: $bin"; continue }
        try {
            Remove-Item -Path $bin -Force -ErrorAction Stop
            Write-Output "  [+] Deleted: $bin"
        } catch {
            # Escalate permissions and retry
            & takeown.exe /f $bin 2>&1 | Out-Null
            & icacls.exe $bin /grant "${env:USERNAME}:F" 2>&1 | Out-Null
            try {
                Remove-Item -Path $bin -Force -ErrorAction Stop
                Write-Output "  [+] Deleted (after takeown): $bin"
            } catch {
                Write-Output "  [!] Could not delete '$bin': $($_.Exception.Message)"
                Write-Output "      Manual step: takeown /f '$bin' && del /f '$bin'"
            }
        }
    }
} else {
    if ($binaries.Count -gt 0) {
        Write-Output ""
        Write-Output "  Binary paths (run again with -DeleteBinary `$true to remove):"
        $binaries | Sort-Object -Unique | ForEach-Object { Write-Output "    $_" }
    }
}

Write-Output ""
Write-Output "===== END KILL PROCESS ====="
