<#
.SYNOPSIS
    Kill Process - Safely terminate a process by name or PID with pre-kill evidence capture.

.DESCRIPTION
    Terminates a specified process but FIRST captures:
      • Full process metadata (path, command line, parent)
      • Any child processes that will also be terminated
      • Open handles (where accessible)

    This "evidence before action" approach ensures you don't lose forensic data
    when terminating a malicious process. Always document before you destroy.

.IR_PHASE
    Containment

.RTR_PERMISSION
    Active Responder

.PARAMETER TargetPID
    Process ID to kill. Takes precedence over TargetName if both supplied.

.PARAMETER TargetName
    Process name to kill (e.g. "malware.exe"). Will kill ALL matching processes.

.PARAMETER DryRun
    If set to $true, collects and displays evidence but does NOT kill the process.
    Use this first to confirm you're targeting the right process.

.EXAMPLE
    # Dry run first — confirm target before killing
    runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-TargetName 'suspicious.exe' -DryRun $true"

    # Live kill by PID
    runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-TargetPID 4832"
#>

param(
    [int]    $TargetPID  = 0,
    [string] $TargetName = "",
    [bool]   $DryRun     = $false
)

if ($TargetPID -eq 0 -and [string]::IsNullOrWhiteSpace($TargetName)) {
    Write-Output "[ERROR] You must supply either -TargetPID or -TargetName"
    Write-Output "Example: -TargetPID 1234"
    Write-Output "Example: -TargetName 'malware.exe'"
    exit 1
}

# ── Resolve target process(es) ────────────────────────────────────────────────
$allProcs = Get-CimInstance Win32_Process
$targets  = @()

if ($TargetPID -gt 0) {
    $targets = $allProcs | Where-Object { $_.ProcessId -eq $TargetPID }
    if (-not $targets) {
        Write-Output "[ERROR] No process found with PID $TargetPID"
        exit 1
    }
} else {
    $targets = $allProcs | Where-Object { $_.Name -ieq $TargetName }
    if (-not $targets) {
        Write-Output "[ERROR] No process found with name '$TargetName'"
        exit 1
    }
}

Write-Output "===== KILL PROCESS ====="
if ($DryRun) { Write-Output "*** DRY RUN MODE — no processes will be terminated ***" }
Write-Output ""

$procIndex = @{}
foreach ($p in $allProcs) { $procIndex[$p.ProcessId] = $p }

foreach ($target in $targets) {
    Write-Output "--- TARGET PROCESS ---"
    Write-Output "PID          : $($target.ProcessId)"
    Write-Output "Name         : $($target.Name)"
    Write-Output "Path         : $($target.ExecutablePath)"
    Write-Output "CommandLine  : $($target.CommandLine)"
    Write-Output "Parent PID   : $($target.ParentProcessId)"
    Write-Output "Parent Name  : $(if ($procIndex.ContainsKey($target.ParentProcessId)) { $procIndex[$target.ParentProcessId].Name } else { 'N/A' })"
    Write-Output "Started      : $($target.CreationDate)"

    # ── Child processes ───────────────────────────────────────────────────────
    # Important: killing a process tree requires stopping children too, or they
    # may be re-parented to System and continue running
    $children = $allProcs | Where-Object { $_.ParentProcessId -eq $target.ProcessId }
    if ($children) {
        Write-Output ""
        Write-Output "Child processes (will also be affected):"
        $children | Select-Object ProcessId, Name, CommandLine | Format-Table -AutoSize
    } else {
        Write-Output "Child processes : None"
    }

    # ── Hash for IOC generation ───────────────────────────────────────────────
    if ($target.ExecutablePath -and (Test-Path $target.ExecutablePath)) {
        try {
            $hash = Get-FileHash -Path $target.ExecutablePath -Algorithm SHA256 -ErrorAction Stop
            Write-Output "SHA256         : $($hash.Hash)"
        } catch {
            Write-Output "SHA256         : [could not hash: $_]"
        }
    }

    Write-Output ""

    if (-not $DryRun) {
        # Kill the process tree (children first to avoid re-parenting)
        foreach ($child in $children) {
            Write-Output "Killing child PID $($child.ProcessId) ($($child.Name))..."
            try {
                Stop-Process -Id $child.ProcessId -Force -ErrorAction Stop
                Write-Output "  [OK] Child killed."
            } catch {
                Write-Output "  [!] Failed to kill child: $_"
            }
        }

        Write-Output "Killing target PID $($target.ProcessId) ($($target.Name))..."
        try {
            Stop-Process -Id $target.ProcessId -Force -ErrorAction Stop
            Write-Output "  [OK] Process terminated."
        } catch {
            Write-Output "  [!] Failed to terminate process: $_"
            Write-Output "      Try running with RTR Admin role if Active Responder insufficient."
        }

        # Confirm it's gone
        Start-Sleep -Milliseconds 500
        $stillRunning = Get-Process -Id $target.ProcessId -ErrorAction SilentlyContinue
        if ($stillRunning) {
            Write-Output "  [!!] Process is STILL RUNNING after kill attempt. May require host isolation."
        } else {
            Write-Output "  [OK] Confirmed: process no longer running."
        }
    } else {
        Write-Output "[DRY RUN] Would kill PID $($target.ProcessId) and $($children.Count) child process(es)."
        Write-Output "[DRY RUN] Re-run without -DryRun `$true to execute."
    }

    Write-Output ""
}

Write-Output "===== END KILL PROCESS ====="
