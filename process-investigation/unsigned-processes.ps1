<#
.SYNOPSIS
    Unsigned Processes - Find running processes whose binaries are not digitally signed.

.DESCRIPTION
    Legitimate software from reputable vendors is almost always signed. Unsigned
    binaries — especially those running from user-writable paths like AppData,
    Temp, or the Desktop — are a strong indicator of malware or tooling dropped
    by an adversary.

    This script:
      1. Enumerates all running processes
      2. Checks Authenticode signature of each binary
      3. Flags unsigned, invalid-signature, or missing binaries
      4. Highlights processes running from high-risk paths

.IR_PHASE
    Identification

.RTR_PERMISSION
    Active Responder

.NOTES
    Get-AuthenticodeSignature reads the file from disk — if the binary has been
    deleted but the process is still running (common malware technique), it will
    show as "file not found". That itself is a high-fidelity indicator.

.EXAMPLE
    runscript -CloudFile="process-investigation/unsigned-processes.ps1"
#>

# Paths that legitimate system software should NOT be running from
$highRiskPaths = @(
    "$env:TEMP",
    "$env:APPDATA",
    "$env:LOCALAPPDATA",
    "$env:PUBLIC",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Downloads",
    "C:\PerfLogs",
    "C:\Intel"
)

Write-Output "===== UNSIGNED / SUSPICIOUS PROCESSES ====="
Write-Output ""

$allProcs = Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 }  # Skip Idle and System

$unsigned    = [System.Collections.Generic.List[object]]::new()
$highRiskHit = [System.Collections.Generic.List[object]]::new()
$deletedBin  = [System.Collections.Generic.List[object]]::new()

foreach ($proc in $allProcs) {
    $path = $null
    try {
        $path = $proc.MainModule.FileName
    } catch {
        # Common for protected system processes — skip silently
        continue
    }

    if (-not $path) { continue }

    # ── Deleted binary check ─────────────────────────────────────────────────
    # Process running with no file on disk = high confidence malicious
    if (-not (Test-Path $path)) {
        $deletedBin.Add([PSCustomObject]@{
            PID  = $proc.Id
            Name = $proc.Name
            Path = $path
        })
        continue
    }

    # ── Signature check ──────────────────────────────────────────────────────
    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue

    $sigStatus = if ($sig) { $sig.Status.ToString() } else { "Unknown" }

    if ($sigStatus -notin @("Valid")) {
        $unsigned.Add([PSCustomObject]@{
            PID       = $proc.Id
            Name      = $proc.Name
            SigStatus = $sigStatus
            Signer    = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "N/A" }
            Path      = $path
        })
    }

    # ── High-risk path check (even if signed) ────────────────────────────────
    foreach ($riskPath in $highRiskPaths) {
        if ($path -like "$riskPath*") {
            $highRiskHit.Add([PSCustomObject]@{
                PID       = $proc.Id
                Name      = $proc.Name
                SigStatus = $sigStatus
                Path      = $path
            })
            break
        }
    }
}

# Output results
if ($deletedBin.Count -gt 0) {
    Write-Output "[!!] PROCESSES WITH DELETED BINARIES (very high confidence IOC):"
    $deletedBin | Format-Table -AutoSize
} else {
    Write-Output "[OK] No processes found running from deleted binaries."
}

Write-Output ""

if ($unsigned.Count -gt 0) {
    Write-Output "[!] UNSIGNED / INVALID SIGNATURE PROCESSES:"
    $unsigned | Format-Table -AutoSize
} else {
    Write-Output "[OK] All accessible processes have valid signatures."
}

Write-Output ""

if ($highRiskHit.Count -gt 0) {
    Write-Output "[!] PROCESSES RUNNING FROM HIGH-RISK PATHS:"
    $highRiskHit | Format-Table -AutoSize
} else {
    Write-Output "[OK] No processes found in high-risk user-writable paths."
}

Write-Output ""
Write-Output "===== END UNSIGNED PROCESSES ====="
