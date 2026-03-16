#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remove a malicious registry Run / RunOnce persistence entry.

.DESCRIPTION
    Checks HKLM and HKCU Run/RunOnce hives, displays all current entries for
    review, then removes the specified value by name. Also checks the 64-bit
    and 32-bit (Wow6432Node) variants. Logs the value data before deletion
    so it can be recorded in case notes.

.IR_PHASE
    Eradication

.RTR_PERMISSION
    RTR Admin

.PARAMETER ValueName
    The exact registry value name to remove (case-insensitive match).

.PARAMETER Hive
    Which hive to target: HKLM (all users, requires admin) or HKCU (current user).
    Defaults to HKLM. Pass "Both" to remove from both hives if present.

.EXAMPLE
    runscript -CloudFile="remediation/remove-registry-run-key.ps1" `
      -CommandLine="-ValueName 'WindowsUpdate' -Hive 'HKLM'"
    runscript -CloudFile="remediation/remove-registry-run-key.ps1" `
      -CommandLine="-ValueName 'SecurityHealth' -Hive 'Both'"
#>
param(
    [Parameter(Mandatory=$true)][string]$ValueName = "",
    [ValidateSet("HKLM","HKCU","Both")][string]$Hive = "HKLM"
)

Write-Output "===== REMOVE REGISTRY RUN KEY ====="
Write-Output "Host     : $env:COMPUTERNAME"
Write-Output "Operator : $env:USERDOMAIN\$env:USERNAME"
Write-Output "Time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Target   : ValueName='$ValueName', Hive='$Hive'"
Write-Output ""

if (-not $ValueName) {
    Write-Output "[ERROR] -ValueName is required"
    exit 1
}

# All Run/RunOnce paths to check
$runPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

# ── Show all Run entries for context ─────────────────────────────────────
Write-Output "===== CURRENT RUN KEY ENTRIES (all hives — for context) ====="
foreach ($path in $runPaths) {
    if (-not (Test-Path $path)) { continue }
    $vals = Get-ItemProperty $path -ErrorAction SilentlyContinue
    if (-not $vals) { continue }
    $entries = $vals.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' }
    if ($entries.Count -eq 0) { continue }

    Write-Output "  [$path]"
    foreach ($e in $entries) {
        $marker = if ($e.Name -ieq $ValueName) { " <-- TARGET" } else { "" }
        Write-Output "  $($e.Name) = $($e.Value)$marker"
    }
    Write-Output ""
}

# ── Filter paths by requested hive ───────────────────────────────────────
$targetPaths = switch ($Hive) {
    "HKLM" { $runPaths | Where-Object { $_ -like 'HKLM:*' } }
    "HKCU" { $runPaths | Where-Object { $_ -like 'HKCU:*' } }
    "Both" { $runPaths }
}

# ── Remove matching entries ───────────────────────────────────────────────
Write-Output "===== REMOVING '$ValueName' ====="
$removed = 0

foreach ($path in $targetPaths) {
    if (-not (Test-Path $path)) { continue }
    $vals = Get-ItemProperty $path -ErrorAction SilentlyContinue
    $match = $vals.PSObject.Properties | Where-Object { $_.Name -ieq $ValueName }
    if (-not $match) { continue }

    Write-Output "  Found in: $path"
    Write-Output "  Value   : $($match.Value)"

    try {
        Remove-ItemProperty -Path $path -Name $ValueName -Force -ErrorAction Stop
        $removed++
        Write-Output "  [+] Removed: $path\$ValueName"
    } catch {
        Write-Output "  [!] Failed to remove from $path`: $($_.Exception.Message)"
    }
}

if ($removed -eq 0) {
    Write-Output "  [?] No matching value '$ValueName' found in the targeted hive(s)"
    Write-Output "      If the persistence is in a different hive, change -Hive parameter"
} else {
    Write-Output ""
    Write-Output "  [+] Total entries removed: $removed"
}

# ── Verify clean ─────────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== POST-REMOVAL VERIFICATION ====="
$stillPresent = $false
foreach ($path in $targetPaths) {
    if (-not (Test-Path $path)) { continue }
    $vals = Get-ItemProperty $path -ErrorAction SilentlyContinue
    $match = $vals.PSObject.Properties | Where-Object { $_.Name -ieq $ValueName }
    if ($match) {
        Write-Output "  [!] Still present in: $path"
        $stillPresent = $true
    }
}
if (-not $stillPresent) {
    Write-Output "  [+] Confirmed clean — '$ValueName' not found in targeted paths"
}

Write-Output ""
Write-Output "===== END REMOVE REGISTRY RUN KEY ====="
