<#
.SYNOPSIS
    LSASS Access - Detect credential dumping indicators targeting LSASS.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.NOTES
    Event 4656 requires "Audit Object Access - Process" to be enabled.
    Check audit policy: auditpol /get /category:*
#>

Write-Output "===== LSASS ACCESS INDICATORS ====="

# -- Current LSASS Process Info -----------------------------------------------
Write-Output "===== LSASS PROCESS ====="
$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if ($lsass) {
    Write-Output "  PID  : $($lsass.Id)"
    try { Write-Output "  Path : $($lsass.MainModule.FileName)" } catch {}
    Write-Output "  Start: $($lsass.StartTime)"
    Write-Output "  CPU  : $([math]::Round($lsass.CPU, 2))s total"
    if ($lsass.CPU -gt 30) {
        Write-Output "  [!] LSASS CPU is elevated - possible active dumping"
    }
} else {
    Write-Output "  [!!] lsass.exe NOT FOUND - unexpected"
}

# -- Dump Files in Common Locations -------------------------------------------
Write-Output ""
Write-Output "===== LSASS DUMP FILES ====="
$dumpSearchPaths = @(
    "C:\Windows\Temp","C:\Temp","$env:TEMP","$env:USERPROFILE",
    "$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads",
    "C:\PerfLogs","C:\ProgramData"
)
$dumpFound = 0
foreach ($searchPath in $dumpSearchPaths) {
    if (-not (Test-Path $searchPath)) { continue }
    $dumps = Get-ChildItem -Path $searchPath -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Extension -eq ".dmp" -or $_.Name -match "lsass|memory\.dmp|minidump") -and
            $_.Length -gt 1MB
        }
    foreach ($d in $dumps) {
        Write-Output ("  [!!] {0}  [{1} MB]  Modified: {2}" -f
            $d.FullName, [math]::Round($d.Length/1MB,1), $d.LastWriteTime)
        $dumpFound++
    }
}
if ($dumpFound -eq 0) { Write-Output "  No LSASS dump files found in common locations." }

# -- Known Credential Dump Tools in Running Processes ------------------------
Write-Output ""
Write-Output "===== RUNNING PROCESSES - KNOWN DUMP TOOL NAMES ====="
$dumpToolNames = @(
    "mimikatz","mimi32","mimi64","procdump","wce","fgdump","pwdump",
    "gsecdump","lsassy","pypykatz","nanodump","handlekatz","ppldump",
    "dumpert","rdrleakdiag","sqldumper"
)
$found = 0
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $procPath = try { $_.MainModule.FileName } catch { "" }
    foreach ($name in $dumpToolNames) {
        if ($_.Name -like "*$name*" -or $procPath -like "*$name*") {
            Write-Output "  [!!] MATCH: $($_.Name) (PID $($_.Id)) Path: $procPath"
            $found++
        }
    }
}
if ($found -eq 0) { Write-Output "  No known credential dump tools found in running processes." }

# -- Audit Policy Check -------------------------------------------------------
Write-Output ""
Write-Output "===== AUDIT POLICY (Handle Manipulation) ====="
$auditOut = auditpol /get /subcategory:"Handle Manipulation" 2>&1
Write-Output ($auditOut -join "`n")

# -- Recent LSASS Handle Access Events (4656) ---------------------------------
Write-Output ""
Write-Output "===== LSASS HANDLE ACCESS EVENTS (4656, last 20, past 24h) ====="
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4656
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 50 -ErrorAction Stop |
    Where-Object { $_.Message -match "lsass" } |
    Select-Object -First 20

    if ($events) {
        $events | ForEach-Object {
            $xml  = [xml]$_.ToXml()
            $data = $xml.Event.EventData.Data
            [PSCustomObject]@{
                Time    = $_.TimeCreated
                Subject = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                Process = ($data | Where-Object { $_.Name -eq 'ProcessName' }).'#text'
                Access  = ($data | Where-Object { $_.Name -eq 'AccessMask' }).'#text'
            }
        } | Format-Table -AutoSize
    } else {
        Write-Output "  No lsass handle access events in Security log (past 24h)."
    }
} catch {
    Write-Output "  [!] Could not read Security log: $_"
}
Write-Output "===== END LSASS ACCESS ====="
