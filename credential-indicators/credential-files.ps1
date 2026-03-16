<#
.SYNOPSIS
    Credential Files - Hunt for SAM copies, NTDS.dit, and dump output files.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== CREDENTIAL FILE HUNT ====="

$stagingPaths = @(
    "C:\Windows\Temp","C:\Temp","$env:TEMP","$env:APPDATA",
    "$env:LOCALAPPDATA","$env:USERPROFILE","C:\PerfLogs","C:\ProgramData","C:\Users"
)

# -- SAM Hive Copies ----------------------------------------------------------
Write-Output "===== SAM HIVE COPIES ====="
Write-Output "(Legitimate SAM lives only at C:\Windows\System32\config\SAM)"
$samFound = 0
foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 3 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -ieq "SAM" -and
            $_.FullName -notmatch "\\System32\\config\\"
        } | ForEach-Object {
            Write-Output ("  [!!] {0}  [{1} KB]  Modified: {2}" -f
                $_.FullName, [math]::Round($_.Length/1KB,1), $_.LastWriteTime)
            $samFound++
        }
}
if ($samFound -eq 0) { Write-Output "  No SAM copies found outside System32\config." }

# -- NTDS.dit Copies ----------------------------------------------------------
Write-Output ""
Write-Output "===== NTDS.DIT COPIES ====="
Write-Output "(Legitimate NTDS.dit lives only at C:\Windows\NTDS\ntds.dit on DCs)"
$ntdsFound = 0
foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 3 -Filter "ntds.dit" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "\\Windows\\NTDS\\" } |
        ForEach-Object {
            Write-Output ("  [!!] {0}  [{1} MB]  Modified: {2}" -f
                $_.FullName, [math]::Round($_.Length/1MB,1), $_.LastWriteTime)
            $ntdsFound++
        }
}
if ($ntdsFound -eq 0) { Write-Output "  No NTDS.dit copies found outside NTDS directory." }

# -- Credential Dump Output File Patterns ------------------------------------
Write-Output ""
Write-Output "===== SUSPECTED CREDENTIAL DUMP OUTPUT (last 7 days) ====="
$credPatterns = @(
    "*password*","*passwd*","*hash*","*credential*",
    "*ntlm*","*kerberos*","*lsass*","*dump*","*sekurlsa*"
)
$credFound = 0
foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    foreach ($pattern in $credPatterns) {
        Get-ChildItem -Path $path -Depth 2 -Filter $pattern -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -in @(".txt",".csv",".log",".out",".dmp",".xml") -and
                $_.LastWriteTime -gt (Get-Date).AddDays(-7)
            } | ForEach-Object {
                Write-Output ("  [!] {0}  [{1} bytes]  Modified: {2}" -f
                    $_.FullName, $_.Length, $_.LastWriteTime)
                $credFound++
            }
    }
}
if ($credFound -eq 0) { Write-Output "  No suspected credential dump output files found." }

# -- Windows Credential Manager -----------------------------------------------
Write-Output ""
Write-Output "===== WINDOWS CREDENTIAL MANAGER (cmdkey /list) ====="
$cmdkeyOut = cmdkey /list 2>&1
$cmdkeyOut | ForEach-Object { Write-Output "  $_" }

Write-Output "===== END CREDENTIAL FILES ====="
