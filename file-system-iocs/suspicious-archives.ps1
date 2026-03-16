<#
.SYNOPSIS
    Suspicious Archives - Hunt for data staging and exfil preparation indicators.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== SUSPICIOUS ARCHIVE / DATA STAGING HUNT ====="

$stagingPaths = @(
    "C:\Windows\Temp","C:\Temp","$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA",
    "$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads","C:\PerfLogs",
    "C:\ProgramData","C:\Intel","C:\Recovery"
)
$archiveExts = @(".zip",".7z",".rar",".tar",".gz",".bz2",".cab",".iso")
$thresholdMB = 50

# -- Large Archives in Staging Paths -----------------------------------------
Write-Output "===== LARGE ARCHIVES (>${thresholdMB} MB) IN STAGING PATHS ====="
$archivesFound = 0
foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Length -gt ($thresholdMB * 1MB) -and
            ($archiveExts | Where-Object { $_.Name.ToLower().EndsWith($_) })
        } | Sort-Object Length -Descending |
        ForEach-Object {
            Write-Output ("  [!] {0,-70} {1,8} MB  Created: {2}" -f
                $_.FullName,
                [math]::Round($_.Length/1MB,1),
                $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"))
            $archivesFound++
        }
}
if ($archivesFound -eq 0) { Write-Output "  No large archives found in staging paths." }

# -- Double Extension Files ---------------------------------------------------
Write-Output ""
Write-Output "===== DOUBLE EXTENSION FILES ====="
$doubleExtFound = 0
foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.[a-z]{2,4}\.[a-z]{2,4}$' -and $_.Name -notmatch '\.tar\.' } |
        ForEach-Object {
            Write-Output "  [!] $($_.FullName)  [$($_.Length) bytes]  Modified: $($_.LastWriteTime)"
            $doubleExtFound++
        }
}
if ($doubleExtFound -eq 0) { Write-Output "  No double-extension files found." }

# -- Archives in System Paths (always suspicious) ----------------------------
Write-Output ""
Write-Output "===== ARCHIVES IN SYSTEM PATHS (always suspicious) ====="
$sysArchiveFound = 0
$sysPaths = @("C:\Windows\System32","C:\Windows\SysWOW64","C:\Windows\Tasks")
foreach ($path in $sysPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
        Where-Object { ($archiveExts | Where-Object { $_.Name.ToLower().EndsWith($_) }) } |
        ForEach-Object {
            Write-Output "  [!!] $($_.FullName)  [$($_.Length) bytes]"
            $sysArchiveFound++
        }
}
if ($sysArchiveFound -eq 0) { Write-Output "  No archives found in system paths." }

# -- File Clusters (many new files in same dir = staging) --------------------
Write-Output ""
Write-Output "===== FILE CLUSTERS (>5 files created in last 48h in same directory) ====="
$cutoff  = (Get-Date).AddHours(-48)
$grouped = foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
        Where-Object { $_.CreationTime -gt $cutoff } |
        Group-Object DirectoryName |
        Where-Object { $_.Count -ge 5 }
}
if ($grouped) {
    $grouped | ForEach-Object {
        $totalMB = ($_.Group | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Output ("  [!] {0,-65} {1,3} files  {2,7} MB total" -f
            $_.Name, $_.Count, [math]::Round($totalMB,1))
    }
} else {
    Write-Output "  No file clusters detected."
}

Write-Output "===== END SUSPICIOUS ARCHIVES ====="
