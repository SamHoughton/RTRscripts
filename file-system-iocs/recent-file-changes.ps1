<#
.SYNOPSIS
    Recent File Changes - Find files created or modified in the last N hours.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.PARAMETER HoursBack  How many hours back to scan (default: 24)
#>

param([int]$HoursBack = 24)

$cutoff = (Get-Date).AddHours(-$HoursBack)
Write-Output "===== RECENT FILE CHANGES (last $HoursBack hours, since $cutoff) ====="

$scanPaths = @(
    @{ Path = "C:\Windows\System32";  Depth = 1 },
    @{ Path = "C:\Windows\SysWOW64"; Depth = 1 },
    @{ Path = "C:\Windows\Temp";      Depth = 3 },
    @{ Path = "C:\ProgramData";       Depth = 3 },
    @{ Path = "C:\Users";             Depth = 4 },
    @{ Path = "C:\Temp";              Depth = 3 },
    @{ Path = "C:\PerfLogs";          Depth = 2 }
)

$suspiciousExts = @(".exe",".dll",".sys",".bat",".cmd",".ps1",".vbs",".js",".hta",".lnk",".scr")

foreach ($entry in $scanPaths) {
    if (-not (Test-Path $entry.Path)) { continue }
    Write-Output ""
    Write-Output "--- $($entry.Path) ---"

    $changed = Get-ChildItem -Path $entry.Path -Recurse -Depth $entry.Depth -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt $cutoff -or $_.CreationTime -gt $cutoff } |
        Sort-Object LastWriteTime -Descending

    if (-not $changed) { Write-Output "  No changes found."; continue }

    $changed | ForEach-Object {
        $flag    = if ($_.Extension -in $suspiciousExts) { "[!]" } else { "   " }
        $relPath = $_.FullName -replace [regex]::Escape($entry.Path), ""
        Write-Output ("  $flag {0,-55} {1,-24} {2,8} KB  {3}" -f
            $relPath,
            $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"),
            [math]::Round($_.Length / 1KB, 1),
            $_.Extension
        )
    }
}

Write-Output ""
Write-Output "===== END RECENT FILE CHANGES ====="
