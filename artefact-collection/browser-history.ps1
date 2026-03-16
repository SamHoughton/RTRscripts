<#
.SYNOPSIS
    Browser History - Extract recent browser history from Chrome, Edge, and Firefox.

.DESCRIPTION
    Collects URLs visited in major browsers from all user profiles on the host.
    Useful for:
      • Finding the initial access vector (phishing link clicked, malicious download)
      • Identifying C2 domains browsed to via malware-embedded browser
      • Locating file download history to correlate with execution artefacts

    Browsers store history in SQLite databases. This script uses a file-copy
    approach to avoid locking issues (history DBs are locked while browser is open).

.IR_PHASE
    Identification

.RTR_PERMISSION
    Active Responder

.NOTES
    Browser must not be currently writing to get a consistent snapshot — the copy
    approach handles read locks but not write locks. Close browser if possible.
    History retention varies: Chrome/Edge ~90 days, Firefox ~180 days by default.

    Requires SQLite querying capability. This script uses .NET SQLite interop
    via a lightweight approach — no external binaries needed.

.EXAMPLE
    runscript -CloudFile="artefact-collection/browser-history.ps1"
#>

# How far back to look
$daysBack = 7
$cutoff   = (Get-Date).AddDays(-$daysBack)

# Temp staging directory — cleaned up at end
$tempDir = "$env:TEMP\RTR_BrowserHistory_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

Write-Output "===== BROWSER HISTORY (last $daysBack days) ====="
Write-Output "Collecting from all profiles under C:\Users\"
Write-Output ""

# ── Helper: query SQLite via .NET ─────────────────────────────────────────────
# PowerShell has no native SQLite support; we use System.Data.SQLite if available,
# otherwise fall back to copying the file and noting it for offline analysis.
function Invoke-SQLiteQuery {
    param([string]$DbPath, [string]$Query)

    # Try to load SQLite assembly (may be present on some endpoints)
    $sqliteAssembly = @(
        "$env:ProgramFiles\System.Data.SQLite\System.Data.SQLite.dll",
        "$env:ProgramFiles (x86)\System.Data.SQLite\System.Data.SQLite.dll"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($sqliteAssembly) {
        try {
            Add-Type -Path $sqliteAssembly -ErrorAction Stop
            $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$DbPath;Version=3;Read Only=True;")
            $conn.Open()
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = $Query
            $reader = $cmd.ExecuteReader()
            $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
            while ($reader.Read()) {
                $row = [ordered]@{}
                for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                    $row[$reader.GetName($i)] = $reader.GetValue($i)
                }
                $rows.Add([PSCustomObject]$row)
            }
            $conn.Close()
            return $rows
        } catch {
            return $null
        }
    }
    return $null
}

# ── Chrome / Edge (same DB schema, Chromium-based) ───────────────────────────
$chromiumProfiles = @()
foreach ($user in (Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue)) {
    foreach ($browser in @("Google\Chrome", "Microsoft\Edge")) {
        $base = "$($user.FullName)\AppData\Local\$browser\User Data"
        if (Test-Path $base) {
            # Enumerate all profiles (Default, Profile 1, Profile 2, ...)
            $profiles = @("Default") + (Get-ChildItem $base -Directory -Filter "Profile*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
            foreach ($profile in $profiles) {
                $histDb = "$base\$profile\History"
                if (Test-Path $histDb) {
                    $chromiumProfiles += [PSCustomObject]@{
                        User    = $user.Name
                        Browser = $browser -replace '.*\\', ''
                        Profile = $profile
                        DbPath  = $histDb
                    }
                }
            }
        }
    }
}

foreach ($entry in $chromiumProfiles) {
    Write-Output "--- $($entry.Browser) | User: $($entry.User) | Profile: $($entry.Profile) ---"

    # Copy DB to temp to avoid lock — Chrome keeps DB open while running
    $tmpDb = "$tempDir\$($entry.Browser)_$($entry.User)_$($entry.Profile).db"
    try {
        Copy-Item -Path $entry.DbPath -Destination $tmpDb -Force -ErrorAction Stop
    } catch {
        Write-Output "  [!] Could not copy history DB (browser may be locking it): $_"
        Write-Output "  Path: $($entry.DbPath)"
        continue
    }

    # Chrome stores timestamps as microseconds since 1601-01-01
    $epoch = [datetime]"1601-01-01"
    $query = @"
SELECT url, title, visit_count, last_visit_time
FROM urls
WHERE last_visit_time > 0
ORDER BY last_visit_time DESC
LIMIT 200
"@

    $rows = Invoke-SQLiteQuery -DbPath $tmpDb -Query $query
    if ($rows) {
        $filtered = $rows | ForEach-Object {
            $ts = $epoch.AddMicroseconds($_.last_visit_time)
            if ($ts -gt $cutoff) {
                [PSCustomObject]@{
                    LastVisit  = $ts.ToString("yyyy-MM-dd HH:mm:ss")
                    VisitCount = $_.visit_count
                    URL        = if ($_.url.Length -gt 100) { $_.url.Substring(0,100) + "..." } else { $_.url }
                    Title      = $_.title
                }
            }
        } | Where-Object { $_ }

        if ($filtered) {
            $filtered | Format-Table -AutoSize
        } else {
            Write-Output "  No visits in the last $daysBack days."
        }
    } else {
        Write-Output "  [!] SQLite query failed (System.Data.SQLite not available)."
        Write-Output "  [>] DB copied to $tmpDb — retrieve with: get $tmpDb"
    }
    Write-Output ""
}

# ── Firefox ───────────────────────────────────────────────────────────────────
foreach ($user in (Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue)) {
    $ffBase = "$($user.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles"
    if (-not (Test-Path $ffBase)) { continue }

    foreach ($profile in (Get-ChildItem $ffBase -Directory -ErrorAction SilentlyContinue)) {
        $histDb = "$($profile.FullName)\places.sqlite"
        if (-not (Test-Path $histDb)) { continue }

        Write-Output "--- Firefox | User: $($user.Name) | Profile: $($profile.Name) ---"

        $tmpDb = "$tempDir\Firefox_$($user.Name)_$($profile.Name).db"
        try {
            Copy-Item -Path $histDb -Destination $tmpDb -Force -ErrorAction Stop
        } catch {
            Write-Output "  [!] Could not copy Firefox history DB: $_"
            continue
        }

        # Firefox timestamps: microseconds since Unix epoch (1970-01-01)
        $ffEpoch = [datetime]"1970-01-01"
        $cutoffMicro = ($cutoff - $ffEpoch).TotalMilliseconds * 1000
        $query = @"
SELECT p.url, p.title, p.visit_count, MAX(h.visit_date) as last_visit
FROM moz_places p
JOIN moz_historyvisits h ON p.id = h.place_id
WHERE h.visit_date > $cutoffMicro
GROUP BY p.id
ORDER BY last_visit DESC
LIMIT 200
"@

        $rows = Invoke-SQLiteQuery -DbPath $tmpDb -Query $query
        if ($rows) {
            $rows | ForEach-Object {
                $ts = $ffEpoch.AddMilliseconds($_.last_visit / 1000)
                [PSCustomObject]@{
                    LastVisit  = $ts.ToString("yyyy-MM-dd HH:mm:ss")
                    VisitCount = $_.visit_count
                    URL        = if ($_.url.Length -gt 100) { $_.url.Substring(0,100) + "..." } else { $_.url }
                    Title      = $_.title
                }
            } | Format-Table -AutoSize
        } else {
            Write-Output "  [!] SQLite query unavailable. DB at: $tmpDb"
            Write-Output "  [>] Retrieve with: get $tmpDb"
        }
        Write-Output ""
    }
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
Write-Output "Cleaning up temp directory: $tempDir"
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "===== END BROWSER HISTORY ====="
