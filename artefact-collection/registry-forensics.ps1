<#
.SYNOPSIS
    Registry Forensics — execution artefacts from UserAssist, BAM, ShimCache, MRU.

.DESCRIPTION
    Extracts execution evidence from Windows registry artefacts that persist after
    binaries are deleted. Covers:
      • UserAssist    — GUI programs launched by each user (ROT13 encoded, with run count)
      • BAM / DAM     — Background Activity Moderator (execution timestamps, Windows 10+)
      • ShimCache     — AppCompatCache (execution history, survives reboots)
      • RecentDocs    — Recently opened files per user per extension
      • Run/RunOnce   — Autorun entries (cross-reference with startup-entries.ps1)
      • TypedPaths    — Explorer address bar history (URLs/paths typed by users)
      • WordWheelQuery— File Explorer search history

    All reads are non-destructive. PSDrive HKCU covers the currently running user;
    for offline/other user hives use the RTR Admin variant with NTUser.dat loading.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.EXAMPLE
    runscript -CloudFile="artefact-collection/registry-forensics.ps1"
#>

$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Output "===== REGISTRY FORENSICS ====="
Write-Output "Host      : $env:COMPUTERNAME"
Write-Output "Operator  : $env:USERNAME"
Write-Output "Time      : $ts"
Write-Output ""

function Decode-Rot13 {
    param([string]$s)
    -join ($s.ToCharArray() | ForEach-Object {
        if     ($_ -ge 'A' -and $_ -le 'Z') { [char](((([int]$_) - 65 + 13) % 26) + 65) }
        elseif ($_ -ge 'a' -and $_ -le 'z') { [char](((([int]$_) - 97 + 13) % 26) + 97) }
        else   { $_ }
    })
}

function Get-HiveUsers {
    # Return SID → username mapping for loaded hives
    $users = @{}
    try {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' |
            ForEach-Object {
                $sid = Split-Path $_.PSPath -Leaf
                $users[$sid] = $_.ProfileImagePath
            }
    } catch { }
    return $users
}

$hiveUsers = Get-HiveUsers

# ── SECTION 1: UserAssist ──────────────────────────────────────────────────────
# Records every GUI application launched. Values are ROT13 encoded, data is binary.
# Byte offsets: 4=session count, 8=run count, 60=last run timestamp (FILETIME)
Write-Output "===== USERASSIST (GUI Execution History) ====="

$uaBase = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
try {
    $guids = Get-ChildItem $uaBase -ErrorAction Stop
    foreach ($guid in $guids) {
        $countPath = Join-Path $guid.PSPath 'Count'
        try {
            $entries = Get-ItemProperty $countPath -ErrorAction Stop
            $entries.PSObject.Properties |
                Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider','UEME_CTX_PACKAGED_APPS') } |
                ForEach-Object {
                    $decoded = Decode-Rot13 $_.Name
                    $data    = $_.Value  # byte array
                    if ($data -is [byte[]] -and $data.Length -ge 72) {
                        $runCount = [BitConverter]::ToInt32($data, 4)
                        $ftLow    = [BitConverter]::ToInt32($data, 60)
                        $ftHigh   = [BitConverter]::ToInt32($data, 64)
                        if ($ftHigh -gt 0 -or $ftLow -gt 0) {
                            $ft   = [long]$ftHigh -shl 32 -bor [long][uint32]$ftLow
                            $time = [DateTime]::FromFileTimeUtc($ft).ToLocalTime()
                            Write-Output ("  [{0:yyyy-MM-dd HH:mm:ss}]  runs={1,-4}  {2}" -f $time, $runCount, $decoded)
                        }
                    }
                }
        } catch { }
    }
} catch {
    Write-Output "  [!] Could not read UserAssist: $_"
}
Write-Output ""

# ── SECTION 2: BAM (Background Activity Moderator) ───────────────────────────
# Windows 10 1709+. Records last execution time of binaries per user SID.
Write-Output "===== BAM — Background Activity Moderator (Last Execution Times) ====="
$bamBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
try {
    $bamSids = Get-ChildItem $bamBase -ErrorAction Stop
    foreach ($sid in $bamSids) {
        $username = $hiveUsers[$sid.PSChildName] ?? $sid.PSChildName
        Write-Output "  User: $username"
        $entries = Get-ItemProperty $sid.PSPath -ErrorAction SilentlyContinue
        $entries.PSObject.Properties |
            Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider','Version','SequenceNumber') -and
                           $_.Name -match '\\\|/' } |
            ForEach-Object {
                $data = $_.Value
                if ($data -is [byte[]] -and $data.Length -ge 8) {
                    $ft   = [BitConverter]::ToInt64($data, 0)
                    if ($ft -gt 0) {
                        $time = [DateTime]::FromFileTimeUtc($ft).ToLocalTime()
                        Write-Output ("  [{0:yyyy-MM-dd HH:mm:ss}]  {1}" -f $time, $_.Name)
                    }
                }
            }
        Write-Output ""
    }
} catch {
    Write-Output "  [i] BAM not available (requires Windows 10 1709+): $_"
}

# ── SECTION 3: ShimCache / AppCompatCache ─────────────────────────────────────
# Records executed binaries — survives deletion. Windows 10/11 stores in binary.
# We do a raw read and extract PE paths (strings starting with \Device\ or C:\)
Write-Output "===== SHIMCACHE — AppCompatCache (Execution Artefacts) ====="
$shimPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
try {
    $shimData = (Get-ItemProperty $shimPath -ErrorAction Stop).AppCompatCache
    if ($shimData) {
        # Parse paths: look for null-terminated Unicode strings containing backslash
        $encoding = [System.Text.Encoding]::Unicode
        $str      = $encoding.GetString($shimData)
        # Extract printable path-like substrings
        $matches  = [regex]::Matches($str, '[A-Za-z]:\\[^\x00-\x1f]{4,260}')
        if ($matches.Count -gt 0) {
            $matches | Select-Object -ExpandProperty Value | Sort-Object -Unique |
                ForEach-Object { Write-Output "  $_" }
        } else {
            Write-Output "  [i] ShimCache present but could not extract paths (binary format varies by OS)"
        }
    }
} catch {
    Write-Output "  [!] Could not read ShimCache: $_"
}
Write-Output ""

# ── SECTION 4: Recently Opened Documents (RecentDocs) ────────────────────────
Write-Output "===== RECENTDOCS — Recently Opened Files (per Extension) ====="
$recentPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
try {
    # Top-level: MRU list of recent files across all types
    $topMRU = Get-ItemProperty $recentPath -ErrorAction Stop
    $mruList = $topMRU.MRUListEx
    if ($mruList -is [byte[]]) {
        Write-Output "  Recent files (MRUListEx order):"
        for ($i = 0; $i -lt ($mruList.Length - 4); $i += 4) {
            $idx = [BitConverter]::ToInt32($mruList, $i)
            if ($idx -eq -1) { break }
            $val = $topMRU.$idx
            if ($val -is [byte[]]) {
                # File name is null-terminated Unicode at start of value
                $enc  = [System.Text.Encoding]::Unicode
                $nullIdx = 0
                for ($j = 0; $j -lt $val.Length - 1; $j += 2) {
                    if ($val[$j] -eq 0 -and $val[$j+1] -eq 0) { $nullIdx = $j; break }
                }
                $filename = $enc.GetString($val, 0, [Math]::Max(2, $nullIdx))
                if ($filename.Trim()) { Write-Output "  $filename" }
            }
        }
    }

    Write-Output ""
    Write-Output "  Extensions with recent activity:"
    Get-ChildItem $recentPath -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty PSChildName | Sort-Object |
        Where-Object { $_ -ne 'Folder' } |
        ForEach-Object { Write-Output "    .$_" }
} catch {
    Write-Output "  [!] Could not read RecentDocs: $_"
}
Write-Output ""

# ── SECTION 5: Explorer Typed Paths / URLs ────────────────────────────────────
Write-Output "===== TYPED PATHS (Explorer Address Bar History) ====="
$typedPaths = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'
try {
    $paths = Get-ItemProperty $typedPaths -ErrorAction Stop
    $paths.PSObject.Properties |
        Where-Object { $_.Name -match '^url\d+$' } |
        Sort-Object Name |
        ForEach-Object { Write-Output "  $($_.Value)" }
} catch {
    Write-Output "  [i] No typed paths found"
}
Write-Output ""

# ── SECTION 6: File Explorer Search History ───────────────────────────────────
Write-Output "===== SEARCH HISTORY (WordWheelQuery) ====="
$wwqPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery'
try {
    $wwq = Get-ItemProperty $wwqPath -ErrorAction Stop
    $mru = $wwq.MRUListEx
    if ($mru -is [byte[]]) {
        for ($i = 0; $i -lt ($mru.Length - 4); $i += 4) {
            $idx = [BitConverter]::ToInt32($mru, $i)
            if ($idx -eq -1) { break }
            $val = $wwq.$idx
            if ($val -is [byte[]]) {
                $term = [System.Text.Encoding]::Unicode.GetString($val).TrimEnd([char]0)
                if ($term.Trim()) { Write-Output "  $term" }
            }
        }
    }
} catch {
    Write-Output "  [i] No search history found"
}
Write-Output ""

# ── SECTION 7: Run / RunOnce Keys ─────────────────────────────────────────────
Write-Output "===== RUN / RUNONCE KEYS ====="
$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($key in $runKeys) {
    try {
        $vals = Get-ItemProperty $key -ErrorAction Stop
        $vals.PSObject.Properties |
            Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider') } |
            ForEach-Object {
                $path = $key -replace 'HKLM:','HKLM' -replace 'HKCU:','HKCU'
                Write-Output "  [$path]"
                Write-Output "    $($_.Name) = $($_.Value)"
            }
    } catch { }
}
Write-Output ""

Write-Output "===== END REGISTRY FORENSICS ====="
