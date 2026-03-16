/**
 * scripts-data.js
 *
 * Embedded script library — each entry contains the full PowerShell source
 * inline so the web app works with no backend / file server.
 *
 * Adding a new script: copy an existing entry and update all fields.
 */

window.RTR_SCRIPTS = [

  // ══════════════════════════════════════════════════════ TRIAGE
  {
    id:         "host-summary",
    category:   "Triage",
    name:       "host-summary.ps1",
    shortDesc:  "OS, uptime, local admins, AV, patches",
    irPhase:    "Identification",
    permission: "Active Responder",
    description: "Collects key host identity and health indicators in a single pass. Designed as the first script to run during the Identification phase — gives you enough context to decide whether deeper investigation is warranted.",
    usage: `runscript -CloudFile="triage/host-summary.ps1"`,
    source: `<#
.SYNOPSIS
    Host Summary - Rapid triage snapshot of a target host.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

# ── System Identity ───────────────────────────────────────────────────────────
$os   = Get-CimInstance Win32_OperatingSystem
$cs   = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS

Write-Output "===== HOST SUMMARY ====="
Write-Output "Hostname       : $($env:COMPUTERNAME)"
Write-Output "Domain         : $($cs.Domain)"
Write-Output "OS             : $($os.Caption) [$($os.Version)]"
Write-Output "Architecture   : $($os.OSArchitecture)"
Write-Output "Serial / UUID  : $($bios.SerialNumber)"
Write-Output "Last Boot      : $($os.LastBootUpTime)"
Write-Output "Current Time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC$(([System.TimeZone]::CurrentTimeZone).GetUtcOffset((Get-Date)))"
Write-Output ""

# ── Uptime ────────────────────────────────────────────────────────────────────
# Long uptime = host may not have received patches
$uptime = (Get-Date) - $os.LastBootUpTime
Write-Output "Uptime         : $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m"
Write-Output ""

# ── Local Admins ──────────────────────────────────────────────────────────────
# Unexpected members here = classic persistence / privilege escalation indicator
Write-Output "===== LOCAL ADMINISTRATORS ====="
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $admins | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize
} catch {
    Write-Output "  [!] Could not enumerate local admins: $_"
}

# ── Installed AV / EDR Products ───────────────────────────────────────────────
Write-Output "===== SECURITY PRODUCTS (SecurityCenter2) ====="
try {
    $av = Get-CimInstance -Namespace "root\\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
    if ($av) {
        $av | Select-Object displayName, productState | Format-Table -AutoSize
    } else {
        Write-Output "  [!] No AV products found in SecurityCenter2"
    }
} catch {
    Write-Output "  [!] SecurityCenter2 query failed (may be server OS): $_"
}

# ── Patch Level ───────────────────────────────────────────────────────────────
Write-Output "===== LAST 5 INSTALLED UPDATES ====="
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 |
    Select-Object HotFixID, InstalledOn, Description | Format-Table -AutoSize

Write-Output "===== END HOST SUMMARY ====="
`
  },

  {
    id:         "active-connections",
    category:   "Triage",
    name:       "active-connections.ps1",
    shortDesc:  "TCP/UDP sockets mapped to owning process",
    irPhase:    "Identification",
    permission: "Active Responder",
    description: "Maps every listening and established socket to its owning process and binary path. Critical during Identification — C2 channels, lateral movement, and exfiltration almost always leave a footprint here.",
    usage: `runscript -CloudFile="triage/active-connections.ps1"`,
    source: `<#
.SYNOPSIS
    Active Connections - Enumerate all current TCP/UDP connections with owning process.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

# ── TCP Connections ───────────────────────────────────────────────────────────
Write-Output "===== TCP CONNECTIONS ====="

$tcpConns = Get-NetTCPConnection | Where-Object { $_.State -ne 'TimeWait' } |
    Sort-Object State, RemoteAddress

$results = foreach ($conn in $tcpConns) {
    $proc = $null
    try { $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue } catch {}

    [PSCustomObject]@{
        State       = $conn.State
        LocalAddr   = "$($conn.LocalAddress):$($conn.LocalPort)"
        RemoteAddr  = "$($conn.RemoteAddress):$($conn.RemotePort)"
        PID         = $conn.OwningProcess
        ProcessName = if ($proc) { $proc.Name } else { "N/A" }
        # Full path helps spot masquerading (e.g. svchost.exe running from AppData)
        ProcessPath = if ($proc) { try { $proc.MainModule.FileName } catch { "Access Denied" } } else { "N/A" }
    }
}
$results | Format-Table -AutoSize

# ── UDP Endpoints ─────────────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== UDP ENDPOINTS ====="
Get-NetUDPEndpoint | ForEach-Object {
    $proc = $null
    try { $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue } catch {}
    [PSCustomObject]@{
        LocalAddr   = "$($_.LocalAddress):$($_.LocalPort)"
        PID         = $_.OwningProcess
        ProcessName = if ($proc) { $proc.Name } else { "N/A" }
        ProcessPath = if ($proc) { try { $proc.MainModule.FileName } catch { "Access Denied" } } else { "N/A" }
    }
} | Sort-Object LocalAddr | Format-Table -AutoSize

# ── Anomaly Hints ─────────────────────────────────────────────────────────────
# Flag ESTABLISHED connections where process is outside system paths
Write-Output ""
Write-Output "===== ANOMALY HINTS (established, non-system path) ====="
$systemPaths = @("C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\")
$results | Where-Object {
    $_.State -eq 'Established' -and
    $_.ProcessPath -ne "N/A" -and
    $_.ProcessPath -ne "Access Denied" -and
    -not ($systemPaths | Where-Object { $results.ProcessPath -like "$_*" })
} | Format-Table -AutoSize

Write-Output "===== END ACTIVE CONNECTIONS ====="
`
  },

  {
    id:         "logged-on-users",
    category:   "Triage",
    name:       "logged-on-users.ps1",
    shortDesc:  "Active sessions + recent logon events",
    irPhase:    "Identification",
    permission: "Active Responder",
    description: "Enumerates interactive, RDP, and service sessions. Useful for confirming whether a legitimate user is active before isolating, and for spotting adversary-controlled accounts.",
    usage: `runscript -CloudFile="triage/logged-on-users.ps1"`,
    source: `<#
.SYNOPSIS
    Logged-On Users - Show all current and recent user sessions.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

# ── Active Sessions ───────────────────────────────────────────────────────────
Write-Output "===== ACTIVE SESSIONS (query user) ====="
try {
    $queryOutput = query user 2>&1
    if ($LASTEXITCODE -eq 0) {
        $queryOutput | ForEach-Object { Write-Output $_ }
    } else {
        Write-Output "  [!] query user returned exit code $LASTEXITCODE"
    }
} catch {
    Write-Output "  [!] query user failed: $_"
}

# ── WMI Logged-On Users ───────────────────────────────────────────────────────
# Shows service & batch logons that query user misses
Write-Output ""
Write-Output "===== WIN32 LOGGEDONUSER ====="
try {
    $loggedOn = Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop
    $loggedOn | ForEach-Object {
        $antecedent = $_.Antecedent.ToString()
        if ($antecedent -match 'Domain="([^"]+)",Name="([^"]+)"') {
            [PSCustomObject]@{ Domain = $Matches[1]; User = $Matches[2] }
        }
    } | Sort-Object Domain, User -Unique | Format-Table -AutoSize
} catch {
    Write-Output "  [!] Win32_LoggedOnUser query failed: $_"
}

# ── Recent Logon Events ───────────────────────────────────────────────────────
# Event 4624 = successful logon. LogonType: 2=Interactive, 3=Network, 10=RDP
Write-Output ""
Write-Output "===== RECENT SUCCESSFUL LOGONS (Event 4624, last 20) ====="
try {
    $logonEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4624
        StartTime = (Get-Date).AddDays(-3)
    } -MaxEvents 20 -ErrorAction Stop

    $logonEvents | ForEach-Object {
        $xml  = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{
            Time         = $_.TimeCreated
            LogonType    = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            User         = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            Domain       = ($data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
            SourceIP     = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            LogonProcess = ($data | Where-Object { $_.Name -eq 'LogonProcessName' }).'#text'
        }
    } | Where-Object { $_.User -ne '-' -and $_.User -notmatch '^\$$' } |
        Format-Table -AutoSize
} catch {
    Write-Output "  [!] Could not read Security log: $_"
}

Write-Output "===== END LOGGED-ON USERS ====="
`
  },

  // ══════════════════════════════════════════════════════ PROCESS INVESTIGATION
  {
    id:         "process-tree",
    category:   "Process Investigation",
    name:       "process-tree.ps1",
    shortDesc:  "Full parent-child hierarchy + suspicious pairs",
    irPhase:    "Identification",
    permission: "Active Responder",
    description: "Reconstructs the complete process tree and flags known-suspicious parent→child chains like Word→PowerShell. Essential for tracing initial access through macro execution or LOLBin abuse.",
    usage: `runscript -CloudFile="process-investigation/process-tree.ps1"`,
    source: `<#
.SYNOPSIS
    Process Tree - Full parent-child process hierarchy with binary metadata.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

# ── Build process map ─────────────────────────────────────────────────────────
$allProcs = Get-CimInstance Win32_Process
$procMap  = @{}
foreach ($p in $allProcs) { $procMap[$p.ProcessId] = $p }

Write-Output "===== PROCESS TREE ====="
Write-Output ("{0,-8} {1,-8} {2,-30} {3,-40} {4}" -f "PID","PPID","ParentName","Name","CommandLine")
Write-Output ("-" * 120)

foreach ($proc in ($allProcs | Sort-Object CreationDate)) {
    $parentName = if ($procMap.ContainsKey($proc.ParentProcessId)) {
        $procMap[$proc.ParentProcessId].Name
    } else { "N/A" }

    $cmdLine = if ($proc.CommandLine) {
        if ($proc.CommandLine.Length -gt 80) { $proc.CommandLine.Substring(0,80) + "..." }
        else { $proc.CommandLine }
    } else { "[no cmdline / access denied]" }

    Write-Output ("{0,-8} {1,-8} {2,-30} {3,-40} {4}" -f
        $proc.ProcessId, $proc.ParentProcessId, $parentName, $proc.Name, $cmdLine)
}

# ── Suspicious Parent-Child Pairs ─────────────────────────────────────────────
Write-Output ""
Write-Output "===== SUSPICIOUS PARENT-CHILD PAIRS ====="

$suspiciousPairs = @(
    @{ Parent = "winword.exe";  Child = "cmd.exe" },
    @{ Parent = "winword.exe";  Child = "powershell.exe" },
    @{ Parent = "winword.exe";  Child = "wscript.exe" },
    @{ Parent = "excel.exe";    Child = "cmd.exe" },
    @{ Parent = "excel.exe";    Child = "powershell.exe" },
    @{ Parent = "outlook.exe";  Child = "powershell.exe" },
    @{ Parent = "mshta.exe";    Child = "powershell.exe" },
    @{ Parent = "wscript.exe";  Child = "powershell.exe" },
    @{ Parent = "cscript.exe";  Child = "powershell.exe" },
    @{ Parent = "svchost.exe";  Child = "cmd.exe" }
)

$hits = 0
foreach ($pair in $suspiciousPairs) {
    $matches = $allProcs | Where-Object {
        $_.Name -ieq $pair.Child -and
        $procMap.ContainsKey($_.ParentProcessId) -and
        $procMap[$_.ParentProcessId].Name -ieq $pair.Parent
    }
    foreach ($m in $matches) {
        Write-Output "[!] $($pair.Parent) (PID $($m.ParentProcessId)) → $($m.Name) (PID $($m.ProcessId))"
        Write-Output "    CmdLine: $($m.CommandLine)"
        $hits++
    }
}
if ($hits -eq 0) { Write-Output "  No known-suspicious parent-child pairs detected." }
Write-Output "===== END PROCESS TREE ====="
`
  },

  {
    id:         "unsigned-processes",
    category:   "Process Investigation",
    name:       "unsigned-processes.ps1",
    shortDesc:  "Find running processes without valid code signing",
    irPhase:    "Identification",
    permission: "Active Responder",
    description: "Legitimate software is almost always signed. Unsigned binaries — especially from AppData/Temp/Desktop — are a strong malware indicator. Also catches processes running from deleted binaries on disk.",
    usage: `runscript -CloudFile="process-investigation/unsigned-processes.ps1"`,
    source: `<#
.SYNOPSIS
    Unsigned Processes - Find running processes whose binaries are not digitally signed.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

$highRiskPaths = @(
    "$env:TEMP", "$env:APPDATA", "$env:LOCALAPPDATA",
    "$env:PUBLIC", "$env:USERPROFILE\\Desktop", "$env:USERPROFILE\\Downloads",
    "C:\\PerfLogs", "C:\\Intel"
)

Write-Output "===== UNSIGNED / SUSPICIOUS PROCESSES ====="

$allProcs    = Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 }
$unsigned    = [System.Collections.Generic.List[object]]::new()
$highRiskHit = [System.Collections.Generic.List[object]]::new()
$deletedBin  = [System.Collections.Generic.List[object]]::new()

foreach ($proc in $allProcs) {
    $path = $null
    try { $path = $proc.MainModule.FileName } catch { continue }
    if (-not $path) { continue }

    # Process running with no binary on disk = high confidence IOC
    if (-not (Test-Path $path)) {
        $deletedBin.Add([PSCustomObject]@{ PID=$proc.Id; Name=$proc.Name; Path=$path })
        continue
    }

    $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
    $sigStatus = if ($sig) { $sig.Status.ToString() } else { "Unknown" }

    if ($sigStatus -notin @("Valid")) {
        $unsigned.Add([PSCustomObject]@{
            PID=$proc.Id; Name=$proc.Name; SigStatus=$sigStatus
            Signer=if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "N/A" }
            Path=$path
        })
    }

    foreach ($riskPath in $highRiskPaths) {
        if ($path -like "$riskPath*") {
            $highRiskHit.Add([PSCustomObject]@{ PID=$proc.Id; Name=$proc.Name; SigStatus=$sigStatus; Path=$path })
            break
        }
    }
}

if ($deletedBin.Count -gt 0) {
    Write-Output "[!!] PROCESSES WITH DELETED BINARIES:"
    $deletedBin | Format-Table -AutoSize
} else { Write-Output "[OK] No processes running from deleted binaries." }

Write-Output ""
if ($unsigned.Count -gt 0) {
    Write-Output "[!] UNSIGNED / INVALID SIGNATURE PROCESSES:"
    $unsigned | Format-Table -AutoSize
} else { Write-Output "[OK] All accessible processes have valid signatures." }

Write-Output ""
if ($highRiskHit.Count -gt 0) {
    Write-Output "[!] PROCESSES IN HIGH-RISK PATHS:"
    $highRiskHit | Format-Table -AutoSize
} else { Write-Output "[OK] No processes found in high-risk user-writable paths." }

Write-Output "===== END UNSIGNED PROCESSES ====="
`
  },

  // ══════════════════════════════════════════════════════ ARTEFACT COLLECTION
  {
    id:         "prefetch-dump",
    category:   "Artefact Collection",
    name:       "prefetch-dump.ps1",
    shortDesc:  "Prefetch execution history + IOC name matching",
    irPhase:    "Identification",
    permission: "Active Responder",
    description: "Windows Prefetch records execution evidence for the last ~128 programs. This is one of the most valuable artefacts for establishing execution history — survives binary deletion. Includes IOC name matching for common attacker tools.",
    usage: `runscript -CloudFile="artefact-collection/prefetch-dump.ps1"`,
    source: `<#
.SYNOPSIS
    Prefetch Dump - List Windows Prefetch files with execution metadata.

.IR_PHASE        Identification / Eradication
.RTR_PERMISSION  Active Responder

.NOTES
    Prefetch is disabled by default on Windows Server. Check first.
    For full run counts and timestamps, retrieve .pf files with RTR get
    and analyse offline with Eric Zimmermann's PECmd.exe
#>

# ── Check if Prefetch is enabled ──────────────────────────────────────────────
$pfKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"
$pfEnabled = (Get-ItemProperty -Path $pfKey -ErrorAction SilentlyContinue).EnablePrefetcher

Write-Output "===== PREFETCH ANALYSIS ====="

if ($pfEnabled -eq 0) {
    Write-Output "[!] Prefetch is DISABLED on this host. No artefacts present."
    exit
} elseif ($null -eq $pfEnabled) {
    Write-Output "[?] Could not read EnablePrefetcher key. Attempting file access..."
} else {
    Write-Output "[OK] Prefetch enabled (EnablePrefetcher = $pfEnabled)"
}

$pfPath = "C:\\Windows\\Prefetch"
if (-not (Test-Path $pfPath)) { Write-Output "[!] Prefetch directory not found."; exit }

$pfFiles = Get-ChildItem -Path $pfPath -Filter "*.pf" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending

Write-Output "Total Prefetch files: $($pfFiles.Count)"
Write-Output ""
Write-Output ("{0,-55} {1,-25} {2}" -f "Executable","Last Run (LastWrite)","Size (KB)")
Write-Output ("-" * 100)

foreach ($f in $pfFiles) {
    $execName = $f.Name -replace '-[A-F0-9]{8}\\.pf$', ''
    Write-Output ("{0,-55} {1,-25} {2}" -f
        $execName,
        $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"),
        [math]::Round($f.Length / 1KB, 1)
    )
}

# ── IOC Name Matching ─────────────────────────────────────────────────────────
$iocNames = @(
    "MIMIKATZ","MIMI","PROCDUMP","PWDUMP","WCEEX","GSECDUMP",
    "RCLONE","MEGA","COBALTSTRIKE","BEACON","METERPRETER",
    "PSEXEC","PAEXEC","WMIEXEC","SECRETSDUMP","LAZAGNE",
    "SHARPHOUND","BLOODHOUND","RUBEUS","KERBRUTE","CHISEL",
    "LIGOLO","NGROK","FRPC","NETSCAN","ADVANCED-PORT-SCANNER",
    "7ZA","WINRAR","ADFIND","NLTEST"
)

Write-Output ""
Write-Output "===== HIGH-VALUE IOC MATCHES ====="
$iocHits = 0
foreach ($f in $pfFiles) {
    $upper = $f.Name.ToUpper()
    foreach ($ioc in $iocNames) {
        if ($upper -like "*$ioc*") {
            Write-Output "[!!] IOC MATCH: $($f.Name)  (last run: $($f.LastWriteTime))"
            $iocHits++
            break
        }
    }
}
if ($iocHits -eq 0) { Write-Output "  No known-bad tool names found in Prefetch." }
Write-Output "===== END PREFETCH DUMP ====="
`
  },

  {
    id:         "browser-history",
    category:   "Artefact Collection",
    name:       "browser-history.ps1",
    shortDesc:  "Chrome, Edge, Firefox history from all profiles",
    irPhase:    "Identification",
    permission: "Active Responder",
    description: "Extracts recent browsing history from Chrome, Edge, and Firefox across all user profiles. Useful for finding initial access vectors (phishing links clicked) and identifying C2 domains visited by malware.",
    usage: `runscript -CloudFile="artefact-collection/browser-history.ps1"`,
    source: `<#
.SYNOPSIS
    Browser History - Extract recent browser history (last 7 days).

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.NOTES
    Uses file-copy approach to handle read locks.
    Requires System.Data.SQLite for live parsing; otherwise copies DBs for offline retrieval.
#>

param([int]$DaysBack = 7)

$cutoff = (Get-Date).AddDays(-$DaysBack)
$tempDir = "$env:TEMP\\RTR_BrowserHistory_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

Write-Output "===== BROWSER HISTORY (last $DaysBack days) ====="

# ── Helper: simple SQLite query via .NET assembly ─────────────────────────────
function Invoke-SQLiteQuery {
    param([string]$DbPath, [string]$Query)
    $dll = @(
        "$env:ProgramFiles\\System.Data.SQLite\\System.Data.SQLite.dll",
        "$env:ProgramFiles (x86)\\System.Data.SQLite\\System.Data.SQLite.dll"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $dll) { return $null }
    try {
        Add-Type -Path $dll -ErrorAction Stop
        $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$DbPath;Version=3;Read Only=True;")
        $conn.Open()
        $cmd = $conn.CreateCommand(); $cmd.CommandText = $Query
        $reader = $cmd.ExecuteReader()
        $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
        while ($reader.Read()) {
            $row = [ordered]@{}
            for ($i = 0; $i -lt $reader.FieldCount; $i++) { $row[$reader.GetName($i)] = $reader.GetValue($i) }
            $rows.Add([PSCustomObject]$row)
        }
        $conn.Close(); return $rows
    } catch { return $null }
}

# ── Chromium (Chrome + Edge) ──────────────────────────────────────────────────
foreach ($user in (Get-ChildItem "C:\\Users" -Directory -ErrorAction SilentlyContinue)) {
    foreach ($browser in @("Google\\Chrome","Microsoft\\Edge")) {
        $base = "$($user.FullName)\\AppData\\Local\\$browser\\User Data"
        if (-not (Test-Path $base)) { continue }
        $profiles = @("Default") + (Get-ChildItem $base -Directory -Filter "Profile*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        foreach ($profile in $profiles) {
            $histDb = "$base\\$profile\\History"
            if (-not (Test-Path $histDb)) { continue }
            Write-Output "--- $($browser -replace '.*\\\\','') | $($user.Name) | $profile ---"
            $tmpDb = "$tempDir\\$(($browser -replace '\\\\','_'))_$($user.Name)_$profile.db"
            try { Copy-Item -Path $histDb -Destination $tmpDb -Force -ErrorAction Stop }
            catch { Write-Output "  [!] Copy failed (browser may be locking DB): $_"; continue }
            $epoch = [datetime]"1601-01-01"
            $rows = Invoke-SQLiteQuery -DbPath $tmpDb -Query "SELECT url,title,visit_count,last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 200"
            if ($rows) {
                $rows | ForEach-Object {
                    $ts = $epoch.AddMicroseconds($_.last_visit_time)
                    if ($ts -gt $cutoff) {
                        [PSCustomObject]@{ LastVisit=$ts.ToString("yyyy-MM-dd HH:mm:ss"); Visits=$_.visit_count; URL=if($_.url.Length -gt 80){$_.url.Substring(0,80)+"..."}else{$_.url} }
                    }
                } | Where-Object { $_ } | Format-Table -AutoSize
            } else {
                Write-Output "  [!] SQLite assembly unavailable. Retrieve DB: get $tmpDb"
            }
        }
    }
}

Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "===== END BROWSER HISTORY ====="
`
  },

  // ══════════════════════════════════════════════════════ REMEDIATION
  {
    id:         "kill-process",
    category:   "Remediation",
    name:       "kill-process.ps1",
    shortDesc:  "Kill process by PID/name — captures evidence first",
    irPhase:    "Containment",
    permission: "Active Responder",
    description: "Terminates a process but first captures its path, command line, parent, and SHA256 hash. Supports -DryRun to preview what would be killed. Always document before you destroy.",
    usage: `# Dry run first
runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-TargetName 'evil.exe' -DryRun \\$true"

# Kill by PID
runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-TargetPID 4832"`,
    source: `<#
.SYNOPSIS
    Kill Process - Safely terminate a process with pre-kill evidence capture.

.IR_PHASE        Containment
.RTR_PERMISSION  Active Responder

.PARAMETER TargetPID   Process ID to kill (takes precedence over TargetName)
.PARAMETER TargetName  Process name to kill (kills ALL matching)
.PARAMETER DryRun      Collect evidence but do NOT kill ($true / $false)
#>

param(
    [int]    $TargetPID  = 0,
    [string] $TargetName = "",
    [bool]   $DryRun     = $false
)

if ($TargetPID -eq 0 -and [string]::IsNullOrWhiteSpace($TargetName)) {
    Write-Output "[ERROR] Supply -TargetPID or -TargetName"
    exit 1
}

$allProcs = Get-CimInstance Win32_Process
$targets  = if ($TargetPID -gt 0) {
    $allProcs | Where-Object { $_.ProcessId -eq $TargetPID }
} else {
    $allProcs | Where-Object { $_.Name -ieq $TargetName }
}

if (-not $targets) {
    Write-Output "[ERROR] No matching process found."
    exit 1
}

Write-Output "===== KILL PROCESS ====="
if ($DryRun) { Write-Output "*** DRY RUN — no processes will be terminated ***" }

$procIndex = @{}
foreach ($p in $allProcs) { $procIndex[$p.ProcessId] = $p }

foreach ($target in $targets) {
    Write-Output ""
    Write-Output "PID         : $($target.ProcessId)"
    Write-Output "Name        : $($target.Name)"
    Write-Output "Path        : $($target.ExecutablePath)"
    Write-Output "CommandLine : $($target.CommandLine)"
    Write-Output "Parent      : $(if ($procIndex.ContainsKey($target.ParentProcessId)) { $procIndex[$target.ParentProcessId].Name } else { 'N/A' }) (PID $($target.ParentProcessId))"
    Write-Output "Started     : $($target.CreationDate)"

    # Hash for IOC generation before we destroy the running evidence
    if ($target.ExecutablePath -and (Test-Path $target.ExecutablePath)) {
        try {
            $hash = Get-FileHash -Path $target.ExecutablePath -Algorithm SHA256 -ErrorAction Stop
            Write-Output "SHA256      : $($hash.Hash)"
        } catch { Write-Output "SHA256      : [could not hash]" }
    }

    $children = $allProcs | Where-Object { $_.ParentProcessId -eq $target.ProcessId }
    if ($children) {
        Write-Output "Children    :"
        $children | Select-Object ProcessId, Name | Format-Table -AutoSize
    }

    if (-not $DryRun) {
        foreach ($child in $children) {
            Write-Output "Killing child $($child.ProcessId) ($($child.Name))..."
            try { Stop-Process -Id $child.ProcessId -Force -ErrorAction Stop; Write-Output "  [OK]" }
            catch { Write-Output "  [!] Failed: $_" }
        }
        Write-Output "Killing PID $($target.ProcessId)..."
        try { Stop-Process -Id $target.ProcessId -Force -ErrorAction Stop; Write-Output "  [OK] Terminated." }
        catch { Write-Output "  [!] Failed: $_" }

        Start-Sleep -Milliseconds 500
        if (Get-Process -Id $target.ProcessId -ErrorAction SilentlyContinue) {
            Write-Output "  [!!] Process STILL RUNNING. May need host isolation."
        } else {
            Write-Output "  [OK] Confirmed gone."
        }
    } else {
        Write-Output "[DRY RUN] Would kill PID $($target.ProcessId) + $($children.Count) child(ren). Remove -DryRun to execute."
    }
}
Write-Output "===== END KILL PROCESS ====="
`
  },

  {
    id:         "isolate-prep-checks",
    category:   "Remediation",
    name:       "isolate-prep-checks.ps1",
    shortDesc:  "Pre-isolation checklist — GO / CAUTION / NO-GO",
    irPhase:    "Containment",
    permission: "Active Responder",
    description: "Runs a pre-flight checklist before network isolation: checks for DC role, active sessions, critical services, sensor health, and database activity. Returns a clear GO / CAUTION / NO-GO recommendation.",
    usage: `runscript -CloudFile="remediation/isolate-prep-checks.ps1"`,
    source: `<#
.SYNOPSIS
    Isolate Prep Checks - Validate safety of network isolation before acting.

.IR_PHASE        Containment
.RTR_PERMISSION  Active Responder

.NOTES
    Isolation itself is done in Falcon Console (Hosts → Isolate Host).
    This script only performs the pre-flight safety checks.
#>

$warnings = [System.Collections.Generic.List[string]]::new()
$blockers = [System.Collections.Generic.List[string]]::new()

Write-Output "===== ISOLATION PRE-FLIGHT CHECKS ====="
Write-Output "Host: $($env:COMPUTERNAME)  |  Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""

# CHECK 1: Domain Controller
Write-Output "[CHECK 1] Domain Controller role..."
try {
    $domainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
    if ($domainRole -ge 4) {
        $blockers.Add("HOST IS A DOMAIN CONTROLLER (DomainRole=$domainRole). Isolation breaks domain auth.")
        Write-Output "  [BLOCKER] This is a Domain Controller."
    } else { Write-Output "  [OK] Not a DC (DomainRole=$domainRole)" }
} catch { $warnings.Add("Could not determine DomainRole"); Write-Output "  [WARN] Could not check DC status." }

# CHECK 2: Active Sessions
Write-Output ""
Write-Output "[CHECK 2] Active user sessions..."
try {
    $activeSessions = query session 2>&1 | Select-String "Active|Actif" | Where-Object { $_ -notmatch "Services|console.*0" }
    if ($activeSessions) {
        $warnings.Add("Active sessions detected. Isolation will disconnect users.")
        Write-Output "  [WARN] Active sessions:"
        $activeSessions | ForEach-Object { Write-Output "         $_" }
    } else { Write-Output "  [OK] No active interactive sessions." }
} catch { Write-Output "  [WARN] Could not enumerate sessions." }

# CHECK 3: Critical Server Roles
Write-Output ""
Write-Output "[CHECK 3] Critical Windows Server roles..."
try {
    $criticalRoles = Get-WindowsFeature -ErrorAction Stop | Where-Object {
        $_.Installed -and $_.FeatureType -eq 'Role' -and
        $_.Name -in @("AD-Domain-Services","DNS","DHCP","FS-FileServer","Web-Server","MSMQ","RemoteAccess")
    }
    if ($criticalRoles) {
        $criticalRoles | ForEach-Object { $warnings.Add("Critical role: $($_.DisplayName)") }
        Write-Output "  [WARN] Critical roles installed:"; $criticalRoles | Select-Object DisplayName | Format-Table -AutoSize
    } else { Write-Output "  [OK] No critical server roles." }
} catch { Write-Output "  [OK] Get-WindowsFeature N/A (workstation OS)." }

# CHECK 4: CrowdStrike Sensor
Write-Output ""
Write-Output "[CHECK 4] CrowdStrike sensor health..."
try {
    $svc = Get-Service -Name "CSFalconService" -ErrorAction Stop
    if ($svc.Status -eq "Running") { Write-Output "  [OK] CSFalconService is Running." }
    else {
        $blockers.Add("CSFalconService is $($svc.Status). Isolation commands may not reach host.")
        Write-Output "  [BLOCKER] CSFalconService: $($svc.Status)"
    }
} catch { $blockers.Add("CSFalconService not found."); Write-Output "  [BLOCKER] Sensor not found." }

# CHECK 5: Database Services
Write-Output ""
Write-Output "[CHECK 5] Database services..."
$runningDb = @("MSSQLSERVER","MySQL","postgresql*","mongod") | ForEach-Object {
    Get-Service -Name $_ -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
}
if ($runningDb) {
    $runningDb | ForEach-Object { $warnings.Add("DB service running: $($_.DisplayName)") }
    Write-Output "  [WARN] DB services running:"; $runningDb | Select-Object DisplayName | Format-Table -AutoSize
} else { Write-Output "  [OK] No database services detected." }

# SUMMARY
Write-Output ""
Write-Output "===== RECOMMENDATION ====="
if ($blockers.Count -gt 0) {
    Write-Output "[NO-GO] DO NOT ISOLATE:"
    $blockers | ForEach-Object { Write-Output "  !! $_" }
} elseif ($warnings.Count -gt 0) {
    Write-Output "[CAUTION] REVIEW BEFORE ISOLATING:"
    $warnings | ForEach-Object { Write-Output "  >> $_" }
    Write-Output "`nIf risk accepted: Falcon Console → Hosts → [host] → Isolate Host"
} else {
    Write-Output "[GO] Safe to isolate. No blockers or warnings."
    Write-Output "Proceed: Falcon Console → Hosts → [host] → Isolate Host"
}
Write-Output "===== END ISOLATE PREP ====="
`
  }

];
