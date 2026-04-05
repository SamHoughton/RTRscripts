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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "host-summary.ps1",
    shortDesc:  "OS, uptime, local admins, AV, patches",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1082","T1016","T1033"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "active-connections.ps1",
    shortDesc:  "TCP/UDP sockets mapped to owning process",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1049","T1071"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "logged-on-users.ps1",
    shortDesc:  "Active sessions + recent logon events",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1033","T1087","T1078"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "process-tree.ps1",
    shortDesc:  "Full parent-child hierarchy + suspicious pairs",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1057","T1055","T1036"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "unsigned-processes.ps1",
    shortDesc:  "Find running processes without valid code signing",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1036","T1055","T1574"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "prefetch-dump.ps1",
    shortDesc:  "Prefetch execution history + IOC name matching",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1083","T1059"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "browser-history.ps1",
    shortDesc:  "Chrome, Edge, Firefox history from all profiles",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1217","T1083"],
    description: "Extracts recent browsing history from Chrome, Edge, and Firefox across all user profiles. Useful for finding initial access vectors (phishing links clicked) and identifying C2 domains visited by malware.",
    params: [
      { name: "DaysBack", type: "number", placeholder: "7", hint: "How many days of history to retrieve (default: 7)", required: false }
    ],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "kill-process.ps1",
    shortDesc:  "Kill process by PID/name — captures evidence first",
    irPhase:    "Containment",
    permission: "Active Responder",
    mitre:      ["T1489"],
    description: "Terminates a process but first captures its path, command line, parent, and SHA256 hash. Supports -DryRun to preview what would be killed. Always document before you destroy.",
    params: [
      { name: "TargetPID",  type: "number",  placeholder: "e.g. 4832",       hint: "Process ID (takes precedence over name)",     required: false },
      { name: "TargetName", type: "string",  placeholder: "e.g. malware.exe", hint: "Process name — kills ALL matching processes", required: false },
      { name: "DryRun",     type: "boolean", default: true,                   hint: "Preview impact without terminating anything" }
    ],
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

  // ══════════════════════════════════════════════════════ PERSISTENCE
  {
    id:         "scheduled-tasks",
    category:   "Persistence",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "scheduled-tasks.ps1",
    shortDesc:  "All scheduled tasks with encoded/LOLBin/user-path indicators",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1053.005"],
    description: "Enumerates every scheduled task and flags entries with encoded PowerShell commands, LOLBin usage (mshta, wscript, rundll32), tasks running from user-writable paths, or tasks with no author. Adversaries frequently use scheduled tasks for persistence and lateral movement.",
    usage: `runscript -CloudFile="persistence/scheduled-tasks.ps1"`,
    source: `<#
.SYNOPSIS
    Scheduled Tasks - Enumerate all tasks with persistence indicators.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== SCHEDULED TASKS ANALYSIS ====="

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
$highRiskPaths = @(
    $env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:PUBLIC,
    "C:\\PerfLogs", "C:\\Intel", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu"
)

$allTasks  = [System.Collections.Generic.List[object]]::new()
$suspicious = [System.Collections.Generic.List[object]]::new()

foreach ($task in $tasks) {
    $actions = $task.Actions | ForEach-Object {
        $cls = $_.CimClass.CimClassName
        if ($cls -eq "MSFT_TaskExecAction")  { "$($_.Execute) $($_.Arguments)".Trim() }
        if ($cls -eq "MSFT_TaskComHandlerAction") { "COM: $($_.ClassId)" }
    }
    $actionStr = ($actions | Where-Object { $_ }) -join " | "

    $allTasks.Add([PSCustomObject]@{
        Name    = $task.TaskName
        Path    = $task.TaskPath
        State   = $task.State
        Author  = if ($task.Author) { $task.Author } else { "[none]" }
        Action  = if ($actionStr.Length -gt 100) { $actionStr.Substring(0,100)+"..." } else { $actionStr }
    })

    $reason = [System.Collections.Generic.List[string]]::new()
    if ($actionStr -match "-[Ee]nc(odedcommand)?[\s=]+[A-Za-z0-9+/=]{20}") {
        $reason.Add("Encoded PS command")
    }
    if ($actionStr -match "wscript|cscript|mshta|regsvr32\.exe|rundll32\.exe") {
        $reason.Add("LOLBin")
    }
    foreach ($rp in $highRiskPaths) {
        if ($rp -and $actionStr -like "$rp*") { $reason.Add("User-writable path"); break }
    }
    if (-not $task.Author -or $task.Author -eq "") {
        $reason.Add("No author")
    }
    if ($actionStr -match "http://|ftp://|\\\\[0-9]{1,3}\.[0-9]{1,3}") {
        $reason.Add("Network path/URL in action")
    }
    if ($reason.Count -gt 0) {
        $suspicious.Add([PSCustomObject]@{
            Name   = $task.TaskName
            Reason = $reason -join ", "
            Author = if ($task.Author) { $task.Author } else { "[none]" }
            Action = $actionStr
        })
    }
}

Write-Output "Total scheduled tasks: $($allTasks.Count)"
Write-Output ""
Write-Output "===== ALL TASKS ====="
$allTasks | Format-Table -AutoSize

Write-Output ""
Write-Output "===== SUSPICIOUS INDICATORS ($($suspicious.Count) found) ====="
if ($suspicious.Count -gt 0) {
    $suspicious | Format-Table -AutoSize
} else {
    Write-Output "  No suspicious scheduled tasks detected."
}
Write-Output "===== END SCHEDULED TASKS ====="
`
  },

  {
    id:         "startup-entries",
    category:   "Persistence",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "startup-entries.ps1",
    shortDesc:  "Run keys, startup folders, IFEO, and autostart services",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1547.001","T1543.003"],
    description: "Checks all common autorun locations: HKLM/HKCU Run and RunOnce keys, per-user and all-users startup folders, Image File Execution Options (debugger hijacking), and auto-start services pointing to unusual paths. Covers the most common Windows persistence mechanisms.",
    usage: `runscript -CloudFile="persistence/startup-entries.ps1"`,
    source: `<#
.SYNOPSIS
    Startup Entries - Enumerate Run keys, startup folders, IFEO, and autostart services.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== STARTUP ENTRY ANALYSIS ====="

$systemPaths = @("C:\\Windows\\","C:\\Program Files\\","C:\\Program Files (x86)\\")
function Test-SuspiciousPath([string]$path) {
    if (-not $path) { return $false }
    $exe = ($path -split '"| -')[0].Trim().Trim('"')
    foreach ($sp in $systemPaths) { if ($exe -like "$sp*") { return $false } }
    return $true
}

# ── Run / RunOnce keys ─────────────────────────────────────────────────────
$runKeys = @(
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
)

Write-Output "===== RUN KEYS ====="
foreach ($key in $runKeys) {
    if (-not (Test-Path $key)) { continue }
    Write-Output "--- $key ---"
    $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    $props.PSObject.Properties |
        Where-Object { $_.Name -notmatch "^PS" } |
        ForEach-Object {
            $flag = if (Test-SuspiciousPath $_.Value) { "[!]" } else { "   " }
            Write-Output ("  $flag {0,-35} = {1}" -f $_.Name, $_.Value)
        }
}

# ── Startup folders ────────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== STARTUP FOLDERS ====="
$startupFolders = @(
    "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"
)
foreach ($folder in $startupFolders) {
    Write-Output "--- $folder ---"
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -ErrorAction SilentlyContinue |
            Select-Object Name, LastWriteTime, Length | Format-Table -AutoSize
    } else {
        Write-Output "  [not found]"
    }
}

# ── Image File Execution Options (debugger hijacking) ─────────────────────
Write-Output ""
Write-Output "===== IMAGE FILE EXECUTION OPTIONS (IFEO) ====="
$ifeoKey = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
if (Test-Path $ifeoKey) {
    Get-ChildItem -Path $ifeoKey -ErrorAction SilentlyContinue | ForEach-Object {
        $debugger = (Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            Write-Output "  [!] $($_.PSChildName) → Debugger: $debugger"
        }
    }
    Write-Output "  (Only entries with a Debugger value are shown)"
} else {
    Write-Output "  IFEO key not found."
}

# ── Auto-start services from non-standard paths ───────────────────────────
Write-Output ""
Write-Output "===== SUSPICIOUS AUTO-START SERVICES ====="
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
    Where-Object {
        $_.StartMode -in @("Auto","Automatic") -and
        $_.PathName -and
        (Test-SuspiciousPath $_.PathName)
    } |
    Select-Object Name, DisplayName, State, StartMode, PathName |
    Format-Table -AutoSize

Write-Output "===== END STARTUP ENTRIES ====="
`
  },

  {
    id:         "wmi-subscriptions",
    category:   "Persistence",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "wmi-subscriptions.ps1",
    shortDesc:  "WMI event filters, consumers, and bindings",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1546.003"],
    description: "Enumerates all WMI permanent event subscriptions (filters, consumers, and filter-to-consumer bindings). WMI persistence is fileless, survives reboots, and is commonly missed by AV. Any non-Microsoft or unlabelled subscription should be investigated immediately.",
    usage: `runscript -CloudFile="persistence/wmi-subscriptions.ps1"`,
    source: `<#
.SYNOPSIS
    WMI Subscriptions - Enumerate all permanent WMI event subscriptions.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.NOTES
    Legitimate WMI subscriptions exist (e.g. SCM, antivirus), but unknown
    entries — especially CommandLineEventConsumers — are high-confidence IOCs.
#>

Write-Output "===== WMI PERMANENT EVENT SUBSCRIPTIONS ====="

$ns = "root\\subscription"

# ── Event Filters ──────────────────────────────────────────────────────────
Write-Output "===== EVENT FILTERS ====="
try {
    $filters = Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop
    if ($filters) {
        $filters | Select-Object Name, QueryLanguage, Query | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "  None found."
    }
} catch { Write-Output "  [!] Error enumerating filters: $_" }

# ── Event Consumers ────────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== EVENT CONSUMERS ====="
$consumerClasses = @("CommandLineEventConsumer","ActiveScriptEventConsumer","LogFileEventConsumer","NtEventLogEventConsumer","SMTPEventConsumer")
foreach ($cls in $consumerClasses) {
    try {
        $consumers = Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction Stop
        if ($consumers) {
            Write-Output "--- $cls ---"
            # CommandLine and ScriptText are the dangerous ones
            $consumers | Select-Object Name, CommandLineTemplate, ScriptText, ExecutablePath | Format-Table -AutoSize -Wrap
        }
    } catch {}
}

# ── Filter-to-Consumer Bindings ────────────────────────────────────────────
Write-Output ""
Write-Output "===== FILTER-TO-CONSUMER BINDINGS ====="
try {
    $bindings = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop
    if ($bindings) {
        $bindings | ForEach-Object {
            $filterRef   = $_.Filter.ToString()   -replace '.*Name="([^"]+)".*','$1'
            $consumerRef = $_.Consumer.ToString()  -replace '.*Name="([^"]+)".*','$1'
            [PSCustomObject]@{ Filter = $filterRef; Consumer = $consumerRef }
        } | Format-Table -AutoSize
    } else {
        Write-Output "  No bindings found."
    }
} catch { Write-Output "  [!] Error enumerating bindings: $_" }

Write-Output ""
Write-Output "NOTE: Legitimate Windows entries include SCM Event Log Consumer."
Write-Output "      Flag anything referencing cmd.exe, powershell.exe, scripts,"
Write-Output "      or unknown consumers not tied to a known security product."
Write-Output "===== END WMI SUBSCRIPTIONS ====="
`
  },

  // ══════════════════════════════════════════════════════ LATERAL MOVEMENT
  {
    id:         "smb-sessions",
    category:   "Lateral Movement",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "smb-sessions.ps1",
    shortDesc:  "Active SMB sessions, open files, and shares",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1021.002","T1135"],
    description: "Enumerates inbound SMB sessions to this host, currently open files via SMB, and all SMB shares. Useful for detecting lateral movement via pass-the-hash, PsExec-style execution, and identifying what an attacker is accessing via admin shares.",
    usage: `runscript -CloudFile="lateral-movement/smb-sessions.ps1"`,
    source: `<#
.SYNOPSIS
    SMB Sessions - Enumerate active SMB sessions, open files, and shares.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== SMB SESSION ANALYSIS ====="
Write-Output "Host: $($env:COMPUTERNAME)  |  Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# ── Active SMB Sessions ────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== ACTIVE SMB SESSIONS (net session) ====="
try {
    $netSessions = net session 2>&1
    if ($LASTEXITCODE -eq 0 -and $netSessions -match "\\\\") {
        $netSessions | ForEach-Object { Write-Output "  $_" }
    } elseif ($netSessions -match "no entries") {
        Write-Output "  No active SMB sessions."
    } else {
        Write-Output "  $netSessions"
    }
} catch { Write-Output "  [!] net session failed: $_" }

# ── SMB Sessions via CIM ───────────────────────────────────────────────────
Write-Output ""
Write-Output "===== SMB SESSIONS (Win32_ServerConnection) ====="
try {
    $smbSessions = Get-CimInstance -ClassName Win32_ServerConnection -ErrorAction Stop
    if ($smbSessions) {
        $smbSessions | Select-Object ComputerName, UserName, NumberOfFiles, ActiveTime |
            Sort-Object ActiveTime -Descending | Format-Table -AutoSize
    } else {
        Write-Output "  No Win32_ServerConnection entries."
    }
} catch { Write-Output "  [!] Win32_ServerConnection query failed: $_" }

# ── Open Files ────────────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== OPEN FILES VIA SMB ====="
try {
    $openFiles = Get-SmbOpenFile -ErrorAction Stop
    if ($openFiles) {
        $openFiles | Select-Object FileId, ClientUserName, ClientComputerName, Path |
            Sort-Object ClientComputerName | Format-Table -AutoSize
    } else {
        Write-Output "  No open SMB files."
    }
} catch {
    Write-Output "  [!] Get-SmbOpenFile failed — attempting net file..."
    net file 2>&1 | ForEach-Object { Write-Output "  $_" }
}

# ── SMB Shares ────────────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== SMB SHARES ====="
try {
    Get-SmbShare -ErrorAction Stop |
        Select-Object Name, Path, Description, CurrentUsers |
        Format-Table -AutoSize
} catch {
    net share 2>&1 | ForEach-Object { Write-Output "  $_" }
}

# ── Admin Share Indicators ────────────────────────────────────────────────
Write-Output ""
Write-Output "===== ADMIN SHARE USAGE INDICATORS (Security log, Event 5140, last 20) ====="
try {
    $shareEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 5140
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 20 -ErrorAction Stop

    $shareEvents | ForEach-Object {
        $xml  = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        [PSCustomObject]@{
            Time         = $_.TimeCreated
            SubjectUser  = ($data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            SourceIP     = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            ShareName    = ($data | Where-Object { $_.Name -eq 'ShareName' }).'#text'
            RelativePath = ($data | Where-Object { $_.Name -eq 'RelativeTargetName' }).'#text'
        }
    } | Format-Table -AutoSize
} catch {
    Write-Output "  [!] Could not read Security log (may require elevated privileges): $_"
}

Write-Output "===== END SMB SESSIONS ====="
`
  },

  {
    id:         "psremoting-activity",
    category:   "Lateral Movement",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "psremoting-activity.ps1",
    shortDesc:  "WinRM status, remote sessions, and PS remoting events",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1021.006","T1059.001"],
    description: "Checks WinRM service state, enumerates active PowerShell remoting sessions, and pulls recent PS remoting events (4103/4104) and WS-Management operational log entries. Helps identify inbound lateral movement via Enter-PSSession, Invoke-Command, or attacker tooling like Evil-WinRM.",
    usage: `runscript -CloudFile="lateral-movement/psremoting-activity.ps1"`,
    source: `<#
.SYNOPSIS
    PSRemoting Activity - Audit WinRM, active remote sessions, and remoting events.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== POWERSHELL REMOTING AUDIT ====="
Write-Output "Host: $($env:COMPUTERNAME)  |  Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# ── WinRM Service State ────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== WINRM SERVICE ====="
$winrm = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
if ($winrm) {
    Write-Output "  Status   : $($winrm.Status)"
    Write-Output "  StartType: $($winrm.StartType)"
    if ($winrm.Status -eq "Running") {
        Write-Output "  [!] WinRM is running — PS Remoting is available inbound"
    }
} else {
    Write-Output "  WinRM service not found."
}

# ── WinRM Listener Config ─────────────────────────────────────────────────
Write-Output ""
Write-Output "===== WINRM LISTENERS ====="
try {
    $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop
    $listeners | ForEach-Object {
        $name = $_.Name
        $props = Get-ChildItem $_.PSPath | Select-Object Name, Value
        Write-Output "  Listener: $name"
        $props | ForEach-Object { Write-Output "    $($_.Name) = $($_.Value)" }
    }
} catch {
    Write-Output "  [!] Could not enumerate WinRM listeners: $_"
}

# ── Active PS Sessions ────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== ACTIVE POWERSHELL REMOTE SESSIONS ====="
try {
    $sessions = Get-PSSession -ErrorAction Stop
    if ($sessions) {
        $sessions | Select-Object Id, Name, ComputerName, State, ConfigurationName | Format-Table -AutoSize
    } else {
        Write-Output "  No active PS remote sessions from this host."
    }
} catch { Write-Output "  [!] Get-PSSession failed: $_" }

# ── PS Remoting Events (4103 / 4104 — Verbose + Script Block logging) ─────
Write-Output ""
Write-Output "===== POWERSHELL SCRIPT BLOCK EVENTS (4104, last 10) ====="
try {
    $sbEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-PowerShell/Operational"
        Id        = 4104
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 10 -ErrorAction Stop
    $sbEvents | ForEach-Object {
        Write-Output "  $($_.TimeCreated)  |  $($_.Message.Substring(0, [Math]::Min(200,$_.Message.Length)))..."
    }
} catch { Write-Output "  [!] No PS 4104 events (Script Block logging may be disabled)" }

# ── WS-Management Operational ─────────────────────────────────────────────
Write-Output ""
Write-Output "===== WS-MANAGEMENT OPERATIONAL (last 10 connection events) ====="
try {
    $wsmEvents = Get-WinEvent -LogName "Microsoft-Windows-WinRM/Operational" -MaxEvents 20 -ErrorAction Stop |
        Where-Object { $_.Id -in @(6, 8, 11, 12, 169) } |
        Select-Object -First 10
    $wsmEvents | ForEach-Object {
        Write-Output "  $($_.TimeCreated)  ID=$($_.Id)  $($_.Message.Substring(0,[Math]::Min(120,$_.Message.Length)))"
    }
} catch { Write-Output "  [!] WinRM Operational log unavailable: $_" }

Write-Output "===== END PSREMOTING ACTIVITY ====="
`
  },

  // ══════════════════════════════════════════════════════ CREDENTIAL INDICATORS
  {
    id:         "lsass-access",
    category:   "Credential Indicators",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "lsass-access.ps1",
    shortDesc:  "LSASS handle access events and memory dump indicators",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1003.001"],
    description: "Looks for indicators of credential theft targeting LSASS: processes with open handles to lsass.exe (via event 4656), recent lsass.dmp files, and known credential dumping tool signatures in running processes and prefetch. The most common first step in any privilege escalation chain.",
    usage: `runscript -CloudFile="credential-indicators/lsass-access.ps1"`,
    source: `<#
.SYNOPSIS
    LSASS Access - Detect credential dumping indicators targeting LSASS.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.NOTES
    Event 4656 requires "Audit Object Access" → "Process" to be enabled.
    If events are absent, check audit policy with: auditpol /get /category:*
#>

Write-Output "===== LSASS ACCESS INDICATORS ====="

# ── Current LSASS Process Info ────────────────────────────────────────────
Write-Output "===== LSASS PROCESS ====="
$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if ($lsass) {
    Write-Output "  PID  : $($lsass.Id)"
    Write-Output "  Path : $($lsass.MainModule.FileName)"
    Write-Output "  Start: $($lsass.StartTime)"
    Write-Output "  CPU  : $([math]::Round($lsass.CPU, 2))s total"
    # Unexpectedly high CPU from lsass = dumping in progress
    if ($lsass.CPU -gt 30) {
        Write-Output "  [!] LSASS CPU is elevated — possible active dumping"
    }
} else {
    Write-Output "  [!!] lsass.exe NOT FOUND — unexpected"
}

# ── Dump files near lsass ─────────────────────────────────────────────────
Write-Output ""
Write-Output "===== LSASS DUMP FILES ====="
$dumpSearchPaths = @(
    "C:\\Windows\\Temp", "C:\\Temp", "$env:TEMP", "$env:USERPROFILE",
    "$env:USERPROFILE\\Desktop", "$env:USERPROFILE\\Downloads",
    "C:\\PerfLogs", "C:\\ProgramData"
)
$dumpFound = 0
foreach ($searchPath in $dumpSearchPaths) {
    if (-not (Test-Path $searchPath)) { continue }
    $dumps = Get-ChildItem -Path $searchPath -Recurse -Depth 2 -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Extension -eq ".dmp" -or $_.Name -match "lsass|memory\.dmp|minidump") -and
            $_.Length -gt 1MB
        }
    foreach ($d in $dumps) {
        Write-Output "  [!!] $($d.FullName)  [$([math]::Round($d.Length/1MB,1)) MB]  Modified: $($d.LastWriteTime)"
        $dumpFound++
    }
}
if ($dumpFound -eq 0) { Write-Output "  No LSASS dump files found in common locations." }

# ── Known Credential Dump Tools in Running Processes ─────────────────────
Write-Output ""
Write-Output "===== RUNNING PROCESSES — KNOWN DUMP TOOL NAMES ====="
$dumpToolNames = @("mimikatz","mimi32","mimi64","procdump","wce","fgdump","pwdump",
    "gsecdump","lsassy","pypykatz","nanodump","handlekatz","ppldump",
    "dumpert","rdrleakdiag","sqldumper")
$found = 0
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    foreach ($name in $dumpToolNames) {
        if ($_.Name -like "*$name*" -or ($_.MainModule.FileName -and $_.MainModule.FileName -like "*$name*")) {
            Write-Output "  [!!] MATCH: $($_.Name) (PID $($_.Id)) Path: $($_.MainModule.FileName)"
            $found++
        }
    }
}
if ($found -eq 0) { Write-Output "  No known credential dump tools found in running processes." }

# ── Audit Policy Check ────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== AUDIT POLICY (Process access auditing) ====="
$auditOut = auditpol /get /subcategory:"Handle Manipulation" 2>&1
Write-Output "  $($auditOut -join "\`n  ")"

# ── Recent LSASS Handle Access Events (4656) ──────────────────────────────
Write-Output ""
Write-Output "===== LSASS HANDLE ACCESS EVENTS (4656, last 20, past 24h) ====="
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4656
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 50 -ErrorAction Stop |
    Where-Object {
        $_.Message -match "lsass"
    } | Select-Object -First 20

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
`
  },

  {
    id:         "credential-files",
    category:   "Credential Indicators",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "credential-files.ps1",
    shortDesc:  "Hunt for SAM copies, NTDS.dit, and credential dump output",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1552","T1552.001"],
    description: "Searches for copies of the SAM registry hive, NTDS.dit, credential dump output files (commonly named passwords.txt, hashes.txt, etc.), and credential vault artefacts outside their expected system locations. A copied SAM or NTDS is definitive proof of offline credential extraction.",
    usage: `runscript -CloudFile="credential-indicators/credential-files.ps1"`,
    source: `<#
.SYNOPSIS
    Credential Files - Hunt for SAM copies, NTDS.dit, and dump output files.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== CREDENTIAL FILE HUNT ====="

$stagingPaths = @(
    "C:\\Windows\\Temp","C:\\Temp","$env:TEMP","$env:APPDATA",
    "$env:LOCALAPPDATA","$env:USERPROFILE","C:\\PerfLogs","C:\\ProgramData","C:\\Users"
)

# ── SAM Hive Copies ───────────────────────────────────────────────────────
Write-Output "===== SAM HIVE COPIES ====="
Write-Output "(Legitimate SAM lives only at C:\\Windows\\System32\\config\\SAM)"
$samFound = 0
foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 3 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -ieq "SAM" -and
            $_.FullName -notmatch "\\System32\\config\\"
        } | ForEach-Object {
            Write-Output "  [!!] $($_.FullName)  [$([math]::Round($_.Length/1KB,1)) KB]  Modified: $($_.LastWriteTime)"
            $samFound++
        }
}
if ($samFound -eq 0) { Write-Output "  No SAM copies found outside System32\\config." }

# ── NTDS.dit Copies ───────────────────────────────────────────────────────
Write-Output ""
Write-Output "===== NTDS.DIT COPIES ====="
Write-Output "(Legitimate NTDS.dit lives only at C:\\Windows\\NTDS\\ntds.dit on DCs)"
$ntdsFound = 0
foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 3 -Filter "ntds.dit" -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch "\\Windows\\NTDS\\" } |
        ForEach-Object {
            Write-Output "  [!!] $($_.FullName)  [$([math]::Round($_.Length/1MB,1)) MB]  Modified: $($_.LastWriteTime)"
            $ntdsFound++
        }
}
if ($ntdsFound -eq 0) { Write-Output "  No NTDS.dit copies found outside NTDS directory." }

# ── Credential Dump Output File Patterns ──────────────────────────────────
Write-Output ""
Write-Output "===== SUSPECTED CREDENTIAL DUMP OUTPUT ====="
$credPatterns = @("*password*","*passwd*","*hash*","*credential*","*ntlm*","*kerberos*","*lsass*","*dump*","*sekurlsa*")
$credFound = 0
foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    foreach ($pattern in $credPatterns) {
        Get-ChildItem -Path $path -Depth 2 -Filter $pattern -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -in @(".txt",".csv",".log",".out",".dmp",".xml") -and
                $_.LastWriteTime -gt (Get-Date).AddDays(-7)
            } | ForEach-Object {
                Write-Output "  [!] $($_.FullName)  [$($_.Length) bytes]  Modified: $($_.LastWriteTime)"
                $credFound++
            }
    }
}
if ($credFound -eq 0) { Write-Output "  No suspected credential dump output files found (last 7 days)." }

# ── Windows Credential Manager ────────────────────────────────────────────
Write-Output ""
Write-Output "===== WINDOWS CREDENTIAL MANAGER (cmdkey) ====="
$cmdkeyOut = cmdkey /list 2>&1
Write-Output ($cmdkeyOut -join "\`n")

Write-Output "===== END CREDENTIAL FILES ====="
`
  },

  // ══════════════════════════════════════════════════════ FILE SYSTEM IOCs
  {
    id:         "recent-file-changes",
    category:   "File System IOCs",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "recent-file-changes.ps1",
    shortDesc:  "Recently created/modified files in sensitive paths",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1083","T1074"],
    description: "Scans key directories (System32, Program Files, ProgramData, user profiles) for files created or modified in the last 24 hours. Malware often writes to system directories to blend in with legitimate files. Sorts by modification time so newest artefacts appear first.",
    params: [
      { name: "HoursBack", type: "number", placeholder: "24", hint: "How many hours back to scan (default: 24)", required: false }
    ],
    usage: `runscript -CloudFile="file-system-iocs/recent-file-changes.ps1"`,
    source: `<#
.SYNOPSIS
    Recent File Changes - Find files created or modified in the last N hours.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

param([int]$HoursBack = 24)

$cutoff = (Get-Date).AddHours(-$HoursBack)
Write-Output "===== RECENT FILE CHANGES (last $HoursBack hours, since $cutoff) ====="

$scanPaths = @(
    @{ Path = "C:\\Windows\\System32";      Depth = 1 },
    @{ Path = "C:\\Windows\\SysWOW64";      Depth = 1 },
    @{ Path = "C:\\Windows\\Temp";          Depth = 3 },
    @{ Path = "C:\\ProgramData";            Depth = 3 },
    @{ Path = "C:\\Users";                  Depth = 4 },
    @{ Path = "C:\\Temp";                   Depth = 3 },
    @{ Path = "C:\\PerfLogs";               Depth = 2 }
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
        $flag = if ($_.Extension -in $suspiciousExts) { "[!]" } else { "   " }
        Write-Output ("  $flag {0,-55} {1,-24} {2,8} KB  {3}" -f
            ($_.FullName -replace [regex]::Escape($entry.Path), ""),
            $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"),
            [math]::Round($_.Length / 1KB, 1),
            $_.Extension
        )
    }
}

Write-Output ""
Write-Output "===== END RECENT FILE CHANGES ====="
`
  },

  {
    id:         "suspicious-archives",
    category:   "File System IOCs",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "suspicious-archives.ps1",
    shortDesc:  "Large archives and data staging indicators",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1560","T1074.001"],
    description: "Hunts for data exfiltration staging indicators: large archive files (.zip, .7z, .rar, .tar) in unusual locations, files with double extensions (malware evasion), unusually large files in temp directories, and clusters of files in staging paths created recently. These patterns frequently precede or follow data theft.",
    usage: `runscript -CloudFile="file-system-iocs/suspicious-archives.ps1"`,
    source: `<#
.SYNOPSIS
    Suspicious Archives - Hunt for data staging and exfil preparation indicators.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== SUSPICIOUS ARCHIVE / DATA STAGING HUNT ====="

$stagingPaths = @(
    "C:\\Windows\\Temp","C:\\Temp","$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA",
    "$env:USERPROFILE\\Desktop","$env:USERPROFILE\\Downloads","C:\\PerfLogs",
    "C:\\ProgramData","C:\\Intel","C:\\Recovery"
)
$archiveExts  = @(".zip",".7z",".rar",".tar",".gz",".bz2",".cab",".iso",".tar.gz")
$thresholdMB  = 50  # Flag archives larger than this

# ── Large Archives in Staging Paths ───────────────────────────────────────
Write-Output "===== LARGE ARCHIVES (>$thresholdMB MB) IN STAGING PATHS ====="
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

# ── Double Extension Files ────────────────────────────────────────────────
Write-Output ""
Write-Output "===== DOUBLE EXTENSION FILES ====="
$doubleExtFound = 0
foreach ($path in $stagingPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.[a-z]{2,4}\.[a-z]{2,4}$' -and $_.Name -notmatch '\.tar\.' } |
        ForEach-Object {
            Write-Output "  [!] $($_.FullName)  [$($_.Length) bytes]"
            $doubleExtFound++
        }
}
if ($doubleExtFound -eq 0) { Write-Output "  No double-extension files found." }

# ── Any Archives in System Paths (always suspicious) ─────────────────────
Write-Output ""
Write-Output "===== ARCHIVES IN SYSTEM PATHS (always suspicious) ====="
$sysArchiveFound = 0
$sysPaths = @("C:\\Windows\\System32","C:\\Windows\\SysWOW64","C:\\Windows\\Tasks")
foreach ($path in $sysPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ChildItem -Path $path -Recurse -Depth 2 -File -ErrorAction SilentlyContinue |
        Where-Object { $archiveExts | Where-Object { $_.Name.ToLower().EndsWith($_) } } |
        ForEach-Object {
            Write-Output "  [!!] $($_.FullName)  [$($_.Length) bytes]"
            $sysArchiveFound++
        }
}
if ($sysArchiveFound -eq 0) { Write-Output "  No archives found in system paths." }

# ── Large File Cluster (many new files in single dir = staging) ───────────
Write-Output ""
Write-Output "===== FILE CLUSTERS (>5 files created in last 48h in same directory) ====="
$cutoff = (Get-Date).AddHours(-48)
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
`
  },

  // ══════════════════════════════════════════════════════ REMEDIATION
  {
    id:         "isolate-prep-checks",
    category:   "Remediation",
    supportedPlatforms: ["crowdstrike"],  // CS-specific
    os: "windows",
    name:       "isolate-prep-checks.ps1",
    shortDesc:  "Pre-isolation checklist — GO / CAUTION / NO-GO",
    irPhase:    "Containment",
    permission: "Active Responder",
    mitre:      ["T1562"],
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
    Write-Output "\`nIf risk accepted: Falcon Console → Hosts → [host] → Isolate Host"
} else {
    Write-Output "[GO] Safe to isolate. No blockers or warnings."
    Write-Output "Proceed: Falcon Console → Hosts → [host] → Isolate Host"
}
Write-Output "===== END ISOLATE PREP ====="
`
  },

  // ══════════════════════════════════════════════════════ Windows — ERADICATION
  {
    id: "eradicate-process",
    category: "Remediation",
    os: "windows",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name: "kill-process.ps1",
    shortDesc: "Kill process by name or PID, optionally delete binary",
    irPhase: "Eradication",
    permission: "RTR Admin",
    mitre:      ["T1489","T1070"],
    description: "Locates a process by name or PID, logs full details (binary path, owner, parent PID, start time) before acting, then kills it. Optional -DeleteBinary flag removes the executable from disk. Always confirm the correct target first — use process-investigation scripts to identify PIDs. Destructive if DeleteBinary is set.",
    params: [
      { name: "ProcessName",  type: "string",  placeholder: "malware.exe",  hint: "Process name to kill — kills all matching instances",    required: false },
      { name: "ProcessId",    type: "number",  placeholder: "4812",         hint: "Specific PID to kill — use when name is ambiguous",      required: false },
      { name: "DeleteBinary", type: "boolean", default: false,              hint: "Also delete the process binary from disk (DESTRUCTIVE)", required: false },
    ],
    usage: `runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-ProcessName 'malware.exe'"`,
    source: `#Requires -RunAsAdministrator
param(
    [string]$ProcessName  = "",
    [int]   $ProcessId    = 0,
    [bool]  $DeleteBinary = \$false
)

Write-Output "===== KILL PROCESS ====="
Write-Output "Host     : \$env:COMPUTERNAME"
Write-Output "Operator : \$env:USERDOMAIN\\\$env:USERNAME"
Write-Output "Time     : \$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""

if (-not \$ProcessName -and \$ProcessId -eq 0) {
    Write-Output "[ERROR] Supply -ProcessName <name> or -ProcessId <pid>"
    exit 1
}

\$targets = if (\$ProcessId -gt 0) {
    @(Get-Process -Id \$ProcessId -ErrorAction SilentlyContinue)
} else {
    @(Get-Process -Name (\$ProcessName -replace '\\.exe\$','') -ErrorAction SilentlyContinue)
}

if (\$targets.Count -eq 0) {
    \$label = if (\$ProcessId -gt 0) { "PID \$ProcessId" } else { "'\$ProcessName'" }
    Write-Output "[ERROR] No process found matching \$label"; exit 1
}

Write-Output "===== TARGETS (\$(\$targets.Count) found) ====="
\$binaries = @()
foreach (\$p in \$targets) {
    \$bin  = try { \$p.MainModule.FileName } catch { "n/a" }
    \$owner = try { \$o = (Get-CimInstance Win32_Process -Filter "ProcessId=\$(\$p.Id)").GetOwner(); "\$(\$o.Domain)\\\$(\$o.User)" } catch { "n/a" }
    \$ppid  = try { (Get-CimInstance Win32_Process -Filter "ProcessId=\$(\$p.Id)").ParentProcessId } catch { "n/a" }
    Write-Output "  Name       : \$(\$p.ProcessName)"
    Write-Output "  PID        : \$(\$p.Id)"
    Write-Output "  Owner      : \$owner"
    Write-Output "  Parent PID : \$ppid"
    Write-Output "  Binary     : \$bin"
    Write-Output "  Started    : \$(\$p.StartTime)"
    Write-Output ""
    if (\$bin -ne "n/a" -and \$bin) { \$binaries += \$bin }
}

Write-Output "===== KILLING ====="
foreach (\$p in \$targets) {
    try { \$p.Kill(); \$p.WaitForExit(3000) | Out-Null; Write-Output "  [+] Killed \$(\$p.ProcessName) (PID \$(\$p.Id))" }
    catch { Write-Output "  [!] Failed to kill PID \$(\$p.Id): \$(\$_.Exception.Message)" }
}

if (\$DeleteBinary) {
    Write-Output ""; Write-Output "===== DELETING BINARIES ====="
    foreach (\$bin in (\$binaries | Sort-Object -Unique)) {
        if (-not (Test-Path \$bin)) { Write-Output "  [?] Already gone: \$bin"; continue }
        try { Remove-Item -Path \$bin -Force -ErrorAction Stop; Write-Output "  [+] Deleted: \$bin" }
        catch {
            & takeown.exe /f \$bin 2>&1 | Out-Null
            & icacls.exe \$bin /grant "\${env:USERNAME}:F" 2>&1 | Out-Null
            try { Remove-Item -Path \$bin -Force; Write-Output "  [+] Deleted (after takeown): \$bin" }
            catch { Write-Output "  [!] Could not delete '\$bin': \$(\$_.Exception.Message)" }
        }
    }
} else {
    if (\$binaries.Count -gt 0) {
        Write-Output ""; Write-Output "  Binary paths (use -DeleteBinary \`\$true to remove):"
        \$binaries | Sort-Object -Unique | ForEach-Object { Write-Output "    \$_" }
    }
}

Write-Output ""; Write-Output "===== END KILL PROCESS ====="
`
  },

  {
    id: "remove-scheduled-task",
    category: "Remediation",
    os: "windows",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name: "remove-scheduled-task.ps1",
    shortDesc: "Log full task definition then permanently delete it",
    irPhase: "Eradication",
    permission: "RTR Admin",
    mitre:      ["T1053.005"],
    description: "Finds a scheduled task by name and path, exports the full task XML definition for case documentation, then permanently deletes it with Unregister-ScheduledTask. Verifies deletion afterwards. Run scheduled-tasks.ps1 first to identify the exact task name and path before executing this script.",
    params: [
      { name: "TaskName", type: "string", placeholder: "MicrosoftEdgeUpdate", hint: "Exact task name — use scheduled-tasks.ps1 to find it",         required: true },
      { name: "TaskPath", type: "string", placeholder: "\\",                  hint: "Task folder path (default: \\ = root). E.g. \\Microsoft\\Windows\\", required: false },
    ],
    usage: `runscript -CloudFile="remediation/remove-scheduled-task.ps1" -CommandLine="-TaskName 'EvilTask' -TaskPath '\\\\'`,
    source: `#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=\$true)][string]\$TaskName = "",
    [string]\$TaskPath = "\\"
)

Write-Output "===== REMOVE SCHEDULED TASK ====="
Write-Output "Host     : \$env:COMPUTERNAME"
Write-Output "Operator : \$env:USERDOMAIN\\\$env:USERNAME"
Write-Output "Time     : \$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Target   : \$TaskPath\$TaskName"
Write-Output ""

if (-not \$TaskName) { Write-Output "[ERROR] -TaskName is required"; exit 1 }

\$task = Get-ScheduledTask -TaskName \$TaskName -TaskPath \$TaskPath -ErrorAction SilentlyContinue
if (-not \$task) {
    Write-Output "[ERROR] Scheduled task not found: '\$TaskName' at path '\$TaskPath'"
    Write-Output "  Hint: run scheduled-tasks.ps1 to list tasks and confirm the exact name/path"
    exit 1
}

Write-Output "===== TASK DETAILS (pre-deletion record) ====="
Write-Output "  Task Name   : \$(\$task.TaskName)"
Write-Output "  Task Path   : \$(\$task.TaskPath)"
Write-Output "  State       : \$(\$task.State)"
foreach (\$a in \$task.Actions) {
    Write-Output "  Execute     : \$(\$a.Execute)"
    Write-Output "  Arguments   : \$(\$a.Arguments)"
}
foreach (\$t in \$task.Triggers) {
    Write-Output "  Trigger     : \$(\$t.CimClass.CimClassName)"
    if (\$t.StartBoundary) { Write-Output "  Starts      : \$(\$t.StartBoundary)" }
}
Write-Output "  RunAs       : \$(\$task.Principal.UserId)"
Write-Output "  RunLevel    : \$(\$task.Principal.RunLevel)"
Write-Output ""
Write-Output "--- Task XML ---"
try { Export-ScheduledTask -TaskName \$TaskName -TaskPath \$TaskPath } catch { Write-Output "  [XML unavailable]" }
Write-Output ""

Write-Output "===== REMOVING ====="
try {
    Unregister-ScheduledTask -TaskName \$TaskName -TaskPath \$TaskPath -Confirm:\$false -ErrorAction Stop
    Write-Output "  [+] Removed: \$TaskPath\$TaskName"
} catch { Write-Output "  [!] Failed: \$(\$_.Exception.Message)"; exit 1 }

\$verify = Get-ScheduledTask -TaskName \$TaskName -TaskPath \$TaskPath -ErrorAction SilentlyContinue
if (\$verify) { Write-Output "  [!] WARNING: task still present — manual review required" }
else          { Write-Output "  [+] Confirmed: task no longer registered" }

Write-Output ""; Write-Output "===== END REMOVE SCHEDULED TASK ====="
`
  },

  {
    id: "remove-service",
    category: "Remediation",
    os: "windows",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name: "remove-service.ps1",
    shortDesc: "Stop and delete a malicious Windows service",
    irPhase: "Eradication",
    permission: "RTR Admin",
    mitre:      ["T1543.003"],
    description: "Finds a service by its sc name (not display name), logs full registry configuration (binary path, account, start type), stops it, and removes it via sc.exe delete. Verifies removal. Optional -DeleteBinary flag removes the service binary from disk. Use suspicious-services.ps1 to identify targets first.",
    params: [
      { name: "ServiceName",  type: "string",  placeholder: "evilsvc",  hint: "Service sc name (not display name) — use suspicious-services.ps1 to find", required: true },
      { name: "DeleteBinary", type: "boolean", default: false,           hint: "Also delete the service binary from disk (DESTRUCTIVE)",                   required: false },
    ],
    usage: `runscript -CloudFile="remediation/remove-service.ps1" -CommandLine="-ServiceName 'evilsvc'"`,
    source: `#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=\$true)][string]\$ServiceName = "",
    [bool]\$DeleteBinary = \$false
)

Write-Output "===== REMOVE SERVICE ====="
Write-Output "Host     : \$env:COMPUTERNAME"
Write-Output "Operator : \$env:USERDOMAIN\\\$env:USERNAME"
Write-Output "Time     : \$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ""

if (-not \$ServiceName) { Write-Output "[ERROR] -ServiceName is required"; exit 1 }

\$svc = Get-Service -Name \$ServiceName -ErrorAction SilentlyContinue
if (-not \$svc) { Write-Output "[ERROR] Service not found: '\$ServiceName'"; exit 1 }

\$reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\\\$ServiceName" -ErrorAction SilentlyContinue

Write-Output "===== SERVICE DETAILS (pre-deletion record) ====="
Write-Output "  Service Name  : \$(\$svc.ServiceName)"
Write-Output "  Display Name  : \$(\$svc.DisplayName)"
Write-Output "  Status        : \$(\$svc.Status)"
Write-Output "  Start Type    : \$(\$svc.StartType)"
if (\$reg) {
    Write-Output "  Binary Path   : \$(\$reg.ImagePath)"
    Write-Output "  Object Name   : \$(\$reg.ObjectName)"
}
Write-Output ""

\$binPath = if (\$reg -and \$reg.ImagePath) { ((\$reg.ImagePath -replace '"','') -split ' ')[0] } else { "" }

Write-Output "===== STOPPING ====="
if (\$svc.Status -eq 'Running') {
    try { Stop-Service -Name \$ServiceName -Force -ErrorAction Stop; Write-Output "  [+] Stopped: \$ServiceName" }
    catch { & sc.exe stop \$ServiceName 2>&1; Start-Sleep 2 }
} else { Write-Output "  [i] Already stopped (\$(\$svc.Status))" }

Write-Output ""; Write-Output "===== DELETING ====="
& sc.exe delete \$ServiceName 2>&1 | ForEach-Object { Write-Output "  \$_" }

Start-Sleep -Milliseconds 500
\$v = Get-Service -Name \$ServiceName -ErrorAction SilentlyContinue
if (\$v) { Write-Output "  [!] Still registered — may need reboot to fully remove" }
else     { Write-Output "  [+] Confirmed: service no longer registered" }

if (\$DeleteBinary -and \$binPath) {
    Write-Output ""; Write-Output "===== DELETING BINARY: \$binPath ====="
    if (Test-Path \$binPath) {
        try { Remove-Item -Path \$binPath -Force; Write-Output "  [+] Deleted: \$binPath" }
        catch { Write-Output "  [!] Could not delete: \$(\$_.Exception.Message)" }
    } else { Write-Output "  [?] Binary not found at path" }
}

Write-Output ""; Write-Output "===== END REMOVE SERVICE ====="
`
  },

  {
    id: "remove-registry-run-key",
    category: "Remediation",
    os: "windows",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name: "remove-registry-run-key.ps1",
    shortDesc: "Remove a Run/RunOnce persistence entry from the registry",
    irPhase: "Eradication",
    permission: "RTR Admin",
    mitre:      ["T1547.001"],
    description: "Displays all current Run/RunOnce entries across HKLM and HKCU (including Wow6432Node variants) for review, then removes the named value. Logs the full value data before deletion for case documentation. Verifies removal afterwards. Run persistence-registry.ps1 first to identify the exact value name.",
    params: [
      { name: "ValueName", type: "string", placeholder: "WindowsUpdate",    hint: "Exact registry value name to remove (case-insensitive match)",  required: true },
      { name: "Hive",      type: "string", placeholder: "HKLM",             hint: "HKLM, HKCU, or Both (default: HKLM)",                          required: false },
    ],
    usage: `runscript -CloudFile="remediation/remove-registry-run-key.ps1" -CommandLine="-ValueName 'WindowsUpdate' -Hive 'HKLM'"`,
    source: `#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory=\$true)][string]\$ValueName = "",
    [ValidateSet("HKLM","HKCU","Both")][string]\$Hive = "HKLM"
)

Write-Output "===== REMOVE REGISTRY RUN KEY ====="
Write-Output "Host     : \$env:COMPUTERNAME"
Write-Output "Operator : \$env:USERDOMAIN\\\$env:USERNAME"
Write-Output "Time     : \$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Target   : ValueName='\$ValueName'  Hive='\$Hive'"
Write-Output ""

if (-not \$ValueName) { Write-Output "[ERROR] -ValueName is required"; exit 1 }

\$allPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

Write-Output "===== ALL CURRENT RUN ENTRIES (for context) ====="
foreach (\$path in \$allPaths) {
    if (-not (Test-Path \$path)) { continue }
    \$vals = Get-ItemProperty \$path -ErrorAction SilentlyContinue
    \$entries = \$vals.PSObject.Properties | Where-Object { \$_.Name -notlike 'PS*' }
    if (-not \$entries) { continue }
    Write-Output "[\$path]"
    foreach (\$e in \$entries) {
        \$mark = if (\$e.Name -ieq \$ValueName) { "  <-- TARGET" } else { "" }
        Write-Output "  \$(\$e.Name) = \$(\$e.Value)\$mark"
    }
    Write-Output ""
}

\$targetPaths = switch (\$Hive) {
    "HKLM" { \$allPaths | Where-Object { \$_ -like 'HKLM:*' } }
    "HKCU" { \$allPaths | Where-Object { \$_ -like 'HKCU:*' } }
    "Both" { \$allPaths }
}

Write-Output "===== REMOVING '\$ValueName' ====="
\$removed = 0
foreach (\$path in \$targetPaths) {
    if (-not (Test-Path \$path)) { continue }
    \$vals  = Get-ItemProperty \$path -ErrorAction SilentlyContinue
    \$match = \$vals.PSObject.Properties | Where-Object { \$_.Name -ieq \$ValueName }
    if (-not \$match) { continue }
    Write-Output "  Found in: \$path  =>  \$(\$match.Value)"
    try {
        Remove-ItemProperty -Path \$path -Name \$ValueName -Force -ErrorAction Stop
        \$removed++; Write-Output "  [+] Removed: \$path\\\$ValueName"
    } catch { Write-Output "  [!] Failed: \$(\$_.Exception.Message)" }
}

if (\$removed -eq 0) { Write-Output "  [?] '\$ValueName' not found in targeted hive(s)" }
else                 { Write-Output ""; Write-Output "  [+] Total entries removed: \$removed" }

Write-Output ""; Write-Output "===== VERIFICATION ====="
\$still = \$false
foreach (\$path in \$targetPaths) {
    if (-not (Test-Path \$path)) { continue }
    \$v = Get-ItemProperty \$path -ErrorAction SilentlyContinue
    if (\$v.PSObject.Properties | Where-Object { \$_.Name -ieq \$ValueName }) {
        Write-Output "  [!] Still present in: \$path"; \$still = \$true
    }
}
if (-not \$still) { Write-Output "  [+] Confirmed clean — '\$ValueName' not found in targeted paths" }

Write-Output ""; Write-Output "===== END REMOVE REGISTRY RUN KEY ====="
`
  },

  // ══════════════════════════════════════════════════════ macOS — TRIAGE
  {
    id: "macos-host-summary",
    category: "Triage",
    os: "macos",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name: "host-summary.sh",
    shortDesc: "OS version, uptime, users, EDR agents, SIP + FileVault",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1082","T1016"],
    description: "macOS rapid triage snapshot: OS/build version, architecture, last boot, currently logged-on users, local admin group, network interfaces, running EDR agents (Falcon, SentinelOne, Defender), FileVault encryption status, and SIP state.",
    usage: `runscript -CloudFile="macos/triage/host-summary.sh"`,
    source: `#!/bin/bash
# Host Summary - macOS rapid triage snapshot.
# IR Phase: Identification | Permission: Active Responder

echo "===== HOST SUMMARY ====="
echo "Hostname     : $(hostname)"
echo "OS Version   : $(sw_vers -productName) $(sw_vers -productVersion) (Build $(sw_vers -buildVersion))"
echo "Architecture : $(uname -m)"
echo "Kernel       : $(uname -r)"
echo "Serial No.   : $(system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial Number/ {print $NF}')"
echo "Model        : $(system_profiler SPHardwareDataType 2>/dev/null | awk -F': ' '/Model Name/ {print $2}')"
echo "Current Time : $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo ""

echo "===== UPTIME ====="
uptime
BOOT_TIME=$(sysctl -n kern.boottime 2>/dev/null | awk -F'[={,]' '{print $2}' | xargs -I{} date -r {} '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
echo "Last Boot    : \${BOOT_TIME:-unknown}"
echo ""

echo "===== LOGGED-ON USERS ====="
who
echo ""

echo "===== LOCAL ADMIN USERS ====="
dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //'
echo ""

echo "===== NETWORK INTERFACES ====="
ifconfig | awk '/^[a-z]/{iface=$1} /inet /{print iface, $2}'
echo ""

echo "===== SECURITY AGENTS ====="
declare -A agents=(
  ["CrowdStrike"]="com.crowdstrike.falcond"
  ["SentinelOne"]="com.sentinelone.sentinel-agent"
  ["Microsoft Defender"]="com.microsoft.wdav.daemon"
)
for name in "\${!agents[@]}"; do
  if launchctl list 2>/dev/null | grep -q "\${agents[$name]}"; then
    echo "  [+] $name is running (\${agents[$name]})"
  fi
done
echo ""

echo "===== FILEVAULT STATUS ====="
fdesetup status 2>/dev/null || echo "  fdesetup not available"
echo ""

echo "===== SYSTEM INTEGRITY PROTECTION (SIP) ====="
csrutil status 2>/dev/null || echo "  csrutil not available"

echo "===== END HOST SUMMARY ====="
`
  },

  {
    id: "macos-active-connections",
    category: "Triage",
    os: "macos",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name: "active-connections.sh",
    shortDesc: "TCP/UDP sockets mapped to process via lsof",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1049"],
    description: "Maps every established and listening socket to its owning process using lsof. Also shows DNS config, default routes, ARP cache, and application firewall state. macOS equivalent of netstat -b.",
    usage: `runscript -CloudFile="macos/triage/active-connections.sh"`,
    source: `#!/bin/bash
# Active Network Connections - macOS
# IR Phase: Identification | Permission: Active Responder

echo "===== ACTIVE NETWORK CONNECTIONS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

echo "===== ESTABLISHED CONNECTIONS ====="
lsof -i -nP 2>/dev/null | awk 'NR==1 || /ESTABLISHED/'
echo ""

echo "===== LISTENING PORTS ====="
lsof -i -nP 2>/dev/null | awk 'NR==1 || /LISTEN/'
echo ""

echo "===== DNS CONFIGURATION ====="
scutil --dns 2>/dev/null | grep -E "nameserver|domain" | head -10
echo ""

echo "===== DEFAULT ROUTES ====="
netstat -rn 2>/dev/null | grep -E "^default"
echo ""

echo "===== ARP CACHE ====="
arp -a 2>/dev/null
echo ""

echo "===== APPLICATION FIREWALL STATUS ====="
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null

echo "===== END ACTIVE CONNECTIONS ====="
`
  },

  {
    id: "macos-logged-on-users",
    category: "Triage",
    os: "macos",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name: "logged-on-users.sh",
    shortDesc: "Current sessions, recent logins, failed auth events",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1033","T1087"],
    description: "Shows current interactive sessions (who/w), recent login history, failed authentication events from the unified log, active SSH sessions, and users with valid login shells. Use this before isolating to confirm whether a legitimate user is active.",
    usage: `runscript -CloudFile="macos/triage/logged-on-users.sh"`,
    source: `#!/bin/bash
# Logged-On Users - macOS
# IR Phase: Identification | Permission: Active Responder

echo "===== LOGGED-ON USER ANALYSIS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

echo "===== CURRENT SESSIONS ====="
who
echo ""

echo "===== ACTIVE SESSIONS (w) ====="
w 2>/dev/null
echo ""

echo "===== RECENT LOGINS (last 20) ====="
last -20 2>/dev/null
echo ""

echo "===== FAILED AUTH ATTEMPTS (last 24h) ====="
log show --predicate 'process == "loginwindow" && eventMessage CONTAINS "failed"' \
  --last 24h 2>/dev/null | tail -20 || echo "  No auth failure log access"
echo ""

echo "===== ACTIVE SSH CONNECTIONS ====="
lsof -i :22 -nP 2>/dev/null | grep ESTABLISHED || echo "  None"
echo ""

echo "===== CONSOLE USER ====="
stat -f '%Su' /dev/console 2>/dev/null
echo ""

echo "===== USERS WITH LOGIN SHELLS ====="
dscl . list /Users UserShell 2>/dev/null | grep -v "nologin\|false\|git-shell" | \
  awk '{printf "  %-20s %s\n", $1, $2}'

echo "===== END LOGGED-ON USERS ====="
`
  },

  // ══════════════════════════════════════════════════════ macOS — PERSISTENCE
  {
    id: "macos-launchd-entries",
    category: "Persistence",
    os: "macos",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name: "launchd-entries.sh",
    shortDesc: "LaunchDaemons, LaunchAgents, login items, cron",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1543.004","T1546"],
    description: "Enumerates all LaunchDaemon and LaunchAgent plists (system and user-level), flags entries not from known Apple/vendor prefixes, checks login items, crontabs, and periodic task scripts. LaunchDaemons are the primary persistence mechanism on macOS — any unknown entry is high priority.",
    usage: `runscript -CloudFile="macos/persistence/launchd-entries.sh"`,
    source: `#!/bin/bash
# LaunchD Persistence - macOS
# IR Phase: Identification | Permission: Active Responder

echo "===== LAUNCHD PERSISTENCE ANALYSIS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"

SAFE_PREFIXES="com.apple com.crowdstrike com.sentinelone com.microsoft com.google com.adobe com.zoom"

flag_entry() {
  local name="$1"
  for prefix in $SAFE_PREFIXES; do
    [[ "$name" == $prefix* ]] && return 1
  done
  return 0
}

scan_plist_dir() {
  local dir="$1" label="$2"
  echo ""
  echo "===== $label ====="
  [ -d "$dir" ] || { echo "  [not found]"; return; }
  for plist in "$dir"/*.plist; do
    [ -f "$plist" ] || continue
    lv=$(defaults read "$plist" Label 2>/dev/null || echo "[no label]")
    prog=$(defaults read "$plist" Program 2>/dev/null || \
           defaults read "$plist" ProgramArguments 2>/dev/null | head -1 | tr -d '(",' || echo "")
    mtime=$(stat -f "%Sm" -t "%Y-%m-%d" "$plist" 2>/dev/null)
    flag_entry "$lv" && flag="[!]" || flag="   "
    printf "  %s %-50s %s  [%s]\n" "$flag" "$lv" "$prog" "$mtime"
  done
}

scan_plist_dir "/Library/LaunchDaemons"     "LAUNCH DAEMONS (System)"
scan_plist_dir "/Library/LaunchAgents"      "LAUNCH AGENTS (System)"
scan_plist_dir "$HOME/Library/LaunchAgents" "LAUNCH AGENTS (User)"

echo ""
echo "===== LOGIN ITEMS ====="
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null

echo ""
echo "===== CRON JOBS ====="
crontab -l 2>/dev/null || echo "  [none]"

echo "===== END LAUNCHD PERSISTENCE ====="
`
  },

  // ══════════════════════════════════════════════════════ macOS — FILE SYSTEM IOCs
  {
    id: "macos-recent-file-changes",
    category: "File System IOCs",
    os: "macos",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name: "recent-file-changes.sh",
    shortDesc: "Recently modified files in LaunchD, tmp, Downloads, local/bin",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1083"],
    description: "Scans LaunchDaemon/Agent directories, /tmp, /usr/local/bin, ~/Downloads, and ~/Desktop for recently created or modified files. Flags executable scripts (.sh, .py, .dylib, .kext). Also hunts for world-writable files and recently modified executables in /usr/local.",
    params: [
      { name: "Hours", type: "number", placeholder: "24", hint: "Hours back to scan (passed as $1, default: 24)", required: false }
    ],
    usage: `runscript -CloudFile="macos/file-system-iocs/recent-file-changes.sh"`,
    source: `#!/bin/bash
# Recent File Changes - macOS
# IR Phase: Identification | Permission: Active Responder
# Usage: run script.sh [HoursBack]

HOURS=\${1:-24}
echo "===== RECENT FILE CHANGES (last \${HOURS}h) ====="
echo "Host: $(hostname) | Since: $(date -v-\${HOURS}H '+%Y-%m-%d %H:%M:%S')"

SUSPICIOUS_EXTS="\\.sh|\\.py|\\.rb|\\.pl|\\.dylib|\\.so|\\.kext|\\.pkg|\\.scpt|\\.osax"

touch -t "$(date -v-\${HOURS}H '+%Y%m%d%H%M.%S')" /tmp/.rtr_time_marker 2>/dev/null

scan_dir() {
  local dir="$1" depth="\${2:-3}"
  [ -d "$dir" ] || return
  echo ""
  echo "--- $dir ---"
  find "$dir" -maxdepth "$depth" -type f -newer /tmp/.rtr_time_marker \
    -not -path "*/\\.*" 2>/dev/null | sort | while read -r f; do
      size=$(stat -f "%z" "$f" 2>/dev/null)
      mtime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$f" 2>/dev/null)
      echo "$f" | grep -qE "$SUSPICIOUS_EXTS" && flag="[!]" || flag="   "
      printf "  %s %-55s %8d bytes  %s\n" "$flag" "\${f:$((\${#dir}+1))}" "\${size:-0}" "$mtime"
  done
}

scan_dir "/Library/LaunchDaemons"       2
scan_dir "/Library/LaunchAgents"        2
scan_dir "$HOME/Library/LaunchAgents"   2
scan_dir "/private/tmp"                 3
scan_dir "/usr/local/bin"               2
scan_dir "$HOME/Downloads"              2
scan_dir "$HOME/Desktop"                2

rm -f /tmp/.rtr_time_marker
echo "===== END RECENT FILE CHANGES ====="
`
  },

  // ══════════════════════════════════════════════════════ Linux — TRIAGE
  {
    id: "linux-host-summary",
    category: "Triage",
    os: "linux",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    name: "host-summary.sh",
    shortDesc: "Distro, kernel, uptime, users, network, EDR agents",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1082","T1016"],
    description: "Linux rapid triage snapshot: distro/kernel, architecture, hardware info (dmidecode), last boot, current users, privileged accounts (uid 0 + sudo/wheel group), network interfaces, and running EDR agents (Falcon, SentinelOne).",
    usage: `runscript -CloudFile="linux/triage/host-summary.sh"`,
    source: `#!/bin/bash
# Host Summary - Linux rapid triage snapshot.
# IR Phase: Identification | Permission: Active Responder

echo "===== HOST SUMMARY ====="
echo "Hostname     : $(hostname)"
echo "Current Time : $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo ""

echo "===== OS / KERNEL ====="
[ -f /etc/os-release ] && . /etc/os-release && echo "  Distribution : $PRETTY_NAME"
echo "  Kernel       : $(uname -r)"
echo "  Architecture : $(uname -m)"
echo ""

echo "===== HARDWARE ====="
cat /sys/class/dmi/id/sys_vendor 2>/dev/null | xargs -I{} echo "  Vendor : {}"
cat /sys/class/dmi/id/product_name 2>/dev/null | xargs -I{} echo "  Model  : {}"
echo ""

echo "===== UPTIME ====="
uptime
echo "  Last boot: $(uptime -s 2>/dev/null || who -b 2>/dev/null | awk '{print $3, $4}')"
echo ""

echo "===== NETWORK INTERFACES ====="
if command -v ip &>/dev/null; then
  ip addr show | awk '/^[0-9]/{iface=$2} /inet /{printf "  %-15s %s\n", iface, $2}'
else
  ifconfig 2>/dev/null | grep -E "^[a-z]|inet " | awk '/^[a-z]/{i=$1} /inet /{print "  " i, $2}'
fi
echo ""

echo "===== LOGGED-ON USERS ====="
who
echo ""

echo "===== PRIVILEGED USERS ====="
echo "  UID 0 accounts:"
awk -F: '$3 == 0 {print "   ", $1}' /etc/passwd
echo "  sudo/wheel group:"
getent group sudo 2>/dev/null || getent group wheel 2>/dev/null
echo ""

echo "===== SECURITY AGENTS ====="
for agent in falcon-sensor sentinelone wdavdaemon cbdaemon; do
  pgrep -x "$agent" &>/dev/null && echo "  [+] $agent is running"
done

echo "===== END HOST SUMMARY ====="
`
  },

  {
    id: "linux-active-connections",
    category: "Triage",
    os: "linux",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    name: "active-connections.sh",
    shortDesc: "Sockets with process info via ss/lsof, firewall state",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1049"],
    description: "Maps all established and listening sockets to their owning processes using ss (preferred) or netstat. Shows DNS config, default routes, ARP/neighbour cache, and firewall status (ufw/firewalld/iptables). Linux equivalent of netstat -bntp.",
    usage: `runscript -CloudFile="linux/triage/active-connections.sh"`,
    source: `#!/bin/bash
# Active Network Connections - Linux
# IR Phase: Identification | Permission: Active Responder

echo "===== ACTIVE NETWORK CONNECTIONS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

if command -v ss &>/dev/null; then
  echo "===== ESTABLISHED CONNECTIONS (ss) ====="
  ss -antp state established 2>/dev/null | head -50
  echo ""
  echo "===== LISTENING PORTS (ss) ====="
  ss -lntp 2>/dev/null
else
  echo "===== CONNECTIONS (netstat) ====="
  netstat -antp 2>/dev/null | grep -E "ESTABLISHED|LISTEN" | head -50
fi
echo ""

echo "===== PROCESS-TO-PORT MAP (lsof) ====="
lsof -i -nP 2>/dev/null | grep -E "ESTABLISHED|LISTEN" | head -40 || echo "  lsof not available"
echo ""

echo "===== DNS CONFIGURATION ====="
cat /etc/resolv.conf 2>/dev/null
echo ""

echo "===== DEFAULT ROUTES ====="
command -v ip &>/dev/null && ip route show default || route -n 2>/dev/null | grep '^0\\.0\\.0\\.0'
echo ""

echo "===== ARP / NEIGHBOUR CACHE ====="
command -v ip &>/dev/null && ip neigh show || arp -n 2>/dev/null
echo ""

echo "===== FIREWALL STATUS ====="
if command -v ufw &>/dev/null; then
  ufw status 2>/dev/null
elif command -v firewall-cmd &>/dev/null; then
  firewall-cmd --state 2>/dev/null && firewall-cmd --list-all 2>/dev/null
elif command -v iptables &>/dev/null; then
  iptables -L -n --line-numbers 2>/dev/null | head -40
fi

echo "===== END ACTIVE CONNECTIONS ====="
`
  },

  // ══════════════════════════════════════════════════════ Linux — PERSISTENCE
  {
    id: "linux-systemd-services",
    category: "Persistence",
    os: "linux",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    name: "systemd-services.sh",
    shortDesc: "Systemd units from non-standard paths, timers, cron, rc.local",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1543.002"],
    description: "Finds systemd services whose ExecStart binary is not in standard system paths (/usr, /bin, /sbin, /lib). Also lists all enabled services, active timers, custom unit files in /etc/systemd/system, crontabs, rc.local, SysV init scripts not owned by any package, and at jobs.",
    usage: `runscript -CloudFile="linux/persistence/systemd-services.sh"`,
    source: `#!/bin/bash
# Systemd Persistence - Linux
# IR Phase: Identification | Permission: Active Responder

echo "===== LINUX PERSISTENCE ANALYSIS ====="
echo "Host: $(hostname) | Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

echo "===== SYSTEMD SERVICES WITH NON-STANDARD EXEC PATHS ====="
systemctl list-units --type=service --all --no-pager 2>/dev/null | \
  awk '/\\.service/ {print $1}' | while read -r svc; do
    execstart=$(systemctl show "$svc" -p ExecStart 2>/dev/null | grep -oP 'path=\\K[^;]+' | head -1)
    if [ -n "$execstart" ] && \
       ! echo "$execstart" | grep -qE "^/usr|^/bin|^/sbin|^/lib|^/opt/(crowdstrike|sentinel|microsoft)"; then
      state=$(systemctl is-active "$svc" 2>/dev/null)
      printf "  [!] %-45s %-10s %s\n" "$svc" "$state" "$execstart"
    fi
done
echo ""

echo "===== ALL ENABLED SERVICES ====="
systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | head -60
echo ""

echo "===== SYSTEMD TIMERS ====="
systemctl list-timers --all --no-pager 2>/dev/null
echo ""

echo "===== CUSTOM UNIT FILES (/etc/systemd/system) ====="
ls -la /etc/systemd/system/*.service /etc/systemd/system/*.timer 2>/dev/null
echo ""

echo "===== ROOT CRONTAB ====="
crontab -u root -l 2>/dev/null || echo "  [none or no access]"
echo ""

echo "===== /etc/crontab ====="
cat /etc/crontab 2>/dev/null

echo ""
echo "===== /etc/cron.d/ ====="
ls -la /etc/cron.d/ 2>/dev/null

echo ""
echo "===== RC.LOCAL ====="
cat /etc/rc.local 2>/dev/null || echo "  Not present"

echo ""
echo "===== AT JOBS ====="
atq 2>/dev/null || echo "  [none]"

echo "===== END SYSTEMD PERSISTENCE ====="
`
  },

  // ══════════════════════════════════════════════════════ macOS — PROCESS INVESTIGATION
  {
    id: "macos-process-tree",
    category: "Process Investigation",
    os: "macos",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    name: "process-tree.sh",
    shortDesc: "Full process hierarchy + suspicious parent/child pairs",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1057","T1055","T1036"],
    description: "Builds a full parent→child process hierarchy on macOS and flags suspicious relationships — browsers or Office apps spawning shells, processes running from /tmp or Downloads, DYLD injection indicators, and hidden (dot-prefixed) executables.",
    usage: `runscript -CloudFile="macos/process-investigation/process-tree.sh"`,
    source: `#!/usr/bin/env bash
# macOS Process Tree - IR Phase: Identification | Permission: Active Responder
set -uo pipefail
echo "===== macOS PROCESS TREE ====="
echo "Host: $(hostname)  Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

echo "===== FULL PROCESS LIST ====="
ps -axo pid=,ppid=,user=,stat=,args= | head -150
echo ""

echo "===== SUSPICIOUS PARENT->CHILD PAIRS ====="
declare -A CMDMAP
while IFS= read -r line; do
  pid=$(echo "$line" | awk '{print $1}')
  cmd=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf $i" "; print ""}')
  CMDMAP[\$pid]="\${cmd:-unknown}"
done < <(ps -axo pid=,args= 2>/dev/null)

FOUND=0
while IFS= read -r line; do
  pid=$(echo "$line" | awk '{print $1}'); ppid=$(echo "$line" | awk '{print $2}')
  cmd=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf $i" "; print ""}')
  parent="\${CMDMAP[\$ppid]:-unknown}"
  echo "\$cmd" | grep -qiE "bash|zsh|sh|python|curl|wget|osascript" || continue
  echo "\$parent" | grep -qiE "Safari|firefox|Chrome|Word|Excel|PowerPoint|Outlook|zoom|Slack" || continue
  echo "  [!] Parent (PID \$ppid): \$parent"; echo "      Child  (PID \$pid):  \$cmd"
  FOUND=\$((FOUND+1))
done < <(ps -axo pid=,ppid=,args= 2>/dev/null)
[ "\$FOUND" -eq 0 ] && echo "  [+] No suspicious pairs detected"
echo ""

echo "===== PROCESSES IN SUSPICIOUS PATHS ====="
FOUND2=0
while IFS= read -r line; do
  pid=$(echo "$line" | awk '{print $1}'); usr=$(echo "$line" | awk '{print $2}')
  cmd=$(echo "$line" | awk '{for(i=3;i<=NF;i++) printf $i" "; print ""}')
  echo "\$cmd" | grep -qE "/tmp/|/var/folders/|Downloads/|Desktop/|/Users/Shared/" || continue
  echo "  [!] PID \$pid (\$usr): \$cmd"; FOUND2=\$((FOUND2+1))
done < <(ps -axo pid=,user=,args= 2>/dev/null)
[ "\$FOUND2" -eq 0 ] && echo "  [+] No processes in suspicious paths"
echo ""

echo "===== TOP CPU CONSUMERS ====="
ps -axo pid=,user=,pcpu=,pmem=,args= 2>/dev/null | sort -rn -k3 | head -10
echo ""
echo "===== END macOS PROCESS TREE ====="
`
  },

  // ══════════════════════════════════════════════════════ macOS — ARTEFACT COLLECTION
  {
    id: "macos-browser-history",
    category: "Artefact Collection",
    os: "macos",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    name: "browser-history.sh",
    shortDesc: "Safari, Chrome, Firefox history + download quarantine log",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1217","T1083"],
    description: "Extracts recent browsing history (last 7 days) from Safari, Chrome, and Firefox for all user profiles using sqlite3. Also queries the macOS quarantine database for downloaded files — useful for tracing phishing visits, C2 connections, and malware staging URLs.",
    usage: `runscript -CloudFile="macos/artefact-collection/browser-history.sh"`,
    source: `#!/usr/bin/env bash
# macOS Browser History - IR Phase: Identification | Permission: Active Responder
set -uo pipefail
DAYS=7
echo "===== macOS BROWSER HISTORY ====="
echo "Host: $(hostname)  Time: $(date '+%Y-%m-%d %H:%M:%S')  Window: last \${DAYS} days"
echo ""
command -v sqlite3 &>/dev/null || { echo "[ERROR] sqlite3 not found"; exit 1; }
CUTOFF=\$(date -v "-\${DAYS}d" '+%s' 2>/dev/null || date -d "-\${DAYS} days" '+%s' 2>/dev/null || echo 0)

echo "===== SAFARI ====="
for USERDIR in /Users/*/; do
  DB="\${USERDIR}Library/Safari/History.db"; [ -f "\$DB" ] || continue
  UNAME=\$(basename "\$USERDIR"); echo "  --- User: \$UNAME ---"
  TMPDB="/tmp/safari_\$\$.db"; cp "\$DB" "\$TMPDB" 2>/dev/null || { echo "  [!] Permission denied"; continue; }
  CUTOFF_MAC=\$(( CUTOFF - 978307200 ))
  sqlite3 "\$TMPDB" "SELECT datetime(v.visit_time+978307200,'unixepoch','localtime'),i.url FROM history_visits v JOIN history_items i ON v.history_item=i.id WHERE v.visit_time>=\$CUTOFF_MAC ORDER BY v.visit_time DESC LIMIT 200;" 2>/dev/null | sed 's/^/  /' || echo "  [!] Query failed"
  rm -f "\$TMPDB"
done
echo ""

echo "===== CHROME ====="
for USERDIR in /Users/*/; do
  BASE="\${USERDIR}Library/Application Support/Google/Chrome"; [ -d "\$BASE" ] || continue
  for PROFILE in "\$BASE"/*/; do
    DB="\${PROFILE}History"; [ -f "\$DB" ] || continue
    UNAME=\$(basename "\$USERDIR"); PNAME=\$(basename "\$PROFILE"); echo "  --- User: \$UNAME / \$PNAME ---"
    TMPDB="/tmp/chrome_\$\$.db"; cp "\$DB" "\$TMPDB" 2>/dev/null || { echo "  [!] Permission denied"; continue; }
    CUTOFF_WK=\$(( (CUTOFF+11644473600)*1000000 ))
    sqlite3 "\$TMPDB" "SELECT datetime((last_visit_time/1000000)-11644473600,'unixepoch','localtime'),url,title FROM urls WHERE last_visit_time>=\$CUTOFF_WK ORDER BY last_visit_time DESC LIMIT 200;" 2>/dev/null | sed 's/^/  /' || echo "  [!] Query failed"
    rm -f "\$TMPDB"
  done
done
echo ""

echo "===== FIREFOX ====="
for USERDIR in /Users/*/; do
  BASE="\${USERDIR}Library/Application Support/Firefox/Profiles"; [ -d "\$BASE" ] || continue
  for PROFILE in "\$BASE"/*/; do
    DB="\${PROFILE}places.sqlite"; [ -f "\$DB" ] || continue
    UNAME=\$(basename "\$USERDIR"); PNAME=\$(basename "\$PROFILE"); echo "  --- User: \$UNAME / \$PNAME ---"
    TMPDB="/tmp/ff_\$\$.db"; cp "\$DB" "\$TMPDB" 2>/dev/null || { echo "  [!] Permission denied"; continue; }
    CUTOFF_FF=\$(( CUTOFF*1000000 ))
    sqlite3 "\$TMPDB" "SELECT datetime(v.visit_date/1000000,'unixepoch','localtime'),p.url,p.title FROM moz_historyvisits v JOIN moz_places p ON v.place_id=p.id WHERE v.visit_date>=\$CUTOFF_FF ORDER BY v.visit_date DESC LIMIT 200;" 2>/dev/null | sed 's/^/  /' || echo "  [!] Query failed"
    rm -f "\$TMPDB"
  done
done
echo ""

echo "===== QUARANTINE DOWNLOAD LOG ====="
for QFILE in /Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2; do
  [ -f "\$QFILE" ] || continue
  QU=\$(echo "\$QFILE" | awk -F'/' '{print \$3}'); echo "  --- User: \$QU ---"
  TMPQDB="/tmp/quarantine_\$\$.db"; cp "\$QFILE" "\$TMPQDB" 2>/dev/null || continue
  CUTOFF_MAC=\$(( CUTOFF - 978307200 ))
  sqlite3 "\$TMPQDB" "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch','localtime'),LSQuarantineDataURLString,LSQuarantineAgentName FROM LSQuarantineEvent WHERE LSQuarantineTimeStamp>=\$CUTOFF_MAC ORDER BY LSQuarantineTimeStamp DESC LIMIT 100;" 2>/dev/null | sed 's/^/  /' || true
  rm -f "\$TMPQDB"
done
echo ""; echo "===== END macOS BROWSER HISTORY ====="
`
  },

  {
    id: "macos-unsigned-binaries",
    category: "Process Investigation",
    os: "macos",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    name: "unsigned-binaries.sh",
    shortDesc: "Unsigned, ad-hoc signed, and Gatekeeper-failed processes",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1036","T1055","T1574"],
    description: "Checks code signatures of all running process binaries using codesign and spctl. Flags unsigned binaries, ad-hoc signed executables, Gatekeeper-rejected apps, processes in staging paths (Downloads/Desktop/tmp), and dot-prefixed hidden executables.",
    usage: `runscript -CloudFile="macos/process-investigation/unsigned-binaries.sh"`,
    source: `#!/usr/bin/env bash
# macOS Unsigned Binaries - IR Phase: Identification | Permission: Active Responder
set -uo pipefail
echo "===== macOS UNSIGNED / SUSPICIOUS BINARIES ====="
echo "Host: $(hostname)  Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
declare -A CHECKED
UNSIGNED=0; ADHOC=0; RISKY=0

while IFS= read -r line; do
  pid=\$(echo "\$line" | awk '{print \$1}'); usr=\$(echo "\$line" | awk '{print \$2}')
  bin=\$(echo "\$line" | awk '{print \$3}')
  [ -z "\$bin" ] && continue
  echo "\$bin" | grep -qE '^(\?|kernel_task)' && continue
  [ "\${CHECKED[\$bin]+_}" ] && continue; CHECKED["\$bin"]=1
  REAL=\$(realpath "\$bin" 2>/dev/null || echo "\$bin")
  SIG=\$(codesign -dv "\$REAL" 2>&1 || true)
  IS_U=false; IS_A=false; PR=""
  echo "\$SIG" | grep -q 'code object is not signed' && IS_U=true && UNSIGNED=\$((UNSIGNED+1))
  echo "\$SIG" | grep -qi 'adhoc' && [ "\$IS_U" = "false" ] && IS_A=true && ADHOC=\$((ADHOC+1))
  echo "\$REAL" | grep -qE '/tmp/|/var/folders/|Downloads/|Desktop/|/Users/Shared/' && PR=" [HIGH-RISK PATH]" && RISKY=\$((RISKY+1))
  \$IS_U || \$IS_A || [ -n "\$PR" ] || continue
  ST="[SIGNED]"; \$IS_U && ST="[UNSIGNED]"; \$IS_A && ST="[AD-HOC]"
  echo "  \$ST\$PR  PID=\$pid user=\$usr"; echo "    Binary: \$REAL"
  AUTHORITY=\$(echo "\$SIG" | grep 'Authority=' | head -1)
  [ -n "\$AUTHORITY" ] && echo "    Signer: \$AUTHORITY"
  echo "\$REAL" | grep -qE '^/System/|^/usr/bin/|^/bin/' || spctl --assess --verbose=4 "\$REAL" 2>&1 | head -1 | sed 's/^/    GK: /'
  echo ""
done < <(ps -axo pid=,user=,comm= 2>/dev/null)

echo "===== SUMMARY ====="
echo "  Unsigned: \$UNSIGNED  Ad-hoc: \$ADHOC  High-risk path: \$RISKY"
echo ""
echo "===== HIDDEN EXECUTABLES ====="
HIDDEN=0
while IFS= read -r line; do
  pid=\$(echo "\$line" | awk '{print \$1}'); cmd=\$(echo "\$line" | awk '{print \$2}')
  \$(basename "\$cmd" 2>/dev/null | grep -q '^\.') && echo "  [!] PID \$pid: \$cmd" && HIDDEN=\$((HIDDEN+1))
done < <(ps -axo pid=,comm= 2>/dev/null)
[ "\$HIDDEN" -eq 0 ] && echo "  [+] No hidden executables running"
echo ""; echo "===== END macOS UNSIGNED / SUSPICIOUS BINARIES ====="
`
  },

  // ══════════════════════════════════════════════════════ Linux — PROCESS INVESTIGATION
  {
    id: "linux-process-tree",
    category: "Process Investigation",
    os: "linux",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    name: "process-tree.sh",
    shortDesc: "Process hierarchy, deleted-binary processes, /tmp execution",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1057","T1055","T1036"],
    description: "Builds a full Linux process tree and identifies attacker techniques: web servers spawning shells (webshell indicator), processes running from deleted binaries (fileless execution), memfd/shm execution, processes in /tmp or /dev/shm, and high CPU/memory outliers.",
    usage: `runscript -CloudFile="linux/process-investigation/process-tree.sh"`,
    source: `#!/usr/bin/env bash
# Linux Process Tree - IR Phase: Identification | Permission: Active Responder
set -uo pipefail
echo "===== LINUX PROCESS TREE ====="
echo "Host: $(hostname)  Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

command -v pstree &>/dev/null && { echo "===== PSTREE ====="; pstree -p -u -l 2>/dev/null | head -100; echo ""; }

echo "===== FULL PROCESS LIST ====="
ps -eo pid=,ppid=,user=,stat=,cmd= --sort=ppid 2>/dev/null | head -150
echo ""

echo "===== SUSPICIOUS PARENT->CHILD PAIRS ====="
declare -A CMDMAP
while IFS= read -r line; do
  pid=\$(echo "\$line" | awk '{print \$1}'); cmd=\$(echo "\$line" | awk '{for(i=2;i<=NF;i++) printf \$i" "; print ""}')
  CMDMAP["\$pid"]="\${cmd:-unknown}"
done < <(ps -eo pid=,cmd= 2>/dev/null)
FOUND=0
while IFS= read -r line; do
  pid=\$(echo "\$line" | awk '{print \$1}'); ppid=\$(echo "\$line" | awk '{print \$2}')
  cmd=\$(echo "\$line" | awk '{for(i=3;i<=NF;i++) printf \$i" "; print ""}')
  parent="\${CMDMAP[\$ppid]:-unknown}"
  echo "\$cmd" | grep -qiE "(^|/)(bash|zsh|sh|python[23]?|perl|nc|curl|wget|socat)( |\$)" || continue
  echo "\$parent" | grep -qiE "(^|/)(nginx|apache2|httpd|php-fpm|mysql|postgres|node|java|tomcat)" || continue
  echo "  [!] Parent (PID \$ppid): \$parent"; echo "      Child  (PID \$pid):  \$cmd"; FOUND=\$((FOUND+1))
done < <(ps -eo pid=,ppid=,cmd= 2>/dev/null | tail -n +2)
[ "\$FOUND" -eq 0 ] && echo "  [+] No suspicious pairs detected"
echo ""

echo "===== PROCESSES WITH DELETED BINARIES ====="
FOUND2=0
for pid in /proc/[0-9]*/; do
  PIDNUM=\$(basename "\$pid")
  EXE="\${pid}exe"; [ -L "\$EXE" ] || continue
  TARGET=\$(readlink "\$EXE" 2>/dev/null || true)
  echo "\$TARGET" | grep -qE '(deleted)|^/memfd:|^/dev/shm/' || continue
  CMD=\$(tr '\0' ' ' < "\${pid}cmdline" 2>/dev/null | head -c 200 || true)
  USR=\$(stat -c '%U' "\$pid" 2>/dev/null || true)
  echo "  [!] PID \$PIDNUM (\$USR) — \$TARGET"; echo "      Cmdline: \$CMD"; FOUND2=\$((FOUND2+1))
done 2>/dev/null
[ "\$FOUND2" -eq 0 ] && echo "  [+] No deleted-binary processes"
echo ""

echo "===== PROCESSES IN /tmp / /dev/shm ====="
FOUND3=0
for pid in /proc/[0-9]*/; do
  PIDNUM=\$(basename "\$pid"); EXE="\${pid}exe"; [ -L "\$EXE" ] || continue
  TARGET=\$(readlink "\$EXE" 2>/dev/null || true)
  echo "\$TARGET" | grep -qE '^/tmp/|^/var/tmp/|^/dev/shm/' || continue
  CMD=\$(tr '\0' ' ' < "\${pid}cmdline" 2>/dev/null | head -c 200 || true)
  USR=\$(stat -c '%U' "\$pid" 2>/dev/null || true)
  echo "  [!] PID \$PIDNUM (\$USR): \$TARGET — \$CMD"; FOUND3=\$((FOUND3+1))
done 2>/dev/null
[ "\$FOUND3" -eq 0 ] && echo "  [+] No processes in suspicious paths"
echo ""

echo "===== TOP CPU / MEMORY ====="
echo "  -- CPU --"; ps -eo pid=,user=,pcpu=,pmem=,cmd= --sort=-pcpu 2>/dev/null | head -10
echo "  -- MEM --"; ps -eo pid=,user=,pcpu=,pmem=,cmd= --sort=-pmem 2>/dev/null | head -10
echo ""; echo "===== END LINUX PROCESS TREE ====="
`
  },

  // ══════════════════════════════════════════════════════ Linux — CREDENTIAL INDICATORS
  {
    id: "linux-credential-files",
    category: "Credential Indicators",
    os: "linux",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    name: "credential-files.sh",
    shortDesc: "passwd/shadow changes, SSH keys, shell history creds, SUID binaries",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1003","T1552","T1078"],
    description: "Identifies credential access indicators on Linux: recent modifications to /etc/passwd, /etc/shadow, and sudoers; UID-0 backdoor accounts; SSH authorized_keys anomalies; credential keywords in shell history; unusual SUID/SGID binaries; processes accessing /proc/*/mem (credential scraping); and browser credential stores.",
    usage: `runscript -CloudFile="linux/credential-indicators/credential-files.sh"`,
    source: `#!/usr/bin/env bash
# Linux Credential Indicators - IR Phase: Identification | Permission: Active Responder
set -uo pipefail
echo "===== LINUX CREDENTIAL INDICATORS ====="
echo "Host: $(hostname)  Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

echo "===== /etc/passwd / shadow / sudoers STATUS ====="
for f in /etc/passwd /etc/shadow /etc/sudoers; do
  [ -f "\$f" ] || continue
  MOD=\$(stat -c '%y' "\$f" 2>/dev/null || echo "unknown")
  PERM=\$(stat -c '%A %U:%G' "\$f" 2>/dev/null || echo "unknown")
  echo "  \$f — modified: \$MOD  perms: \$PERM"
done
echo ""

echo "  --- UID 0 accounts (should be only root) ---"
awk -F: '\$3==0 {print "  [!] UID 0: "\$1" shell="\$7}' /etc/passwd 2>/dev/null || true
echo ""
echo "  --- Accounts with login shells ---"
awk -F: '\$7 !~ /nologin|false|sync/ && \$1 != "#" {print "  "\$1" ("\$7")"}' /etc/passwd 2>/dev/null || true
echo ""

echo "===== SSH authorized_keys ====="
find /root /home -name 'authorized_keys' 2>/dev/null | while read -r akf; do
  OWNER=\$(stat -c '%U' "\$akf" 2>/dev/null || true); MOD=\$(stat -c '%y' "\$akf" 2>/dev/null || true)
  COUNT=\$(wc -l < "\$akf" 2>/dev/null || echo "?")
  echo "  \$akf (owner: \$OWNER, modified: \$MOD, keys: \$COUNT)"
  grep -v '^#' "\$akf" 2>/dev/null | while read -r key; do
    [ -z "\$key" ] && continue
    TYPE=\$(echo "\$key" | awk '{print \$1}'); COMMENT=\$(echo "\$key" | awk '{print \$3}')
    echo "    Key: \$TYPE  Comment: \$COMMENT"
  done
done || echo "  No authorized_keys found"
echo ""

echo "===== SHELL HISTORY — CREDENTIAL KEYWORDS ====="
for HISTFILE in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history; do
  [ -f "\$HISTFILE" ] || continue
  OWNER=\$(stat -c '%U' "\$HISTFILE" 2>/dev/null || true)
  MATCHES=\$(grep -inE "password|passwd|secret|token|api_key|Authorization|Bearer|--password|-p " "\$HISTFILE" 2>/dev/null | tail -20 || true)
  [ -n "\$MATCHES" ] && echo "  [!] \$HISTFILE (owner: \$OWNER):" && echo "\$MATCHES" | sed 's/^/    /'
done || true
echo "  [i] History scan complete"
echo ""

echo "===== UNUSUAL SUID BINARIES ====="
KNOWN="ping|ping6|sudo|su|passwd|newgrp|chfn|chsh|mount|umount|pkexec|ssh-agent|at|crontab|gpasswd|traceroute|write|wall|chage|expiry|dbus-daemon-launch-helper"
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r f; do
  BASE=\$(basename "\$f")
  echo "\$BASE" | grep -qiE "^(\$KNOWN)\$" && continue
  OWNER=\$(stat -c '%U:%G' "\$f" 2>/dev/null || true); MOD=\$(stat -c '%y' "\$f" 2>/dev/null || true)
  echo "  [!] Unusual SUID: \$f (owner: \$OWNER)"
done
echo ""

echo "===== PROCESSES READING /proc/*/mem (CREDENTIAL SCRAPING) ====="
MEM_FOUND=0
for pid in /proc/[0-9]*/fd/; do
  PIDNUM=\$(echo "\$pid" | grep -o '[0-9]*' | head -1)
  ls -la "\$pid" 2>/dev/null | grep -q '/proc/.*/mem' || continue
  CMD=\$(tr '\0' ' ' < "/proc/\$PIDNUM/cmdline" 2>/dev/null | head -c 200 || true)
  USR=\$(stat -c '%U' "/proc/\$PIDNUM" 2>/dev/null || true)
  echo "  [!] PID \$PIDNUM (\$USR): \$CMD"; MEM_FOUND=\$((MEM_FOUND+1))
done 2>/dev/null
[ "\$MEM_FOUND" -eq 0 ] && echo "  [+] No credential-scraping process memory access detected"
echo ""; echo "===== END LINUX CREDENTIAL INDICATORS ====="
`
  },

  // ══════════════════════════════════════════════════════ Linux — FILE SYSTEM IOCs
  {
    id: "linux-recent-file-changes",
    category: "File System IOCs",
    os: "linux",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    name: "recent-file-changes.sh",
    shortDesc: "Modified files in /tmp, /etc, systemd paths, /usr/local, home dirs",
    irPhase: "Identification",
    permission: "Active Responder",
    mitre:      ["T1083"],
    description: "Scans /tmp, /var/tmp, /dev/shm, /etc, systemd unit paths, /usr/local, and home directories for recently modified files. Flags setuid/setgid binaries changed recently (privilege escalation indicator) and modifications to /etc/passwd, /etc/shadow, and sudoers.",
    params: [
      { name: "Hours", type: "number", placeholder: "24", hint: "Hours back to scan (passed as $1, default: 24)", required: false }
    ],
    usage: `runscript -CloudFile="linux/file-system-iocs/recent-file-changes.sh"`,
    source: `#!/bin/bash
# Recent File Changes - Linux
# IR Phase: Identification | Permission: Active Responder

HOURS=\${1:-24}
MINUTES=$(( HOURS * 60 ))
echo "===== RECENT FILE CHANGES (last \${HOURS}h) ====="
echo "Host: $(hostname)"

SUSPICIOUS_EXTS="\\.( sh|py|rb|pl|so|ko|elf|out|cgi|php|jsp)$"

scan_dir() {
  local dir="$1" depth="\${2:-3}"
  [ -d "$dir" ] || return
  echo ""; echo "--- $dir ---"
  find "$dir" -maxdepth "$depth" -type f -mmin "-\${MINUTES}" 2>/dev/null | sort | while read -r f; do
    size=$(stat -c "%s" "$f" 2>/dev/null || echo 0)
    mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d. -f1)
    echo "$f" | grep -qE "\\.sh$|\\.py$|\\.rb$|\\.pl$|\\.so$|\\.ko$" && flag="[!]" || flag="   "
    printf "  %s %-60s %8d bytes  %s\n" "$flag" "\${f:$((\${#dir}+1))}" "$size" "$mtime"
  done
}

scan_dir "/tmp" 3; scan_dir "/var/tmp" 3; scan_dir "/dev/shm" 2
scan_dir "/etc" 2; scan_dir "/etc/systemd" 3
scan_dir "/usr/local/bin" 2; scan_dir "/usr/local/sbin" 2
scan_dir "/home" 3; scan_dir "/root" 3

echo ""
echo "===== RECENTLY MODIFIED SETUID/SETGID BINARIES ====="
find /usr /bin /sbin -maxdepth 4 -type f \\( -perm -4000 -o -perm -2000 \\) \
  -mmin "-\${MINUTES}" 2>/dev/null | while read -r f; do
    printf "  [!!] %-50s perms=%s  %s\n" "$f" "$(stat -c '%a' "$f")" "$(stat -c '%y' "$f" | cut -d. -f1)"
done

echo ""
echo "===== /etc/passwd, /etc/shadow, /etc/sudoers MODIFIED? ====="
for f in /etc/passwd /etc/shadow /etc/sudoers; do
  [ -n "$(find "$f" -mmin "-\${MINUTES}" 2>/dev/null)" ] && \
    printf "  [!!] %s modified: %s\n" "$f" "$(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1)"
done

echo "===== END RECENT FILE CHANGES ====="
`
  }

,

  // ══════════════════════════════════════════════════════ EVENT LOG FORENSICS
  {
    id:         "event-log-forensics",
    category:   "Artefact Collection",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "event-log-forensics.ps1",
    shortDesc:  "Security, System, PowerShell, WinRM events — logons, services, tamper",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1078","T1059.001","T1053.005","T1003"],
    description: "Pulls the highest-value event IDs from Security, System, PowerShell Operational, and WinRM logs. Covers logon events, explicit credential use, privilege escalation, new services, PowerShell script block logging, Kerberos authentication, and tamper indicators. Run first on any host where account activity or remote access is suspected.",
    params: [
      { name: "Hours",     type: "number", default: 24,  hint: "Hours back to search" },
      { name: "MaxEvents", type: "number", default: 50,  hint: "Max events per category" }
    ],
    usage: `runscript -CloudFile="artefact-collection/event-log-forensics.ps1"
runscript -CloudFile="artefact-collection/event-log-forensics.ps1" -CommandLine="-Hours 72 -MaxEvents 100"`,
    source: `<#
.SYNOPSIS
    Event Log Forensics - Security, System, PowerShell, and WinRM events.

.DESCRIPTION
    Pulls the highest-value event IDs from the Security, System, PowerShell
    Operational, and Microsoft-Windows-WinRM/Operational logs. Covers logon
    events, explicit credential use, privilege escalation, new services,
    PowerShell script block logging, and Kerberos authentication.

    Run this first on any host where account activity or remote access is
    suspected. Output is structured so each section can be pasted directly
    into a case note.

.PARAMETER Hours
    How many hours back to search. Default: 24.

.PARAMETER MaxEvents
    Maximum events to return per event ID / category. Default: 50.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.EXAMPLE
    runscript -CloudFile="artefact-collection/event-log-forensics.ps1"
    runscript -CloudFile="artefact-collection/event-log-forensics.ps1" -CommandLine="-Hours 72 -MaxEvents 100"
#>
param(
    [int]$Hours     = 24,
    [int]$MaxEvents = 50
)

$cutoff = (Get-Date).AddHours(-$Hours)
$ts     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

Write-Output "===== EVENT LOG FORENSICS ====="
Write-Output "Host      : $env:COMPUTERNAME"
Write-Output "Operator  : $env:USERNAME"
Write-Output "Time      : $ts"
Write-Output "Window    : Last $Hours hours (since $($cutoff.ToString('yyyy-MM-dd HH:mm:ss')))"
Write-Output ""

function Get-FilteredEvents {
    param($LogName, [int[]]$Ids, $Cutoff, $Max)
    try {
        $filter = @{
            LogName   = $LogName
            Id        = $Ids
            StartTime = $Cutoff
        }
        Get-WinEvent -FilterHashtable $filter -MaxEvents ($Max * $Ids.Count) -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -notmatch 'No events') {
            Write-Output "  [!] Could not query '$LogName': $_"
        }
        @()
    }
}

# ── SECTION 1: Logon / Logoff (Security) ──────────────────────────────────────
# 4624=Logon, 4625=Failed Logon, 4634=Logoff, 4647=User-initiated Logoff
# 4648=Logon with explicit creds (pass-the-hash / runas indicator)
Write-Output "===== LOGON EVENTS (4624/4625/4648) ====="

$logonTypeMap = @{
    2='Interactive'; 3='Network'; 4='Batch'; 5='Service';
    7='Unlock'; 8='NetworkCleartext'; 9='NewCredentials';
    10='RemoteInteractive(RDP)'; 11='CachedInteractive'
}

$logonEvents = Get-FilteredEvents -LogName 'Security' -Ids @(4624,4625,4648) -Cutoff $cutoff -Max $MaxEvents
if ($logonEvents) {
    $logonEvents | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents | ForEach-Object {
        $x    = [xml]$_.ToXml()
        $data = $x.Event.EventData.Data
        $d    = @{}
        $data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }

        $typeNum  = [int]($d['LogonType'] ?? 0)
        $typeStr  = $logonTypeMap[$typeNum] ?? "Type$typeNum"
        $status   = if ($_.Id -eq 4625) { " [FAILED]" } elseif ($_.Id -eq 4648) { " [EXPLICIT-CRED]" } else { "" }
        $user     = "$($d['TargetDomainName'])\$($d['TargetUserName'])"
        $srcIp    = $d['IpAddress'] ?? $d['WorkstationName'] ?? '-'
        $process  = $d['ProcessName'] ?? '-'

        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}{2}  {3}  {4}  src={5}  proc={6}" -f \`
            $_.TimeCreated, $_.Id, $status, $typeStr, $user, $srcIp, $process)
    }
} else {
    Write-Output "  [i] No logon events in window"
}
Write-Output ""

# ── SECTION 2: Privilege Escalation / Special Logon ──────────────────────────
# 4672=Special privileges assigned (admin-level logon)
# 4673=Privileged service call, 4674=Attempt to use privileged object
Write-Output "===== PRIVILEGE EVENTS (4672) ====="
$privEvents = Get-FilteredEvents -LogName 'Security' -Ids @(4672) -Cutoff $cutoff -Max $MaxEvents
if ($privEvents) {
    $privEvents | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents | ForEach-Object {
        $x   = [xml]$_.ToXml()
        $d   = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
        $user = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"
        $privs = ($d['PrivilegeList'] -replace '\s+', ', ') ?? '-'
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  {1}  privs={2}" -f $_.TimeCreated, $user, $privs)
    }
} else {
    Write-Output "  [i] No privilege events in window"
}
Write-Output ""

# ── SECTION 3: Account Changes ────────────────────────────────────────────────
# 4720=Account created, 4722=Account enabled, 4723=PW change attempt
# 4724=Admin PW reset, 4725=Account disabled, 4726=Account deleted
# 4728=Member added to security-enabled global group (Domain Admins etc)
# 4732=Member added to security-enabled local group (Administrators)
# 4756=Member added to universal group
Write-Output "===== ACCOUNT CHANGES (4720/4722/4724/4726/4728/4732/4756) ====="
$acctIds = @(4720,4722,4724,4725,4726,4728,4732,4756)
$acctEvents = Get-FilteredEvents -LogName 'Security' -Ids $acctIds -Cutoff $cutoff -Max $MaxEvents
if ($acctEvents) {
    $acctEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
        $by     = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"
        $target = $d['TargetUserName'] ?? $d['MemberName'] ?? '-'
        $grp    = $d['TargetUserName'] ?? $d['GroupName'] ?? ''
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  by={2}  target={3}" -f \`
            $_.TimeCreated, $_.Id, $by, $target)
    }
} else {
    Write-Output "  [i] No account-change events in window"
}
Write-Output ""

# ── SECTION 4: PowerShell Script Block Logging ────────────────────────────────
# 4103=Module logging, 4104=Script block (most valuable — shows decoded commands)
Write-Output "===== POWERSHELL SCRIPT BLOCK LOG (4104) ====="
$psEvents = Get-FilteredEvents \`
    -LogName 'Microsoft-Windows-PowerShell/Operational' \`
    -Ids @(4104) -Cutoff $cutoff -Max $MaxEvents
if ($psEvents) {
    # Filter out trivial blocks (prompt, tab completion noise)
    $interesting = $psEvents | Where-Object {
        $_.Message.Length -gt 80 -and
        $_.Message -notmatch 'Get-PSReadlineOption|prompt\b|TabExpansion'
    } | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents

    if ($interesting) {
        $interesting | ForEach-Object {
            $x = [xml]$_.ToXml()
            $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
            $script = ($d['ScriptBlockText'] ?? '').Trim() -replace '\s+', ' '
            $preview = if ($script.Length -gt 200) { $script.Substring(0,200) + '...' } else { $script }
            Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  {1}" -f $_.TimeCreated, $preview)
        }
    } else {
        Write-Output "  [i] No substantial script blocks in window"
    }
} else {
    Write-Output "  [i] PowerShell/Operational log empty or not enabled"
    Write-Output "  [!] To enable: Set-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1"
}
Write-Output ""

# ── SECTION 5: New Service Installations ──────────────────────────────────────
# 7045=New service installed — classic persistence and lateral movement indicator
Write-Output "===== NEW SERVICES INSTALLED (7045) ====="
$svcEvents = Get-FilteredEvents -LogName 'System' -Ids @(7045) -Cutoff $cutoff -Max $MaxEvents
if ($svcEvents) {
    $svcEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  name={1}  type={2}  path={3}  account={4}" -f \`
            $_.TimeCreated, $d['ServiceName'], $d['ServiceType'], $d['ImagePath'], $d['AccountName'])
    }
} else {
    Write-Output "  [i] No new services installed in window"
}
Write-Output ""

# ── SECTION 6: Kerberos Authentication ────────────────────────────────────────
# 4768=TGT request, 4769=TGS request, 4771=Pre-auth failed (brute force / spray)
# 4776=NTLM authentication
Write-Output "===== KERBEROS / NTLM (4768/4769/4771/4776) ====="
$kerbEvents = Get-FilteredEvents -LogName 'Security' -Ids @(4768,4769,4771,4776) -Cutoff $cutoff -Max $MaxEvents
if ($kerbEvents) {
    # Focus on failures and interesting targets
    $kerbEvents | Where-Object {
        $x = [xml]$_.ToXml()
        $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
        # 4771 failure codes; 4769 with failure status; 4776 with error
        $_.Id -eq 4771 -or
        ($_.Id -eq 4769 -and $d['Status'] -ne '0x0') -or
        ($_.Id -eq 4776 -and $d['Status'] -ne '0x0')
    } | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents | ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
        $user   = $d['TargetUserName'] ?? $d['ClientName'] ?? '-'
        $status = $d['Status'] ?? $d['ErrorCode'] ?? '-'
        $srcIp  = $d['IPAddress'] ?? '-'
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  user={2}  status={3}  src={4}" -f \`
            $_.TimeCreated, $_.Id, $user, $status, $srcIp)
    }

    # Summary count
    $failCount = ($kerbEvents | Where-Object { $_.Id -eq 4771 }).Count
    if ($failCount -gt 0) {
        Write-Output ""
        Write-Output "  [!] Kerberos pre-auth failures (4771): $failCount in window"
    }
} else {
    Write-Output "  [i] No Kerberos/NTLM events in window (may not be a DC)"
}
Write-Output ""

# ── SECTION 7: WinRM / Remoting ───────────────────────────────────────────────
# 91=WSMan create shell, 168=auth attempt
Write-Output "===== WINRM CONNECTIONS (Microsoft-Windows-WinRM/Operational) ====="
$winrmEvents = Get-FilteredEvents \`
    -LogName 'Microsoft-Windows-WinRM/Operational' \`
    -Ids @(91,168) -Cutoff $cutoff -Max $MaxEvents
if ($winrmEvents) {
    $winrmEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  {2}" -f \`
            $_.TimeCreated, $_.Id, ($_.Message -split "\`n")[0])
    }
} else {
    Write-Output "  [i] No WinRM events in window"
}
Write-Output ""

# ── SECTION 8: Defender / Windows Security Events ─────────────────────────────
# 1102=Audit log cleared (!!), 1100=Event log service stopped
# 4719=Audit policy changed
Write-Output "===== TAMPER INDICATORS (1100/1102/4719) ====="
$tamperEvents = Get-FilteredEvents -LogName 'Security' -Ids @(1100,1102,4719) -Cutoff $cutoff -Max 20
if ($tamperEvents) {
    $tamperEvents | Sort-Object TimeCreated | ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
        $by = $d['SubjectUserName'] ?? $d['UserData'] ?? 'unknown'
        Write-Output ("  [!!] {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  by={2}  {3}" -f \`
            $_.TimeCreated, $_.Id,
            $by,
            $(if ($_.Id -eq 1102) {'SECURITY LOG CLEARED'} elseif ($_.Id -eq 1100) {'EVENT LOG SERVICE STOPPED'} else {'Audit policy changed'}))
    }
} else {
    Write-Output "  [+] No log-tamper events detected"
}
Write-Output ""

# ── SECTION 9: Scheduled Task Creation ────────────────────────────────────────
# 4698=Scheduled task created, 4702=Updated, 4699=Deleted
Write-Output "===== SCHEDULED TASK EVENTS (4698/4699/4702) ====="
$taskEvents = Get-FilteredEvents -LogName 'Security' -Ids @(4698,4699,4702) -Cutoff $cutoff -Max $MaxEvents
if ($taskEvents) {
    $taskEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
        $x = [xml]$_.ToXml()
        $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
        $action = switch ($_.Id) { 4698 {'CREATED'} 4699 {'DELETED'} 4702 {'UPDATED'} }
        $by     = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"
        $name   = $d['TaskName'] ?? '-'
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  {1}  by={2}  task={3}" -f \`
            $_.TimeCreated, $action, $by, $name)
    }
} else {
    Write-Output "  [i] No scheduled task changes in window"
}
Write-Output ""

# ── Quick Statistics ──────────────────────────────────────────────────────────
Write-Output "===== SUMMARY ====="
Write-Output "  Logon events     : $($logonEvents.Count)"
Write-Output "  Failed logons    : $(($logonEvents | Where-Object Id -eq 4625).Count)"
Write-Output "  Explicit creds   : $(($logonEvents | Where-Object Id -eq 4648).Count)"
Write-Output "  PS script blocks : $($psEvents.Count)"
Write-Output "  New services     : $($svcEvents.Count)"
Write-Output "  Acct changes     : $($acctEvents.Count)"
Write-Output "  Task changes     : $($taskEvents.Count)"
Write-Output "  Tamper events    : $($tamperEvents.Count)"
Write-Output ""
Write-Output "===== END EVENT LOG FORENSICS ====="
`
  },

  // ══════════════════════════════════════════════════════ DEFENDER EXCLUSIONS
  {
    id:         "defender-exclusions",
    category:   "Triage",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "defender-exclusions.ps1",
    shortDesc:  "AV exclusions, ASR rules, tamper protection, recent detections",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1562","T1562.001"],
    description: "Enumerates all Windows Defender exclusion paths, processes, extensions, and IP ranges. Checks ASR rule configuration and flags disabled rules. Shows tamper protection state, recent Defender configuration changes from event log (5007), and threat detections from the past 7 days.",
    usage: `runscript -CloudFile="triage/defender-exclusions.ps1"`,
    source: `<#
.SYNOPSIS
    Defender Exclusions — enumerate all AV exclusions and recent configuration changes.

.DESCRIPTION
    Enumerates all Windows Defender exclusion paths, processes, extensions, IP ranges,
    and ASR rule exceptions. Attackers frequently add exclusions to bypass real-time
    protection before dropping payloads. Also checks Defender's operational health,
    tamper protection state, and recent configuration changes from the event log.

    This script is read-only and makes no changes to Defender configuration.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.EXAMPLE
    runscript -CloudFile="triage/defender-exclusions.ps1"
#>

$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Output "===== WINDOWS DEFENDER EXCLUSIONS ====="
Write-Output "Host      : $env:COMPUTERNAME"
Write-Output "Operator  : $env:USERNAME"
Write-Output "Time      : $ts"
Write-Output ""

# ── SECTION 1: Defender Status ────────────────────────────────────────────────
Write-Output "===== DEFENDER STATUS ====="
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    $realtime = if ($mpStatus.RealTimeProtectionEnabled) { "[ENABLED]" } else { "[!!] DISABLED" }
    $tamper   = if ($mpStatus.IsTamperProtected)         { "[ENABLED]" } else { "[WARNING] Tamper protection off" }
    $cloud    = if ($mpStatus.CloudProtectionEnabled)    { "Enabled"   } else { "Disabled" }

    Write-Output "  Real-time protection : $realtime"
    Write-Output "  Tamper protection    : $tamper"
    Write-Output "  Cloud protection     : $cloud"
    Write-Output "  Anti-spyware enabled : $($mpStatus.AntiSpywareEnabled)"
    Write-Output "  Antivirus enabled    : $($mpStatus.AntivirusEnabled)"
    Write-Output "  Behavior monitor     : $($mpStatus.BehaviorMonitorEnabled)"
    Write-Output "  NIS enabled          : $($mpStatus.NisEnabled)"
    Write-Output ""
    Write-Output "  Engine version       : $($mpStatus.AMEngineVersion)"
    Write-Output "  Signature version    : $($mpStatus.AntivirusSignatureVersion)"
    Write-Output "  Signature age (days) : $($mpStatus.AntivirusSignatureAge)"
    Write-Output "  Last full scan       : $($mpStatus.FullScanEndTime)"
    Write-Output "  Last quick scan      : $($mpStatus.QuickScanEndTime)"
} catch {
    Write-Output "  [!] Could not query Defender status: $_"
}
Write-Output ""

# ── SECTION 2: Exclusion Paths ────────────────────────────────────────────────
Write-Output "===== EXCLUSION PATHS ====="
try {
    $prefs = Get-MpPreference -ErrorAction Stop
    if ($prefs.ExclusionPath) {
        $prefs.ExclusionPath | Sort-Object | ForEach-Object {
            # Flag paths in high-risk locations
            $risk = ""
            if ($_ -match 'Temp|AppData|ProgramData|Users\\Public|Downloads|\\Tmp|C:\\Windows\\Temp') {
                $risk = "  [!!] HIGH-RISK PATH"
            }
            Write-Output "  $_$risk"
        }
    } else {
        Write-Output "  [+] No path exclusions configured"
    }
} catch {
    Write-Output "  [!] Could not query exclusions: $_"
}
Write-Output ""

# ── SECTION 3: Exclusion Processes ───────────────────────────────────────────
Write-Output "===== EXCLUSION PROCESSES ====="
try {
    $prefs = Get-MpPreference -ErrorAction Stop
    if ($prefs.ExclusionProcess) {
        $prefs.ExclusionProcess | Sort-Object | ForEach-Object {
            $risk = ""
            if ($_ -match 'powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin') {
                $risk = "  [!!] LOLBIN EXCLUSION"
            }
            Write-Output "  $_$risk"
        }
    } else {
        Write-Output "  [+] No process exclusions configured"
    }
} catch {
    Write-Output "  [!] Could not query process exclusions: $_"
}
Write-Output ""

# ── SECTION 4: Extension Exclusions ──────────────────────────────────────────
Write-Output "===== EXCLUSION EXTENSIONS ====="
try {
    $prefs = Get-MpPreference -ErrorAction Stop
    if ($prefs.ExclusionExtension) {
        $prefs.ExclusionExtension | Sort-Object | ForEach-Object {
            $risk = ""
            if ($_ -match '\.exe|\.dll|\.ps1|\.bat|\.vbs|\.js|\.hta|\.wsf|\.scr|\.pif') {
                $risk = "  [!!] EXECUTABLE EXTENSION"
            }
            Write-Output "  $_$risk"
        }
    } else {
        Write-Output "  [+] No extension exclusions configured"
    }
} catch {
    Write-Output "  [!] Could not query extension exclusions: $_"
}
Write-Output ""

# ── SECTION 5: IP / Threat Exclusions ────────────────────────────────────────
Write-Output "===== EXCLUSION IP RANGES / THREAT NAMES ====="
try {
    $prefs = Get-MpPreference -ErrorAction Stop
    if ($prefs.ExclusionIpAddress) {
        Write-Output "  IP Ranges:"
        $prefs.ExclusionIpAddress | ForEach-Object { Write-Output "    $_" }
    } else {
        Write-Output "  [+] No IP exclusions configured"
    }
    if ($prefs.ThreatIDDefaultAction_Ids) {
        Write-Output "  Threat ID overrides:"
        $prefs.ThreatIDDefaultAction_Ids | ForEach-Object { Write-Output "    ThreatID: $_" }
    }
} catch {
    Write-Output "  [!] Could not query IP/threat exclusions: $_"
}
Write-Output ""

# ── SECTION 6: ASR Rules State ────────────────────────────────────────────────
Write-Output "===== ATTACK SURFACE REDUCTION (ASR) RULES ====="
$asrRuleNames = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office apps from creating child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b3" = "Block credential stealing from LSASS"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email/webmail"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files unless they meet prevalence criteria"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JS/VBS from launching downloaded executable"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office apps from creating executable content"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office apps from injecting into processes"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication app from creating child processes"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations from PSExec/WMI"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted/unsigned USB processes"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
}

try {
    $prefs = Get-MpPreference -ErrorAction Stop
    $ruleIds     = $prefs.AttackSurfaceReductionRules_Ids
    $ruleActions = $prefs.AttackSurfaceReductionRules_Actions

    if ($ruleIds) {
        for ($i = 0; $i -lt $ruleIds.Count; $i++) {
            $id     = $ruleIds[$i]
            $action = switch ($ruleActions[$i]) { 0 {'Disabled'} 1 {'Block'} 2 {'Audit'} 6 {'Warn'} default {"Action=$($ruleActions[$i])"} }
            $name   = $asrRuleNames[$id.ToLower()] ?? $id
            $flag   = if ($action -eq 'Disabled') { "  [!]" } else { "     " }
            Write-Output "$flag  [$action]  $name"
        }
    } else {
        Write-Output "  [i] No ASR rules configured (may be consumer/non-E5 license)"
    }
} catch {
    Write-Output "  [!] Could not query ASR rules: $_"
}
Write-Output ""

# ── SECTION 7: Recent Defender Config Changes (Event Log) ─────────────────────
# Event 5007 in Microsoft-Windows-Windows Defender/Operational = config change
Write-Output "===== RECENT DEFENDER CONFIG CHANGES (last 48h, Event 5007) ====="
try {
    $defEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Windows Defender/Operational'
        Id        = 5007
        StartTime = (Get-Date).AddHours(-48)
    } -MaxEvents 50 -ErrorAction Stop

    $defEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
        # Event message contains the old and new value
        $msg = $_.Message -replace '\s+', ' '
        # Extract the changed setting
        if ($msg -match 'HKLM\\SOFTWARE\\(.+?) = (.+)$') {
            Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  {1}" -f $_.TimeCreated, $matches[0])
        } else {
            Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  {1}" -f $_.TimeCreated, ($msg | Select-Object -First 1))
        }
    }
} catch {
    if ($_.Exception.Message -match 'No events') {
        Write-Output "  [+] No Defender configuration changes in last 48h"
    } else {
        Write-Output "  [!] Could not query Defender event log: $_"
    }
}
Write-Output ""

# ── SECTION 8: Defender Detections (recent threats) ──────────────────────────
Write-Output "===== RECENT THREAT DETECTIONS (last 7 days) ====="
try {
    $threats = Get-MpThreatDetection -ErrorAction Stop |
        Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-7) } |
        Sort-Object InitialDetectionTime -Descending |
        Select-Object -First 20

    if ($threats) {
        $threats | ForEach-Object {
            $t       = Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue
            $name    = $t.ThreatName ?? "ThreatID:$($_.ThreatID)"
            $severity = $t.SeverityID ?? '-'
            Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  [{1}]  {2}" -f \`
                $_.InitialDetectionTime, $severity, $name)
            Write-Output "    Resources: $($_.Resources -join ', ')"
        }
    } else {
        Write-Output "  [+] No threat detections in last 7 days"
    }
} catch {
    Write-Output "  [!] Could not query threat detections: $_"
}
Write-Output ""

Write-Output "===== END DEFENDER EXCLUSIONS ====="
`
  },

  // ══════════════════════════════════════════════════════ SHADOW COPY STATUS
  {
    id:         "shadow-copy-status",
    category:   "File System IOCs",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "shadow-copy-status.ps1",
    shortDesc:  "VSS copies, deletion evidence, bcdedit recovery state",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1490"],
    description: "Ransomware almost always deletes Volume Shadow Copies before encryption. Enumerates existing shadow copies, checks VSS service and writer state, searches event logs for shadow-deletion commands (vssadmin/wmic/bcdedit), and checks boot recovery configuration. Run early during ransomware triage to confirm scope and whether recovery paths exist.",
    usage: `runscript -CloudFile="file-system-iocs/shadow-copy-status.ps1"`,
    source: `<#
.SYNOPSIS
    Shadow Copy / VSS Status — enumerate copies, service state, and deletion evidence.

.DESCRIPTION
    Ransomware almost always deletes Volume Shadow Copies before or during encryption
    to prevent recovery. This script enumerates existing shadow copies, checks the VSS
    service and writer state, and looks for evidence of recent shadow copy deletion in
    the event log. Also shows backup configuration (wbadmin) and System Restore state.

    Run early during ransomware triage to confirm scope and whether recovery paths exist.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.EXAMPLE
    runscript -CloudFile="file-system-iocs/shadow-copy-status.ps1"
#>

$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Output "===== SHADOW COPY / VSS STATUS ====="
Write-Output "Host      : $env:COMPUTERNAME"
Write-Output "Operator  : $env:USERNAME"
Write-Output "Time      : $ts"
Write-Output ""

# ── SECTION 1: VSS Service State ──────────────────────────────────────────────
Write-Output "===== VSS SERVICE STATE ====="
try {
    $vss = Get-Service -Name VSS -ErrorAction Stop
    $state = if ($vss.Status -eq 'Running') { "[RUNNING]" } elseif ($vss.Status -eq 'Stopped') { "[STOPPED]" } else { "[$($vss.Status)]" }
    Write-Output "  Volume Shadow Copy (VSS) : $state  StartType: $($vss.StartType)"
} catch {
    Write-Output "  [!] Could not query VSS service: $_"
}

# Also check SWPRV (Microsoft Software Shadow Copy Provider)
try {
    $swprv = Get-Service -Name SWPRV -ErrorAction Stop
    Write-Output "  SW Shadow Copy Provider  : [$($swprv.Status)]  StartType: $($swprv.StartType)"
} catch { }
Write-Output ""

# ── SECTION 2: Existing Shadow Copies ────────────────────────────────────────
Write-Output "===== EXISTING SHADOW COPIES ====="
try {
    $shadows = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop |
        Sort-Object InstallDate -Descending

    if ($shadows) {
        Write-Output "  Count: $($shadows.Count)"
        Write-Output ""
        $shadows | ForEach-Object {
            $sizeGB = if ($_.Count) { [math]::Round($_.Count / 1GB, 2) } else { '?' }
            Write-Output "  ID      : $($_.ID)"
            Write-Output "  Volume  : $($_.VolumeName)  →  $($_.DeviceObject)"
            Write-Output "  Created : $($_.InstallDate)"
            Write-Output "  SetID   : $($_.SetID)"
            Write-Output ""
        }
    } else {
        Write-Output "  [!!] NO SHADOW COPIES EXIST — recovery via VSS not possible"
    }
} catch {
    Write-Output "  [!] Could not query shadow copies: $_"
}

# ── SECTION 3: Volume Shadow Copy Storage ────────────────────────────────────
Write-Output "===== VSS STORAGE ALLOCATION (vssadmin) ====="
try {
    $vssadmin = & vssadmin list shadowstorage 2>&1
    $vssadmin | ForEach-Object { Write-Output "  $_" }
} catch {
    Write-Output "  [!] vssadmin not available: $_"
}
Write-Output ""

# ── SECTION 4: VSS Writers State ─────────────────────────────────────────────
Write-Output "===== VSS WRITERS STATE ====="
try {
    $writers = & vssadmin list writers 2>&1
    # Flag any writers with errors
    $inWriter = $false; $writerName = ""; $state = ""; $lastError = ""
    $writers | ForEach-Object {
        if ($_ -match 'Writer name:') {
            $writerName = $_ -replace '.*Writer name:\s*', '' -replace "'", ""
            $inWriter = $true; $state = ""; $lastError = ""
        } elseif ($_ -match 'State:') {
            $state = $_ -replace '.*State:\s*', ''
        } elseif ($_ -match 'Last error:') {
            $lastError = $_ -replace '.*Last error:\s*', ''
            if ($state -notmatch 'Stable' -or $lastError -notmatch 'No error') {
                Write-Output "  [!] $writerName"
                Write-Output "      State: $state  LastError: $lastError"
            }
        }
    }
    Write-Output "  [i] Writers with errors shown above. All others stable."
} catch {
    Write-Output "  [!] vssadmin writers query failed: $_"
}
Write-Output ""

# ── SECTION 5: Evidence of Shadow Copy Deletion (Event Log) ──────────────────
# Event 8224 = VSS service shut down (can precede deletion)
# Check Application log for backup events, and Security for vssadmin/wmic usage
Write-Output "===== SHADOW COPY DELETION EVIDENCE (Event Log, last 7 days) ====="
$cutoff7d = (Get-Date).AddDays(-7)

# VSS events in Application log
try {
    $vssAppEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Application'
        ProviderName = 'VSS'
        StartTime = $cutoff7d
    } -MaxEvents 50 -ErrorAction Stop

    if ($vssAppEvents) {
        Write-Output "  VSS Application Events:"
        $vssAppEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
            Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  {2}" -f \`
                $_.TimeCreated, $_.Id, (($_.Message -split "\`n")[0] -replace '\s+', ' '))
        }
    }
} catch { }

# Check Security log for vssadmin / wmic process creation that deleted shadows
# 4688 = Process creation (requires audit policy)
try {
    $procEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4688
        StartTime = $cutoff7d
    } -MaxEvents 500 -ErrorAction Stop |
    Where-Object {
        $_.Message -match 'vssadmin|wmic|wbadmin|diskshadow|bcdedit' -and
        $_.Message -match 'delete|shadows|resize|shadowstorage'
    }

    if ($procEvents) {
        Write-Output ""
        Write-Output "  [!!] Suspicious shadow-deletion commands detected in Security log:"
        $procEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
            $x = [xml]$_.ToXml()
            $d = @{}; $x.Event.EventData.Data | ForEach-Object { if ($_.Name) { $d[$_.Name] = $_.'#text' } }
            $by  = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])"
            $cmd = $d['CommandLine'] ?? $d['NewProcessName'] ?? '-'
            Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  by={1}  cmd={2}" -f $_.TimeCreated, $by, $cmd)
        }
    } else {
        Write-Output "  [+] No shadow-deletion commands found in Security log (4688)"
        Write-Output "      Note: Requires 'Audit Process Creation' to be enabled"
    }
} catch {
    if ($_.Exception.Message -notmatch 'No events') {
        Write-Output "  [i] Process creation audit may not be enabled (4688 events unavailable)"
    }
}
Write-Output ""

# ── SECTION 6: Windows Backup Status ─────────────────────────────────────────
Write-Output "===== WINDOWS BACKUP / WBADMIN ====="
try {
    $wbStatus = & wbadmin get status 2>&1
    $wbStatus | ForEach-Object { Write-Output "  $_" }
} catch {
    Write-Output "  [i] wbadmin not available"
}
Write-Output ""

# ── SECTION 7: System Restore Points ─────────────────────────────────────────
Write-Output "===== SYSTEM RESTORE POINTS ====="
try {
    $restorePoints = Get-ComputerRestorePoint -ErrorAction Stop |
        Sort-Object CreationTime -Descending

    if ($restorePoints) {
        $restorePoints | Select-Object -First 10 |
            Format-Table -AutoSize @{N='Created';E={$_.CreationTime}}, Description, RestorePointType |
            Out-String | Write-Output
    } else {
        Write-Output "  [i] No restore points found (may be disabled or server OS)"
    }
} catch {
    Write-Output "  [i] System Restore query failed (may be disabled): $_"
}
Write-Output ""

# ── SECTION 8: Boot Recovery Config ──────────────────────────────────────────
# Ransomware disables recovery via bcdedit /set recoveryenabled No
Write-Output "===== BOOT RECOVERY CONFIG (bcdedit) ====="
try {
    $bcd = & bcdedit /enum current 2>&1
    $recoveryLine = $bcd | Where-Object { $_ -match 'recoveryenabled' }
    if ($recoveryLine) {
        if ($recoveryLine -match 'No') {
            Write-Output "  [!!] Recovery DISABLED — bcdedit /set recoveryenabled No detected"
        } else {
            Write-Output "  [+] Recovery enabled: $recoveryLine"
        }
    } else {
        Write-Output "  [+] No explicit recovery override found"
    }
} catch {
    Write-Output "  [i] bcdedit query failed: $_"
}
Write-Output ""

Write-Output "===== END SHADOW COPY STATUS ====="
`
  },

  // ══════════════════════════════════════════════════════ REGISTRY FORENSICS
  {
    id:         "registry-forensics",
    category:   "Artefact Collection",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "registry-forensics.ps1",
    shortDesc:  "UserAssist, BAM, ShimCache, RecentDocs, Run keys",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1547.001","T1552.001","T1083"],
    description: "Extracts execution evidence from Windows registry artefacts that persist after binaries are deleted. Covers UserAssist (GUI app launches with ROT13 decode), BAM/DAM (execution timestamps per user), ShimCache/AppCompatCache, RecentDocs MRU, Explorer typed paths/search history, and Run/RunOnce autorun keys.",
    usage: `runscript -CloudFile="artefact-collection/registry-forensics.ps1"`,
    source: `<#
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
`
  },

  // ══════════════════════════════════════════════════════ NAMED PIPES
  {
    id:         "named-pipes",
    category:   "Lateral Movement",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    os: "windows",
    name:       "named-pipes.ps1",
    shortDesc:  "C2 pipe patterns — Cobalt Strike, Sliver, Havoc, Metasploit",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1021.002","T1559.001"],
    description: "C2 frameworks use named pipes for IPC, SMB lateral movement, and beacon staging. Enumerates all named pipes on the host using Win32 P/Invoke, maps to owning process where possible, and flags pipes matching known C2 framework patterns (Cobalt Strike, Metasploit, Sliver, Havoc, PoshC2). Checks SMB-accessible pipes via IPC$ share.",
    usage: `runscript -CloudFile="lateral-movement/named-pipes.ps1"`,
    source: `<#
.SYNOPSIS
    Named Pipes — enumerate all pipes, map to processes, flag C2 framework defaults.

.DESCRIPTION
    C2 frameworks (Cobalt Strike, Metasploit, Sliver, Havoc, Brute Ratel) use named
    pipes for inter-process communication, SMB lateral movement, and beacon staging.
    Several have well-known default pipe names that are trivially detectable.

    This script enumerates all named pipes on the local host, maps each to its owning
    process where possible, and flags pipes matching known C2 patterns. It also checks
    for pipes accessible via the network (potential SMB C2 channel).

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.EXAMPLE
    runscript -CloudFile="lateral-movement/named-pipes.ps1"
#>

$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
Write-Output "===== NAMED PIPES ====="
Write-Output "Host      : $env:COMPUTERNAME"
Write-Output "Operator  : $env:USERNAME"
Write-Output "Time      : $ts"
Write-Output ""

# ── Known C2 / Suspicious Pipe Patterns ──────────────────────────────────────
# Sources: threat intel, vendor research, public C2 framework defaults
$c2Patterns = [ordered]@{
    # Cobalt Strike defaults (many operators forget to change these)
    'Cobalt Strike'    = @('\\\\.\\pipe\\MSSE-[0-9a-f]+-server','\\\\.\\pipe\\status_[0-9a-f]+',
                           '\\\\.\\pipe\\msagent_[0-9a-f]+','\\\\.\\pipe\\halfduplex',
                           '\\\\.\\pipe\\postex_[0-9a-f]+','\\\\.\\pipe\\postex_ssh_[0-9a-f]+',
                           '\\\\.\\pipe\\dce_[0-9a-f]+','\\\\.\\pipe\\mojo\.[0-9]+\.[0-9]+\.',
                           '\\\\.\\pipe\\interprocess_[0-9]+')
    # Metasploit / Meterpreter
    'Metasploit'       = @('\\\\.\\pipe\\[a-zA-Z0-9]{16,}$')   # random-length, no extension
    # Sliver C2
    'Sliver'           = @('\\\\.\\pipe\\[0-9a-f]{8}-[0-9a-f]{4}','\\\\.\\pipe\\svcctl')
    # Havoc C2
    'Havoc'            = @('\\\\.\\pipe\\havoc[a-z_]+','\\\\.\\pipe\\NamedPipe_[0-9a-f]+')
    # PoshC2
    'PoshC2'           = @('\\\\.\\pipe\\PoshC2','\\\\.\\pipe\\posh[a-z]')
    # Common LOLBin / living-off-the-land pipes used for injection
    'Suspicious'       = @('\\\\.\\pipe\\[Cc]hrome\.[0-9]+\.[0-9]+\.',  # fake Chrome pipe
                           '\\\\.\\pipe\\[Cc]hromium\.[0-9]+',
                           '\\\\.\\pipe\\DserNamePipe')
}

function Test-C2Pipe {
    param([string]$Name)
    $lowerName = $Name.ToLower()
    foreach ($framework in $c2Patterns.Keys) {
        foreach ($pattern in $c2Patterns[$framework]) {
            if ($lowerName -match ($pattern.ToLower() -replace '\\\\.\\\\pipe\\\\','\\\\pipe\\\\')) {
                return $framework
            }
        }
    }
    return $null
}

# ── SECTION 1: Enumerate All Named Pipes ─────────────────────────────────────
Write-Output "===== ALL NAMED PIPES ====="

# Use .NET to get pipe names
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class PipeHelper {
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr FindFirstFile(string lpFileName, out WIN32_FIND_DATA lpFindFileData);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FindNextFile(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool FindClose(IntPtr hFindFile);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct WIN32_FIND_DATA {
        public uint dwFileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
        public uint nFileSizeHigh;
        public uint nFileSizeLow;
        public uint dwReserved0;
        public uint dwReserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string cFileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
        public string cAlternateFileName;
    }

    public static List<string> GetPipes() {
        var pipes = new List<string>();
        WIN32_FIND_DATA data;
        var handle = FindFirstFile(@"\\.\pipe\*", out data);
        if (handle == IntPtr.Zero || handle.ToInt64() == -1) return pipes;
        do {
            pipes.Add(data.cFileName);
        } while (FindNextFile(handle, out data));
        FindClose(handle);
        return pipes;
    }
}
"@ -ErrorAction SilentlyContinue

# Build process handle→PID map for pipe ownership
$processPipes = @{}
try {
    # Use handle.exe if available, otherwise skip process mapping
    $handleExe = Get-Command handle.exe -ErrorAction SilentlyContinue
    if (-not $handleExe) {
        # Fallback: use Get-Process to at least map well-known names
    }
} catch { }

# Get all pipes
$allPipes = @()
try {
    $allPipes = [PipeHelper]::GetPipes()
} catch {
    # Fallback: use .NET Directory approach
    try {
        $allPipes = [System.IO.Directory]::GetFiles('\\.\pipe\') |
            ForEach-Object { Split-Path $_ -Leaf }
    } catch {
        Write-Output "  [!] Could not enumerate pipes via PipeHelper or Directory: $_"
    }
}

if (-not $allPipes) {
    # Last resort: parse 'pipelist' or 'handle' output if available
    Write-Output "  [!] Primary pipe enumeration failed, trying pipelist.exe..."
    try {
        $pl = & pipelist.exe /accepteula 2>&1
        $allPipes = $pl | Where-Object { $_ -match '\\\\' } |
            ForEach-Object { ($_ -split '\s+')[0] }
    } catch { }
}

Write-Output "  Total pipes found: $($allPipes.Count)"
Write-Output ""

$suspicious = [System.Collections.Generic.List[object]]::new()
$allPipes | Sort-Object | ForEach-Object {
    $pipe    = $_
    $fullPath = "\\.\pipe\$pipe"

    # Flag C2 patterns
    $c2match = Test-C2Pipe $fullPath
    if ($c2match) {
        $suspicious.Add([pscustomobject]@{ Name = $pipe; Match = $c2match })
        Write-Output "  [!!] $pipe  ← MATCHES $c2match PATTERN"
    }
}

# Print all pipes grouped
$knownSystemPipes = @(
    'lsass','srvsvc','netlogon','samr','wkssvc','ntsvcs','svcctl','eventlog',
    'spoolss','epmapper','LocalSpooler','atsvc','DAV RPC SERVICE','InitShutdown',
    'LSM_API_service','ROUTER','scerpc','ntsvcs','LSA','winreg','browser',
    'PIPE_EVENTROOT','TermSrv_API_service','Ctx_WinStation_API_service'
)

Write-Output ""
Write-Output "  All pipes (non-system):"
$allPipes | Sort-Object | ForEach-Object {
    $isSystem = $knownSystemPipes | Where-Object { $_ -like "*$_*" }
    if (-not ($_ -match ('^(' + ($knownSystemPipes -join '|') + ')$'))) {
        Write-Output "    $_"
    }
}
Write-Output ""

# ── SECTION 2: C2 Matches Summary ────────────────────────────────────────────
Write-Output "===== C2 PATTERN MATCHES ====="
if ($suspicious.Count -gt 0) {
    $suspicious | ForEach-Object {
        Write-Output "  [!!] MATCH: $($_.Match)"
        Write-Output "       Pipe : $($_.Name)"
        Write-Output ""
    }
} else {
    Write-Output "  [+] No pipes matching known C2 framework patterns"
    Write-Output ""
    Write-Output "  Checked patterns: Cobalt Strike, Metasploit, Sliver, Havoc, PoshC2"
}
Write-Output ""

# ── SECTION 3: SMB-accessible Pipes ──────────────────────────────────────────
# The IPC$ share exposes certain pipes over the network
Write-Output "===== SMB-ACCESSIBLE PIPES (via IPC$) ====="
try {
    $netShare = & net share IPC$ 2>&1
    $netShare | ForEach-Object { Write-Output "  $_" }
    Write-Output ""
    Write-Output "  Pipes accessible via SMB (net file / session):"
    $netFile = & net file 2>&1
    $netFile | ForEach-Object { Write-Output "  $_" }
} catch {
    Write-Output "  [i] Could not enumerate SMB pipe sessions: $_"
}
Write-Output ""

# ── SECTION 4: Process → Pipe Mapping (best-effort) ──────────────────────────
Write-Output "===== PROCESS OPEN HANDLES (best-effort via handle.exe) ====="
Write-Output "  Note: For full process→pipe mapping, run handle.exe from Sysinternals"
Write-Output "  with: handle.exe -a -t pipe"
Write-Output ""
Write-Output "  Checking for handle.exe in PATH..."
try {
    $h = & handle.exe -accepteula -a -t pipe 2>&1
    if ($h -match 'File  \\Device\\NamedPipe\\') {
        $h | Where-Object { $_ -match 'NamedPipe' } |
            ForEach-Object { Write-Output "  $_" }
    } else {
        Write-Output "  [i] handle.exe not available — pipe-to-process mapping skipped"
    }
} catch {
    Write-Output "  [i] handle.exe not found in PATH"
}
Write-Output ""

Write-Output "===== END NAMED PIPES ====="
`
  },

  // ══════════════════════════════════════════════════════ LINUX KERNEL MODULES
  {
    id:         "linux-kernel-modules",
    category:   "Persistence",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    os: "linux",
    name:       "kernel-modules.sh",
    shortDesc:  "LKM rootkit detection — rogue modules, hidden modules, DKMS",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1547.006"],
    description: "Rootkits and kernel-level backdoors often load as kernel modules. Enumerates all loaded modules, identifies those without a corresponding .ko file on disk, flags modules loaded from non-standard paths, and cross-references /proc/modules with /sys/module to detect hiding techniques. Checks DKMS, Secure Boot state, and known rootkit module names.",
    usage: `runscript -CloudFile="linux/persistence/kernel-modules.sh"`,
    source: `#!/usr/bin/env bash
# =============================================================================
# Linux Kernel Modules — RTR / IR Script
# IR Phase   : Identification
# Platform   : Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
# Permission : Active Responder
# =============================================================================
# PURPOSE
#   Rootkits and kernel-level backdoors often load as kernel modules (LKM).
#   This script enumerates all loaded modules, checks for modules not present
#   in the package manager database (unsigned/unknown), flags modules loaded
#   from unusual paths, and checks for signs of module hiding techniques.
#
#   Note: A sophisticated rootkit may hide itself from lsmod output; this
#   script cross-references /proc/modules with /sys/module for discrepancies.
#
# USAGE
#   runscript -CloudFile="linux/persistence/kernel-modules.sh"
# =============================================================================

set -uo pipefail

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

echo "===== LINUX KERNEL MODULES ====="
echo "Host     : $HOSTNAME"
echo "Operator : $CURRENT_USER"
echo "Time     : $TIMESTAMP"
echo "Kernel   : $(uname -r)"
echo ""

# =============================================================================
# SECTION 1 — All loaded modules (lsmod)
# =============================================================================
echo "===== ALL LOADED MODULES ====="
if command -v lsmod &>/dev/null; then
  lsmod 2>/dev/null | head -100
else
  echo "  [!] lsmod not available, reading /proc/modules"
  awk '{print $1, $2, $3}' /proc/modules 2>/dev/null | head -100
fi
echo ""

# =============================================================================
# SECTION 2 — Total count and size statistics
# =============================================================================
TOTAL_MODS=$(lsmod 2>/dev/null | tail -n +2 | wc -l || awk 'END{print NR}' /proc/modules)
echo "===== MODULE STATISTICS ====="
echo "  Total loaded modules : $TOTAL_MODS"
echo "  Kernel version       : $(uname -r)"
echo "  Module directory     : /lib/modules/$(uname -r)"
echo ""

# =============================================================================
# SECTION 3 — Modules NOT in package manager (potential rogues)
# Legitimate modules ship with kernel packages or DKMS.
# An unknown module has no corresponding .ko file on disk.
# =============================================================================
echo "===== MODULES WITHOUT .ko FILE ON DISK (potential rogue modules) ====="
MOD_DIR="/lib/modules/$(uname -r)"
ROGUE=0
while IFS= read -r line; do
  modname=$(echo "$line" | awk '{print $1}' | tr '-' '_')
  [ "$modname" = "Module" ] && continue

  # Find .ko file (may be compressed as .ko.xz or .ko.gz)
  found=$(find "$MOD_DIR" -name "\${modname}.ko" -o -name "\${modname}.ko.xz" -o -name "\${modname}.ko.gz" 2>/dev/null | head -1)

  if [ -z "$found" ]; then
    # Double-check with modname substitution (dashes vs underscores)
    modname2=$(echo "$modname" | tr '_' '-')
    found=$(find "$MOD_DIR" -name "\${modname2}.ko" -o -name "\${modname2}.ko.xz" 2>/dev/null | head -1)
  fi

  if [ -z "$found" ]; then
    echo "  [!!] Module '$modname' has NO .ko file in $MOD_DIR"
    # Check if it's a known in-tree built-in
    if grep -q "^$modname$" /lib/modules/$(uname -r)/modules.builtin 2>/dev/null; then
      echo "       (built-in to kernel — likely OK)"
    else
      ROGUE=$((ROGUE+1))
    fi
  fi
done < <(lsmod 2>/dev/null || awk '{print $1}' /proc/modules)

[ "$ROGUE" -eq 0 ] && echo "  [+] All loaded modules have corresponding .ko files"
echo ""

# =============================================================================
# SECTION 4 — Modules loaded from non-standard paths
# Standard: /lib/modules/<kernel-version>/
# Suspicious: /tmp, /dev/shm, /home, /var/tmp, or relative paths
# =============================================================================
echo "===== MODULES FROM UNUSUAL LOAD PATHS ====="
UNUSUAL=0
# /proc/modules column 6 is the live file path (not always populated)
while IFS= read -r line; do
  modname=$(echo "$line" | awk '{print $1}')
  modpath=$(echo "$line" | awk '{print $6}')  # may be empty
  [ -z "$modpath" ] || [ "$modpath" = "-" ] && continue
  if ! echo "$modpath" | grep -qE "^/lib/modules/|^/usr/lib/modules/"; then
    echo "  [!!] $modname loaded from: $modpath"
    UNUSUAL=$((UNUSUAL+1))
  fi
done < /proc/modules 2>/dev/null || true
[ "$UNUSUAL" -eq 0 ] && echo "  [+] All modules loaded from standard paths"
echo ""

# =============================================================================
# SECTION 5 — /sys/module vs /proc/modules discrepancy (rootkit hiding check)
# A rootkit hiding itself from lsmod may still appear in /sys/module or vice versa
# =============================================================================
echo "===== /proc/modules vs /sys/module CROSS-CHECK ====="
if [ -d /sys/module ]; then
  PROC_MODS=$(awk '{print $1}' /proc/modules 2>/dev/null | tr '-' '_' | sort)
  SYS_MODS=$(ls /sys/module/ 2>/dev/null | tr '-' '_' | sort)

  # Modules in /sys/module but not in /proc/modules
  HIDDEN=$(comm -23 <(echo "$SYS_MODS") <(echo "$PROC_MODS") 2>/dev/null | head -20)
  if [ -n "$HIDDEN" ]; then
    echo "  [!!] Modules in /sys/module but NOT in /proc/modules (possible hiding):"
    echo "$HIDDEN" | while read -r m; do echo "    $m"; done
  else
    echo "  [+] No discrepancy between /proc/modules and /sys/module"
  fi
else
  echo "  [i] /sys/module not accessible"
fi
echo ""

# =============================================================================
# SECTION 6 — Recently loaded modules (dmesg timestamp)
# =============================================================================
echo "===== RECENTLY LOADED MODULES (dmesg, last boot) ====="
if command -v dmesg &>/dev/null; then
  dmesg 2>/dev/null | grep -iE "module|insmod|modprobe|loading" | \
    grep -v "# " | tail -30 | while read -r line; do
    echo "  $line"
  done || echo "  [i] No module load messages in dmesg"
else
  echo "  [i] dmesg not available"
fi
echo ""

# =============================================================================
# SECTION 7 — DKMS modules (third-party kernel modules)
# DKMS compiles modules for each kernel — legitimate use includes VirtualBox,
# Nvidia drivers, etc. Unknown DKMS entries are worth investigating.
# =============================================================================
echo "===== DKMS MODULES (third-party compiled) ====="
if command -v dkms &>/dev/null; then
  dkms status 2>/dev/null | while read -r line; do
    echo "  $line"
  done || echo "  [i] No DKMS modules found"
else
  echo "  [i] dkms not installed"
  # Check DKMS tree directly
  if [ -d /var/lib/dkms ]; then
    ls /var/lib/dkms/ 2>/dev/null | while read -r d; do
      echo "  $d"
    done
  fi
fi
echo ""

# =============================================================================
# SECTION 8 — Module signing status
# On Secure Boot systems, unsigned modules should not load.
# =============================================================================
echo "===== MODULE SIGNING / SECURE BOOT ====="
if [ -f /proc/sys/kernel/modules_disabled ]; then
  MODDIS=$(cat /proc/sys/kernel/modules_disabled)
  echo "  kernel.modules_disabled : $MODDIS $([ "$MODDIS" = "1" ] && echo '(no new modules can load)')"
fi

if command -v mokutil &>/dev/null; then
  SB=$(mokutil --sb-state 2>/dev/null || echo "unavailable")
  echo "  Secure Boot state       : $SB"
fi

# Check if any loaded modules are unsigned
if [ -f /proc/sys/kernel/unsupported_modules ] 2>/dev/null; then
  echo "  Unsupported modules     : $(cat /proc/sys/kernel/unsupported_modules)"
fi

# Check dmesg for signature warnings
dmesg 2>/dev/null | grep -iE "module.*signature|unsigned module|required key" | \
  tail -10 | while read -r line; do
  echo "  [!] $line"
done || true
echo ""

# =============================================================================
# SECTION 9 — Notable high-risk modules (known rootkit module names)
# =============================================================================
echo "===== KNOWN ROOTKIT MODULE NAME CHECK ====="
ROOTKIT_NAMES="reptile|diamorphine|drovorub|adore|knark|rkit|azazel|necurs|suterusu|average|rooty"
FOUND_RK=0
while IFS= read -r line; do
  modname=$(echo "$line" | awk '{print $1}')
  if echo "$modname" | grep -iqE "$ROOTKIT_NAMES"; then
    echo "  [!!!] KNOWN ROOTKIT MODULE NAME: $modname"
    FOUND_RK=$((FOUND_RK+1))
  fi
done < <(lsmod 2>/dev/null || awk '{print $1}' /proc/modules) || true
[ "$FOUND_RK" -eq 0 ] && echo "  [+] No modules matching known rootkit names"
echo ""

echo "===== END LINUX KERNEL MODULES ====="
`
  },

  // ══════════════════════════════════════════════════════ LINUX CONTAINER INDICATORS
  {
    id:         "linux-container-indicators",
    category:   "Triage",
    supportedPlatforms: ["crowdstrike","sentinelone"],
    os: "linux",
    name:       "container-indicators.sh",
    shortDesc:  "Container escape risk, Docker socket, privileged containers, K8s",
    irPhase:    "Identification",
    permission: "Active Responder",
    mitre:      ["T1611","T1610"],
    description: "Detects container presence, container escape indicators, exposed Docker sockets, privileged containers, abnormal mounts, and unusual capabilities. Useful both on a container host (find rogue containers) and when the compromised host may itself be inside a container (determine escape risk). Includes Kubernetes pod detection and service account token checks.",
    usage: `runscript -CloudFile="linux/triage/container-indicators.sh"`,
    source: `#!/usr/bin/env bash
# =============================================================================
# Linux Container Indicators — RTR / IR Script
# IR Phase   : Identification
# Platform   : Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+)
# Permission : Active Responder
# =============================================================================
# PURPOSE
#   Detect container presence, container escape indicators, exposed Docker sockets,
#   privileged containers, abnormal mounts, and unusual capabilities. Useful both
#   when responding on a container host (find rogue containers) and when the
#   compromised host itself may be inside a container (determine escape risk).
#
# USAGE
#   runscript -CloudFile="linux/triage/container-indicators.sh"
# =============================================================================

set -uo pipefail

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

echo "===== LINUX CONTAINER INDICATORS ====="
echo "Host     : $HOSTNAME"
echo "Operator : $CURRENT_USER"
echo "Time     : $TIMESTAMP"
echo ""

# =============================================================================
# SECTION 1 — Am I running inside a container?
# =============================================================================
echo "===== CONTAINER SELF-DETECTION ====="
IN_CONTAINER=false

# .dockerenv file
if [ -f /.dockerenv ]; then
  echo "  [!!] /.dockerenv present — this host IS a container"
  IN_CONTAINER=true
fi

# /run/.containerenv (Podman/OCI)
if [ -f /run/.containerenv ]; then
  echo "  [!!] /run/.containerenv present — Podman/OCI container"
  IN_CONTAINER=true
  cat /run/.containerenv 2>/dev/null | head -10 | sed 's/^/    /'
fi

# cgroup check
if grep -q docker /proc/1/cgroup 2>/dev/null; then
  echo "  [!!] /proc/1/cgroup contains 'docker'"
  IN_CONTAINER=true
fi
if grep -q kubepods /proc/1/cgroup 2>/dev/null; then
  echo "  [!!] /proc/1/cgroup contains 'kubepods' — Kubernetes pod"
  IN_CONTAINER=true
fi
if grep -q 'lxc\|containerd' /proc/1/environ 2>/dev/null; then
  echo "  [!!] LXC/containerd environment detected"
  IN_CONTAINER=true
fi

# PID 1 binary
PID1_EXE=$(readlink /proc/1/exe 2>/dev/null || true)
if echo "$PID1_EXE" | grep -qE "pause|tini|dumb-init|s6-svscan"; then
  echo "  [!!] PID 1 is '$PID1_EXE' — typical container init process"
  IN_CONTAINER=true
fi

if [ "$IN_CONTAINER" = "false" ]; then
  echo "  [+] This host does NOT appear to be running inside a container"
fi
echo ""

# =============================================================================
# SECTION 2 — Docker daemon status and version
# =============================================================================
echo "===== DOCKER DAEMON ====="
if command -v docker &>/dev/null; then
  echo "  Docker CLI: $(docker --version 2>/dev/null)"
  if systemctl is-active docker &>/dev/null 2>&1; then
    echo "  Docker daemon: RUNNING"
    docker info 2>/dev/null | grep -E "Server Version|Containers:|Running:|Paused:|Stopped:|Images:|Storage Driver:|Security Options:" | \
      sed 's/^/  /'
  else
    echo "  Docker daemon: NOT RUNNING (or not systemd-managed)"
  fi
else
  echo "  [i] Docker CLI not found"
fi
echo ""

# =============================================================================
# SECTION 3 — Exposed Docker socket (critical privilege escalation vector)
# An exposed /var/run/docker.sock inside a container = full host compromise
# =============================================================================
echo "===== DOCKER SOCKET EXPOSURE ====="
for SOCK in /var/run/docker.sock /run/docker.sock /tmp/docker.sock; do
  if [ -S "$SOCK" ]; then
    PERMS=$(stat -c '%A %U:%G' "$SOCK" 2>/dev/null || stat -f '%Sp %Su:%Sg' "$SOCK" 2>/dev/null)
    echo "  [!!] Docker socket found: $SOCK  ($PERMS)"
    echo "       This allows full container escape if writable"
    # Check if current user can access it
    if [ -r "$SOCK" ] || [ -w "$SOCK" ]; then
      echo "       [!!!] Current user ($CURRENT_USER) CAN ACCESS this socket"
    fi
  fi
done
# Also look for socket bind-mounts
if grep -q 'docker.sock' /proc/mounts 2>/dev/null; then
  echo "  [!!] docker.sock appears in /proc/mounts (bind-mounted into container)"
  grep 'docker.sock' /proc/mounts | sed 's/^/    /'
fi
[ ! -S /var/run/docker.sock ] && [ ! -S /run/docker.sock ] && echo "  [+] No Docker socket found at standard paths"
echo ""

# =============================================================================
# SECTION 4 — Running containers
# =============================================================================
echo "===== RUNNING CONTAINERS ====="
if command -v docker &>/dev/null && systemctl is-active docker &>/dev/null 2>&1; then
  RUNNING=$(docker ps --no-trunc --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}\t{{.Ports}}' 2>/dev/null || true)
  if [ -n "$RUNNING" ]; then
    echo "$RUNNING" | sed 's/^/  /'
  else
    echo "  [i] No running containers"
  fi
  echo ""
  echo "  All containers (including stopped):"
  docker ps -a --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}' 2>/dev/null | sed 's/^/  /' || true
elif command -v crictl &>/dev/null; then
  echo "  (using crictl — likely Kubernetes node)"
  crictl ps 2>/dev/null | sed 's/^/  /' || true
elif command -v podman &>/dev/null; then
  echo "  (using podman)"
  podman ps -a 2>/dev/null | sed 's/^/  /' || true
else
  echo "  [i] No container runtime CLI found (docker/crictl/podman)"
fi
echo ""

# =============================================================================
# SECTION 5 — Privileged containers (escape risk)
# =============================================================================
echo "===== PRIVILEGED CONTAINERS ====="
if command -v docker &>/dev/null && systemctl is-active docker &>/dev/null 2>&1; then
  PRIV_FOUND=0
  docker ps -q 2>/dev/null | while read -r cid; do
    PRIV=$(docker inspect "$cid" --format '{{.HostConfig.Privileged}}' 2>/dev/null || true)
    NAME=$(docker inspect "$cid" --format '{{.Name}}' 2>/dev/null | tr -d '/')
    IMAGE=$(docker inspect "$cid" --format '{{.Config.Image}}' 2>/dev/null || true)
    if [ "$PRIV" = "true" ]; then
      echo "  [!!] PRIVILEGED: $cid  name=$NAME  image=$IMAGE"
      PRIV_FOUND=$((PRIV_FOUND+1))
    fi
    # Check for dangerous capabilities even if not fully privileged
    CAPS=$(docker inspect "$cid" --format '{{.HostConfig.CapAdd}}' 2>/dev/null || true)
    if echo "$CAPS" | grep -qiE "SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|DAC_READ_SEARCH"; then
      echo "  [!] DANGEROUS CAPS: $cid  name=$NAME  caps=$CAPS"
    fi
  done || true
  [ "$PRIV_FOUND" -eq 0 ] && echo "  [+] No privileged containers found" || true
else
  echo "  [i] Docker not running"
fi
echo ""

# =============================================================================
# SECTION 6 — Suspicious mounts (escape indicators)
# Mounting host / or /proc or /sys inside a container enables escape
# =============================================================================
echo "===== SUSPICIOUS MOUNTS ====="
SUSP_MOUNT=0
while IFS= read -r line; do
  src=$(echo "$line" | awk '{print $1}')
  dst=$(echo "$line" | awk '{print $2}')
  # Flag mounts of root filesystem, proc, sys, dev, cgroups
  if echo "$dst" | grep -qE "^/host|^/mnt/host"; then
    echo "  [!!] Host filesystem mount: $line"; SUSP_MOUNT=$((SUSP_MOUNT+1))
  fi
  # Writable /proc or /sys
  if echo "$dst $src" | grep -qE "/proc/sys|/proc/sysrq"; then
    echo "  [!] Sensitive proc mount: $line"; SUSP_MOUNT=$((SUSP_MOUNT+1))
  fi
done < /proc/mounts 2>/dev/null || true
[ "$SUSP_MOUNT" -eq 0 ] && echo "  [+] No obviously suspicious mounts"
echo ""

# =============================================================================
# SECTION 7 — Current process capabilities
# CAP_SYS_ADMIN essentially grants root; combinations can enable escape
# =============================================================================
echo "===== CURRENT PROCESS CAPABILITIES ====="
if [ -f /proc/self/status ]; then
  grep -E "^Cap(Inh|Prm|Eff|Bnd|Amb):" /proc/self/status 2>/dev/null | while read -r line; do
    label=$(echo "$line" | cut -d: -f1)
    hex=$(echo "$line" | cut -d: -f2 | tr -d ' ')
    # Non-zero effective capabilities = elevated
    if [ "$hex" != "0000000000000000" ] && [ -n "$hex" ]; then
      echo "  [!] $label: 0x$hex (non-zero)"
      if command -v capsh &>/dev/null; then
        capsh --decode="$hex" 2>/dev/null | sed 's/^/      /'
      fi
    else
      echo "  $label: 0x$hex"
    fi
  done
fi
echo ""

# =============================================================================
# SECTION 8 — Kubernetes indicators
# =============================================================================
echo "===== KUBERNETES INDICATORS ====="
K8S_FOUND=false
# Service account token (all K8s pods have this by default)
SA_TOKEN="/var/run/secrets/kubernetes.io/serviceaccount/token"
if [ -f "$SA_TOKEN" ]; then
  echo "  [!!] Kubernetes service account token found: $SA_TOKEN"
  echo "       Namespace: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || 'unknown')"
  K8S_FOUND=true
fi
# KUBERNETES_SERVICE_HOST env var
if env 2>/dev/null | grep -q KUBERNETES_SERVICE_HOST; then
  echo "  [!!] KUBERNETES_SERVICE_HOST set — running in a K8s pod"
  env | grep -E "^KUBERNETES_|^K8S_" | sed 's/^/    /'
  K8S_FOUND=true
fi
# kubectl
if command -v kubectl &>/dev/null; then
  echo "  kubectl present: $(kubectl version --client 2>/dev/null | head -1)"
  echo "  Can we access API server?"
  kubectl get pods --all-namespaces 2>&1 | head -5 | sed 's/^/  /'
fi
[ "$K8S_FOUND" = "false" ] && echo "  [+] No Kubernetes indicators detected"
echo ""

echo "===== END LINUX CONTAINER INDICATORS ====="
`
  }

];