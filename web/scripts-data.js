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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
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
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name:       "browser-history.ps1",
    shortDesc:  "Chrome, Edge, Firefox history from all profiles",
    irPhase:    "Identification",
    permission: "Active Responder",
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
    name:       "kill-process.ps1",
    shortDesc:  "Kill process by PID/name — captures evidence first",
    irPhase:    "Containment",
    permission: "Active Responder",
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
    name:       "scheduled-tasks.ps1",
    shortDesc:  "All scheduled tasks with encoded/LOLBin/user-path indicators",
    irPhase:    "Identification",
    permission: "Active Responder",
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
    name:       "startup-entries.ps1",
    shortDesc:  "Run keys, startup folders, IFEO, and autostart services",
    irPhase:    "Identification",
    permission: "Active Responder",
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
    name:       "wmi-subscriptions.ps1",
    shortDesc:  "WMI event filters, consumers, and bindings",
    irPhase:    "Identification",
    permission: "Active Responder",
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
    name:       "smb-sessions.ps1",
    shortDesc:  "Active SMB sessions, open files, and shares",
    irPhase:    "Identification",
    permission: "Active Responder",
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
    name:       "psremoting-activity.ps1",
    shortDesc:  "WinRM status, remote sessions, and PS remoting events",
    irPhase:    "Identification",
    permission: "Active Responder",
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
    name:       "lsass-access.ps1",
    shortDesc:  "LSASS handle access events and memory dump indicators",
    irPhase:    "Identification",
    permission: "Active Responder",
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
Write-Output "  $($auditOut -join "`n  ")"

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
    name:       "credential-files.ps1",
    shortDesc:  "Hunt for SAM copies, NTDS.dit, and credential dump output",
    irPhase:    "Identification",
    permission: "Active Responder",
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
Write-Output ($cmdkeyOut -join "`n")

Write-Output "===== END CREDENTIAL FILES ====="
`
  },

  // ══════════════════════════════════════════════════════ FILE SYSTEM IOCs
  {
    id:         "recent-file-changes",
    category:   "File System IOCs",
    supportedPlatforms: ["crowdstrike","sentinelone","defender"],
    name:       "recent-file-changes.ps1",
    shortDesc:  "Recently created/modified files in sensitive paths",
    irPhase:    "Identification",
    permission: "Active Responder",
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
    name:       "suspicious-archives.ps1",
    shortDesc:  "Large archives and data staging indicators",
    irPhase:    "Identification",
    permission: "Active Responder",
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
    supportedPlatforms: ["crowdstrike"],  // CS-specific: checks CSFalconService + references Falcon Console
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
    Write-Output "\`nIf risk accepted: Falcon Console → Hosts → [host] → Isolate Host"
} else {
    Write-Output "[GO] Safe to isolate. No blockers or warnings."
    Write-Output "Proceed: Falcon Console → Hosts → [host] → Isolate Host"
}
Write-Output "===== END ISOLATE PREP ====="
`
  }

];
