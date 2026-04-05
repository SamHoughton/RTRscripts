<#
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

        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}{2}  {3}  {4}  src={5}  proc={6}" -f `
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
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  by={2}  target={3}" -f `
            $_.TimeCreated, $_.Id, $by, $target)
    }
} else {
    Write-Output "  [i] No account-change events in window"
}
Write-Output ""

# ── SECTION 4: PowerShell Script Block Logging ────────────────────────────────
# 4103=Module logging, 4104=Script block (most valuable — shows decoded commands)
Write-Output "===== POWERSHELL SCRIPT BLOCK LOG (4104) ====="
$psEvents = Get-FilteredEvents `
    -LogName 'Microsoft-Windows-PowerShell/Operational' `
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
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  name={1}  type={2}  path={3}  account={4}" -f `
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
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  user={2}  status={3}  src={4}" -f `
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
$winrmEvents = Get-FilteredEvents `
    -LogName 'Microsoft-Windows-WinRM/Operational' `
    -Ids @(91,168) -Cutoff $cutoff -Max $MaxEvents
if ($winrmEvents) {
    $winrmEvents | Sort-Object TimeCreated -Descending | ForEach-Object {
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  {2}" -f `
            $_.TimeCreated, $_.Id, ($_.Message -split "`n")[0])
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
        Write-Output ("  [!!] {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  by={2}  {3}" -f `
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
        Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  {1}  by={2}  task={3}" -f `
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
