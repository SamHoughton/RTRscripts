<#
.SYNOPSIS
    Logged-On Users - Show all currently active and recently active user sessions.

.DESCRIPTION
    Enumerates interactive, remote desktop, and service sessions on the host.
    Useful for confirming whether a legitimate user is active (before isolating)
    and for spotting adversary-controlled accounts or anomalous logon times.

.IR_PHASE
    Identification

.RTR_PERMISSION
    Active Responder

.NOTES
    Combines query.exe output (session layer) with Win32_LoggedOnUser (WMI) for
    maximum coverage. No disk writes.

.EXAMPLE
    runscript -CloudFile="triage/logged-on-users.ps1"
#>

# ── Active Sessions via quser/query ──────────────────────────────────────────
# query.exe is the most reliable way to see RDP and console sessions simultaneously
Write-Output "===== ACTIVE SESSIONS (query user) ====="
try {
    $queryOutput = query user 2>&1
    if ($LASTEXITCODE -eq 0) {
        $queryOutput | ForEach-Object { Write-Output $_ }
    } else {
        Write-Output "  [!] query user returned exit code $LASTEXITCODE (no sessions, or access denied)"
    }
} catch {
    Write-Output "  [!] query user failed: $_"
}

Write-Output ""

# ── WMI Logged-On Users ───────────────────────────────────────────────────────
# Win32_LoggedOnUser shows service & batch logons that query user misses
Write-Output "===== WIN32 LOGGEDONUSER (includes service/batch accounts) ====="
try {
    $loggedOn = Get-CimInstance Win32_LoggedOnUser -ErrorAction Stop
    $loggedOn | ForEach-Object {
        $antecedent = $_.Antecedent.ToString()
        # Parse out Domain and Name from the reference string
        if ($antecedent -match 'Domain="([^"]+)",Name="([^"]+)"') {
            [PSCustomObject]@{
                Domain = $Matches[1]
                User   = $Matches[2]
            }
        }
    } | Sort-Object Domain, User -Unique | Format-Table -AutoSize
} catch {
    Write-Output "  [!] Win32_LoggedOnUser query failed: $_"
}

# ── Recent Logon Events (Security Log) ───────────────────────────────────────
# Event 4624 = successful logon. Pull last 20 to spot unusual accounts / times.
# Note: requires the Security event log to be readable (usually needs local admin)
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
            Time        = $_.TimeCreated
            # LogonType 2=Interactive, 3=Network, 10=RemoteInteractive(RDP)
            LogonType   = ($data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
            User        = ($data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            Domain      = ($data | Where-Object { $_.Name -eq 'TargetDomainName' }).'#text'
            SourceIP    = ($data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
            LogonProcess= ($data | Where-Object { $_.Name -eq 'LogonProcessName' }).'#text'
        }
    } | Where-Object { $_.User -ne '-' -and $_.User -notmatch '^\$$' } |
        Format-Table -AutoSize

} catch {
    Write-Output "  [!] Could not read Security log: $_"
    Write-Output "      (Ensure Active Responder role and Security log read access)"
}

Write-Output "===== END LOGGED-ON USERS ====="
