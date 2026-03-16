<#
.SYNOPSIS
    SMB Sessions - Enumerate active SMB sessions, open files, and shares.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== SMB SESSION ANALYSIS ====="
Write-Output "Host: $($env:COMPUTERNAME)  |  Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# -- Active SMB Sessions via net session -------------------------------------
Write-Output ""
Write-Output "===== ACTIVE SMB SESSIONS (net session) ====="
try {
    $netSessions = net session 2>&1
    if ($LASTEXITCODE -eq 0 -and $netSessions -match "\\") {
        $netSessions | ForEach-Object { Write-Output "  $_" }
    } elseif ($netSessions -match "no entries") {
        Write-Output "  No active SMB sessions."
    } else {
        Write-Output "  $netSessions"
    }
} catch { Write-Output "  [!] net session failed: $_" }

# -- SMB Sessions via CIM ----------------------------------------------------
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

# -- Open Files ---------------------------------------------------------------
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
    Write-Output "  [!] Get-SmbOpenFile failed - attempting net file..."
    net file 2>&1 | ForEach-Object { Write-Output "  $_" }
}

# -- SMB Shares ---------------------------------------------------------------
Write-Output ""
Write-Output "===== SMB SHARES ====="
try {
    Get-SmbShare -ErrorAction Stop |
        Select-Object Name, Path, Description, CurrentUsers |
        Format-Table -AutoSize
} catch {
    net share 2>&1 | ForEach-Object { Write-Output "  $_" }
}

# -- Admin Share Access Events (5140) ----------------------------------------
Write-Output ""
Write-Output "===== ADMIN SHARE USAGE INDICATORS (Security log, Event 5140, last 20, 24h) ====="
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
    Write-Output "  [!] Could not read Security log: $_"
}

Write-Output "===== END SMB SESSIONS ====="
