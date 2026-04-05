<#
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
            Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  ID:{1}  {2}" -f `
                $_.TimeCreated, $_.Id, (($_.Message -split "`n")[0] -replace '\s+', ' '))
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
