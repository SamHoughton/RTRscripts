<#
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
            Write-Output ("  {0:yyyy-MM-dd HH:mm:ss}  [{1}]  {2}" -f `
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
