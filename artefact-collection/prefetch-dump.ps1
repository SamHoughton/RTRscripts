<#
.SYNOPSIS
    Prefetch Dump - List Windows Prefetch files with execution metadata.

.DESCRIPTION
    Windows Prefetch records execution evidence for the last ~128 programs run
    (or ~1024 on Win8.1+). This is one of the most valuable artefacts for
    establishing execution history — it survives binary deletion and tells you:
      • WHAT was executed (name + hash)
      • HOW MANY TIMES it ran
      • WHEN it last ran (and up to 8 previous run times on Win8+)

    Key use cases:
      • Confirm malware execution even after it's been deleted
      • Establish a timeline of attacker tooling
      • Find staging tools (7zip, rclone, mimikatz) run briefly before deletion

.IR_PHASE
    Identification / Eradication

.RTR_PERMISSION
    Active Responder

.NOTES
    Prefetch is disabled by default on Windows Server. Check first.
    Files are in C:\Windows\Prefetch\*.pf — readable without admin in most configs.
    Last-run timestamps can be off by up to 10 seconds due to Prefetch's lazy-write.

.EXAMPLE
    runscript -CloudFile="artefact-collection/prefetch-dump.ps1"
#>

# ── Check if Prefetch is enabled ──────────────────────────────────────────────
$pfKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
$pfEnabled = (Get-ItemProperty -Path $pfKey -ErrorAction SilentlyContinue).EnablePrefetcher

Write-Output "===== PREFETCH ANALYSIS ====="

if ($pfEnabled -eq 0) {
    Write-Output "[!] Prefetch is DISABLED on this host (EnablePrefetcher = 0)."
    Write-Output "    No artefacts will be present."
    exit
} elseif ($null -eq $pfEnabled) {
    Write-Output "[?] Could not read EnablePrefetcher registry key. Attempting file access anyway..."
} else {
    Write-Output "[OK] Prefetch enabled (EnablePrefetcher = $pfEnabled)"
}

Write-Output ""

# ── Enumerate .pf files ───────────────────────────────────────────────────────
$pfPath = "C:\Windows\Prefetch"

if (-not (Test-Path $pfPath)) {
    Write-Output "[!] Prefetch directory not found at $pfPath"
    exit
}

$pfFiles = Get-ChildItem -Path $pfPath -Filter "*.pf" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending

Write-Output "Total Prefetch files: $($pfFiles.Count)"
Write-Output ""

# ── Parse file metadata ───────────────────────────────────────────────────────
# NOTE: Full binary parsing of .pf files requires tools like PECmd or python-prefetch.
# This script extracts what's available from the filesystem layer (name, size, timestamps).
# For full run-count and embedded timestamps, pull the files via RTR get and analyse offline.

Write-Output "{0,-55} {1,-25} {2,-25} {3}" -f "Executable","Last Run (LastWrite)","Created","Size (KB)"
Write-Output ("-" * 130)

foreach ($f in $pfFiles) {
    # Prefetch filename format: EXECNAME-XXXXXXXX.pf  (hash is load-path hash)
    $execName = $f.Name -replace '-[A-F0-9]{8}\.pf$', ''

    Write-Output ("{0,-55} {1,-25} {2,-25} {3}" -f
        $execName,
        $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"),
        $f.CreationTime.ToString("yyyy-MM-dd HH:mm:ss"),
        [math]::Round($f.Length / 1KB, 1)
    )
}

# ── High-value IOC names ──────────────────────────────────────────────────────
# Common attacker tools — flag if any prefetch entries match
$iocNames = @(
    "MIMIKATZ", "MIMI", "PROCDUMP", "PWDUMP", "FGDUMP",
    "WCEEX", "GSECDUMP", "RCLONE", "MEGA", "COBALTSTRIKE",
    "BEACON", "METERPRETER", "PSEXEC", "PAEXEC", "WMIEXEC",
    "SECRETSDUMP", "LAZAGNE", "SHARPHOUND", "BLOODHOUND",
    "RUBEUS", "KERBRUTE", "CHISEL", "LIGOLO", "NGROK", "FRPC",
    "NETSCAN", "ADVANCED-PORT-SCANNER", "7ZA", "WINRAR",
    "ADFIND", "NLTEST"
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

Write-Output ""
Write-Output "TIP: To parse full run counts and all 8 timestamps, retrieve .pf files via:"
Write-Output "     RTR> get C:\Windows\Prefetch\TOOLNAME-*.pf"
Write-Output "     Then analyse offline with Eric Zimmermann's PECmd.exe"
Write-Output "===== END PREFETCH DUMP ====="
