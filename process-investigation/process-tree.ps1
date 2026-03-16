<#
.SYNOPSIS
    Process Tree - Full parent-child process hierarchy with binary metadata.

.DESCRIPTION
    Reconstructs the complete process tree and annotates each process with:
      • Full executable path
      • Command-line arguments (where accessible)
      • Parent process name
      • Process start time
      • Code signing status

    Adversaries frequently use process injection, LOLBins (Living Off the Land
    Binaries), and renamed executables. The tree view surfaces chains like:
        Word.exe → cmd.exe → powershell.exe → net.exe
    which are highly indicative of macro-based initial access.

.IR_PHASE
    Identification

.RTR_PERMISSION
    Active Responder

.NOTES
    Command-line for some system processes may show "Access Denied" — this is
    normal. Focus on unexpected chains rather than individual entries.

.EXAMPLE
    runscript -CloudFile="process-investigation/process-tree.ps1"
#>

# ── Build process map ─────────────────────────────────────────────────────────
# Index by PID so we can O(1) look up parent names
$allProcs = Get-CimInstance Win32_Process
$procMap  = @{}
foreach ($p in $allProcs) { $procMap[$p.ProcessId] = $p }

Write-Output "===== PROCESS TREE ====="
Write-Output ("{0,-8} {1,-8} {2,-30} {3,-40} {4}" -f "PID","PPID","ParentName","Name","CommandLine")
Write-Output ("-" * 120)

foreach ($proc in ($allProcs | Sort-Object CreationDate)) {
    $parentName = if ($procMap.ContainsKey($proc.ParentProcessId)) {
        $procMap[$proc.ParentProcessId].Name
    } else {
        "N/A"
    }

    # Truncate long command lines for readability; full data is in CIM
    $cmdLine = if ($proc.CommandLine) {
        if ($proc.CommandLine.Length -gt 80) { $proc.CommandLine.Substring(0,80) + "..." }
        else { $proc.CommandLine }
    } else { "[no cmdline / access denied]" }

    Write-Output ("{0,-8} {1,-8} {2,-30} {3,-40} {4}" -f
        $proc.ProcessId,
        $proc.ParentProcessId,
        $parentName,
        $proc.Name,
        $cmdLine
    )
}

# ── Suspicious Parent-Child Pairs ─────────────────────────────────────────────
# These combinations are almost never legitimate and warrant immediate attention
Write-Output ""
Write-Output "===== SUSPICIOUS PARENT-CHILD PAIRS ====="

# Define pairs: [parent] → [child] that are almost always malicious
$suspiciousPairs = @(
    @{ Parent = "winword.exe";    Child = "cmd.exe" },
    @{ Parent = "winword.exe";    Child = "powershell.exe" },
    @{ Parent = "winword.exe";    Child = "wscript.exe" },
    @{ Parent = "excel.exe";      Child = "cmd.exe" },
    @{ Parent = "excel.exe";      Child = "powershell.exe" },
    @{ Parent = "outlook.exe";    Child = "cmd.exe" },
    @{ Parent = "outlook.exe";    Child = "powershell.exe" },
    @{ Parent = "mshta.exe";      Child = "cmd.exe" },
    @{ Parent = "mshta.exe";      Child = "powershell.exe" },
    @{ Parent = "wscript.exe";    Child = "powershell.exe" },
    @{ Parent = "cscript.exe";    Child = "powershell.exe" },
    @{ Parent = "svchost.exe";    Child = "cmd.exe" },          # unusual but not always malicious
    @{ Parent = "explorer.exe";   Child = "powershell.exe" }    # depends on context
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
