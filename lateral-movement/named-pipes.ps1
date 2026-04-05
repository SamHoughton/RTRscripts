<#
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
