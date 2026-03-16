<#
.SYNOPSIS
    Active Connections - Enumerate all current TCP/UDP network connections with owning process.

.DESCRIPTION
    Maps every listening and established socket to its owning process and binary path.
    Critical during Identification — C2 channels, lateral movement, and exfil almost
    always leave a footprint here.

    Highlights:
      • Connections to non-standard ports
      • Processes with network sockets that shouldn't have them (e.g. notepad.exe)
      • LISTENING sockets on unexpected interfaces

.IR_PHASE
    Identification

.RTR_PERMISSION
    Active Responder

.NOTES
    Requires PowerShell 5+ (Get-NetTCPConnection / Get-NetUDPEndpoint available since Win8/2012R2).
    No disk writes. Safe for production hosts.

.EXAMPLE
    runscript -CloudFile="triage/active-connections.ps1"
#>

# ── TCP Connections ───────────────────────────────────────────────────────────
# Get-NetTCPConnection is faster and more reliable than netstat parsing
Write-Output "===== TCP CONNECTIONS ====="

$tcpConns = Get-NetTCPConnection | Where-Object { $_.State -ne 'TimeWait' } |
    Sort-Object State, RemoteAddress

$results = foreach ($conn in $tcpConns) {
    $proc = $null
    try {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    } catch {}

    [PSCustomObject]@{
        State         = $conn.State
        LocalAddr     = "$($conn.LocalAddress):$($conn.LocalPort)"
        RemoteAddr    = "$($conn.RemoteAddress):$($conn.RemotePort)"
        PID           = $conn.OwningProcess
        ProcessName   = if ($proc) { $proc.Name } else { "N/A" }
        # Full path helps spot masquerading — a "svchost.exe" running from AppData is suspicious
        ProcessPath   = if ($proc) { try { $proc.MainModule.FileName } catch { "Access Denied" } } else { "N/A" }
    }
}

$results | Format-Table -AutoSize

# ── UDP Endpoints ─────────────────────────────────────────────────────────────
# UDP is stateless so there's no Remote; focus on unusual listening ports
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

# ── Quick Anomaly Hints ───────────────────────────────────────────────────────
# Flag established connections where process path is outside System32 / Program Files
Write-Output ""
Write-Output "===== ANOMALY HINTS (established, non-system path) ====="
$systemPaths = @("C:\Windows\", "C:\Program Files\", "C:\Program Files (x86)\")

$results | Where-Object {
    $_.State -eq 'Established' -and
    $_.ProcessPath -ne "N/A" -and
    $_.ProcessPath -ne "Access Denied" -and
    -not ($systemPaths | Where-Object { $_.ProcessPath -like "$_*" })
} | Format-Table -AutoSize

Write-Output "===== END ACTIVE CONNECTIONS ====="
