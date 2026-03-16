<#
.SYNOPSIS
    Startup Entries - Enumerate Run keys, startup folders, IFEO, and autostart services.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== STARTUP ENTRY ANALYSIS ====="

$systemPaths = @("C:\Windows\","C:\Program Files\","C:\Program Files (x86)\")
function Test-SuspiciousPath([string]$path) {
    if (-not $path) { return $false }
    $exe = ($path -split '"| -')[0].Trim().Trim('"')
    foreach ($sp in $systemPaths) { if ($exe -like "$sp*") { return $false } }
    return $true
}

# -- Run / RunOnce keys -------------------------------------------------------
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
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

# -- Startup folders ---------------------------------------------------------
Write-Output ""
Write-Output "===== STARTUP FOLDERS ====="
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
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

# -- Image File Execution Options (debugger hijacking) ----------------------
Write-Output ""
Write-Output "===== IMAGE FILE EXECUTION OPTIONS (IFEO) ====="
$ifeoKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
if (Test-Path $ifeoKey) {
    Get-ChildItem -Path $ifeoKey -ErrorAction SilentlyContinue | ForEach-Object {
        $debugger = (Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            Write-Output "  [!] $($_.PSChildName) -> Debugger: $debugger"
        }
    }
    Write-Output "  (Only entries with a Debugger value are shown)"
} else {
    Write-Output "  IFEO key not found."
}

# -- Auto-start services from non-standard paths ----------------------------
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
