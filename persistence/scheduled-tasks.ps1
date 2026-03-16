<#
.SYNOPSIS
    Scheduled Tasks - Enumerate all tasks with persistence indicators.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder
#>

Write-Output "===== SCHEDULED TASKS ANALYSIS ====="

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
$highRiskPaths = @(
    $env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, $env:PUBLIC,
    "C:\PerfLogs", "C:\Intel", "C:\ProgramData\Microsoft\Windows\Start Menu"
)

$allTasks  = [System.Collections.Generic.List[object]]::new()
$suspicious = [System.Collections.Generic.List[object]]::new()

foreach ($task in $tasks) {
    $actions = $task.Actions | ForEach-Object {
        $cls = $_.CimClass.CimClassName
        if ($cls -eq "MSFT_TaskExecAction")  { "$($_.Execute) $($_.Arguments)".Trim() }
        if ($cls -eq "MSFT_TaskComHandlerAction") { "COM: $($_.ClassId)" }
    }
    $actionStr = ($actions | Where-Object { $_ }) -join " | "

    $allTasks.Add([PSCustomObject]@{
        Name    = $task.TaskName
        Path    = $task.TaskPath
        State   = $task.State
        Author  = if ($task.Author) { $task.Author } else { "[none]" }
        Action  = if ($actionStr.Length -gt 100) { $actionStr.Substring(0,100)+"..." } else { $actionStr }
    })

    $reason = [System.Collections.Generic.List[string]]::new()
    if ($actionStr -match "-[Ee]nc(odedcommand)?[\s=]+[A-Za-z0-9+/=]{20}") {
        $reason.Add("Encoded PS command")
    }
    if ($actionStr -match "wscript|cscript|mshta|regsvr32\.exe|rundll32\.exe") {
        $reason.Add("LOLBin")
    }
    foreach ($rp in $highRiskPaths) {
        if ($rp -and $actionStr -like "$rp*") { $reason.Add("User-writable path"); break }
    }
    if (-not $task.Author -or $task.Author -eq "") {
        $reason.Add("No author")
    }
    if ($actionStr -match "http://|ftp://|\\[0-9]{1,3}\.[0-9]{1,3}") {
        $reason.Add("Network path/URL in action")
    }
    if ($reason.Count -gt 0) {
        $suspicious.Add([PSCustomObject]@{
            Name   = $task.TaskName
            Reason = $reason -join ", "
            Author = if ($task.Author) { $task.Author } else { "[none]" }
            Action = $actionStr
        })
    }
}

Write-Output "Total scheduled tasks: $($allTasks.Count)"
Write-Output ""
Write-Output "===== ALL TASKS ====="
$allTasks | Format-Table -AutoSize

Write-Output ""
Write-Output "===== SUSPICIOUS INDICATORS ($($suspicious.Count) found) ====="
if ($suspicious.Count -gt 0) {
    $suspicious | Format-Table -AutoSize
} else {
    Write-Output "  No suspicious scheduled tasks detected."
}
Write-Output "===== END SCHEDULED TASKS ====="
