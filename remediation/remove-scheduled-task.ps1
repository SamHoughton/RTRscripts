#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remove a malicious scheduled task by name and optional path.

.DESCRIPTION
    Finds a scheduled task, outputs the full task definition (action, trigger,
    run-as user, XML) for documentation, then deletes it. Run the triage script
    'scheduled-tasks.ps1' first to identify the exact task name.
    CONFIRM the task name is correct — this action cannot be undone.

.IR_PHASE
    Eradication

.RTR_PERMISSION
    RTR Admin

.PARAMETER TaskName
    Exact name of the scheduled task to remove.

.PARAMETER TaskPath
    Task folder path. Defaults to "\" (root). Use the path shown in
    Task Scheduler or from the triage output (e.g. "\Microsoft\Windows\").

.EXAMPLE
    runscript -CloudFile="remediation/remove-scheduled-task.ps1" `
      -CommandLine="-TaskName 'MicrosoftEdgeUpdateCore' -TaskPath '\'"
#>
param(
    [Parameter(Mandatory=$true)][string]$TaskName = "",
    [string]$TaskPath = "\"
)

Write-Output "===== REMOVE SCHEDULED TASK ====="
Write-Output "Host     : $env:COMPUTERNAME"
Write-Output "Operator : $env:USERDOMAIN\$env:USERNAME"
Write-Output "Time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output "Target   : $TaskPath$TaskName"
Write-Output ""

if (-not $TaskName) {
    Write-Output "[ERROR] -TaskName is required"
    exit 1
}

# ── Find the task ──────────────────────────────────────────────────────────
$task = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue

if (-not $task) {
    Write-Output "[ERROR] Scheduled task not found: '$TaskName' at path '$TaskPath'"
    Write-Output "  Hint: use scheduled-tasks.ps1 to list tasks and confirm the exact name/path"
    exit 1
}

# ── Document before deletion ───────────────────────────────────────────────
Write-Output "===== TASK DETAILS (pre-deletion record) ====="
Write-Output "  Task Name   : $($task.TaskName)"
Write-Output "  Task Path   : $($task.TaskPath)"
Write-Output "  State       : $($task.State)"
Write-Output "  Description : $($task.Description)"
Write-Output ""

Write-Output "  --- Actions ---"
foreach ($action in $task.Actions) {
    Write-Output "  Execute   : $($action.Execute)"
    Write-Output "  Arguments : $($action.Arguments)"
    Write-Output "  WorkDir   : $($action.WorkingDirectory)"
}
Write-Output ""

Write-Output "  --- Triggers ---"
foreach ($trigger in $task.Triggers) {
    Write-Output "  Type      : $($trigger.CimClass.CimClassName)"
    if ($trigger.StartBoundary)  { Write-Output "  Starts    : $($trigger.StartBoundary)" }
    if ($trigger.RepetitionInterval) { Write-Output "  Interval  : $($trigger.RepetitionInterval)" }
}
Write-Output ""

Write-Output "  --- Run As ---"
$principal = $task.Principal
Write-Output "  User      : $($principal.UserId)"
Write-Output "  LogonType : $($principal.LogonType)"
Write-Output "  RunLevel  : $($principal.RunLevel)"
Write-Output ""

# Export XML for case notes
Write-Output "  --- Task XML ---"
try {
    Export-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
} catch {
    Write-Output "  [XML export unavailable]"
}
Write-Output ""

# ── Remove ────────────────────────────────────────────────────────────────
Write-Output "===== REMOVING TASK ====="
try {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction Stop
    Write-Output "  [+] Removed: $TaskPath$TaskName"
} catch {
    Write-Output "  [!] Failed to remove task: $($_.Exception.Message)"
    exit 1
}

# ── Confirm gone ──────────────────────────────────────────────────────────
$verify = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
if ($verify) {
    Write-Output "  [!] WARNING: Task still present after removal attempt — manual review required"
} else {
    Write-Output "  [+] Confirmed: task no longer exists"
}

Write-Output ""
Write-Output "===== END REMOVE SCHEDULED TASK ====="
