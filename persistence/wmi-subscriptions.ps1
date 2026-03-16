<#
.SYNOPSIS
    WMI Subscriptions - Enumerate all permanent WMI event subscriptions.

.IR_PHASE        Identification
.RTR_PERMISSION  Active Responder

.NOTES
    Legitimate WMI subscriptions exist (e.g. SCM, antivirus), but unknown
    entries - especially CommandLineEventConsumers - are high-confidence IOCs.
    WMI persistence is fileless, survives reboots, and is commonly missed by AV.
#>

Write-Output "===== WMI PERMANENT EVENT SUBSCRIPTIONS ====="

$ns = "root\subscription"

# -- Event Filters -----------------------------------------------------------
Write-Output "===== EVENT FILTERS ====="
try {
    $filters = Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop
    if ($filters) {
        $filters | Select-Object Name, QueryLanguage, Query | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "  None found."
    }
} catch { Write-Output "  [!] Error enumerating filters: $_" }

# -- Event Consumers ---------------------------------------------------------
Write-Output ""
Write-Output "===== EVENT CONSUMERS ====="
$consumerClasses = @(
    "CommandLineEventConsumer",
    "ActiveScriptEventConsumer",
    "LogFileEventConsumer",
    "NtEventLogEventConsumer",
    "SMTPEventConsumer"
)
foreach ($cls in $consumerClasses) {
    try {
        $consumers = Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction Stop
        if ($consumers) {
            Write-Output "--- $cls ---"
            $consumers | Select-Object Name, CommandLineTemplate, ScriptText, ExecutablePath |
                Format-Table -AutoSize -Wrap
        }
    } catch {}
}

# -- Filter-to-Consumer Bindings ---------------------------------------------
Write-Output ""
Write-Output "===== FILTER-TO-CONSUMER BINDINGS ====="
try {
    $bindings = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop
    if ($bindings) {
        $bindings | ForEach-Object {
            $filterRef   = $_.Filter.ToString()   -replace '.*Name="([^"]+)".*','$1'
            $consumerRef = $_.Consumer.ToString()  -replace '.*Name="([^"]+)".*','$1'
            [PSCustomObject]@{ Filter = $filterRef; Consumer = $consumerRef }
        } | Format-Table -AutoSize
    } else {
        Write-Output "  No bindings found."
    }
} catch { Write-Output "  [!] Error enumerating bindings: $_" }

Write-Output ""
Write-Output "NOTE: Legitimate Windows entries include SCM Event Log Consumer."
Write-Output "      Flag anything referencing cmd.exe, powershell.exe, scripts,"
Write-Output "      or unknown consumers not tied to a known security product."
Write-Output "===== END WMI SUBSCRIPTIONS ====="
