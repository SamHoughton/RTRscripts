# RTR Labs — IR Script Library

A curated, heavily-commented library of scripts for **Real Time Response** sessions across **CrowdStrike Falcon**, **SentinelOne Singularity**, and **Microsoft Defender for Endpoint** — covering host triage, process investigation, persistence hunting, artefact collection, and safe eradication on **Windows**, **macOS**, and **Linux**.

> **Interactive editor:** Browse, edit, and deploy scripts at **[rtrlabs.io](https://rtrlabs.io)** — Monaco editor, platform-aware deployment commands, and OS selector built in.

---

## Platform Support Matrix

| Feature | CrowdStrike RTR | SentinelOne Singularity | MDE Live Response |
|---|---|---|---|
| Windows scripts | ✅ Full | ✅ Full | ✅ Full |
| macOS scripts | ✅ Full | ✅ Full | ⚠️ Limited |
| Linux scripts | ✅ Full | ✅ Full | ✅ Full |
| Parameter injection | ✅ `-CommandLine` | ✅ Via UI | ⚠️ Limited |
| Upload method | Cloud Script Library | Script Library (UI) | Live Response Library |

---

## Prerequisites & Permissions

### Permission Levels

| Tag | Level | What it unlocks |
|---|---|---|
| **Active Responder** | Standard | Script execution, file transfer, process listing |
| **RTR Admin** | Elevated | Killing protected processes, registry writes, service control, binary deletion |

Each script is tagged with the minimum permission required. Eradication scripts require RTR Admin.

### Windows Requirements

- CrowdStrike Falcon sensor **7.0+** or SentinelOne agent with remote scripts enabled
- **PowerShell 5.1+** on the target host
- Security event log access (default in most deployments)
- `Get-WindowsFeature` (Server SKUs only — used in `isolate-prep-checks.ps1`)

### macOS Requirements

- CrowdStrike Falcon sensor with RTR enabled, or SentinelOne agent
- Bash 3.2+ (ships with macOS); scripts tested on macOS 12+
- Some queries require elevated permissions (launchd daemon enumeration)

### Linux Requirements

- CrowdStrike Falcon sensor or SentinelOne agent with remote scripts enabled
- Bash 4.0+; tested on Ubuntu 20.04+, RHEL 8+, Debian 11+
- `ss` preferred over `netstat`; `systemctl` for systemd-based distros

---

## Script Reference — Windows (22 scripts · 36 total across all platforms)

### Triage
*Run these first. Establish situational awareness before taking any action.*

| Script | IR Phase | Permission | Description |
|---|---|---|---|
| [`triage/host-summary.ps1`](triage/host-summary.ps1) | Identification | Active Responder | OS version, uptime, local admins, AV products, last 5 patches |
| [`triage/active-connections.ps1`](triage/active-connections.ps1) | Identification | Active Responder | All TCP/UDP sockets mapped to owning process + path, with anomaly hints |
| [`triage/logged-on-users.ps1`](triage/logged-on-users.ps1) | Identification | Active Responder | Active sessions, Win32 logon enumeration, last 20 Security log 4624 events |

### Process Investigation
*Dig into what's running and why.*

| Script | IR Phase | Permission | Description |
|---|---|---|---|
| [`process-investigation/process-tree.ps1`](process-investigation/process-tree.ps1) | Identification | Active Responder | Full parent→child process hierarchy + suspicious pair detection |
| [`process-investigation/unsigned-processes.ps1`](process-investigation/unsigned-processes.ps1) | Identification | Active Responder | Flags unsigned binaries, deleted-on-disk processes, high-risk path execution |

### Artefact Collection
*Collect evidence before it disappears.*

| Script | IR Phase | Permission | Description |
|---|---|---|---|
| [`artefact-collection/prefetch-dump.ps1`](artefact-collection/prefetch-dump.ps1) | Identification | Active Responder | List all Prefetch files with timestamps + IOC name matching |
| [`artefact-collection/browser-history.ps1`](artefact-collection/browser-history.ps1) | Identification | Active Responder | Chrome, Edge, Firefox history from all user profiles (last 7 days) |

### Persistence
*Find what survives a reboot.*

| Script | IR Phase | Permission | Description |
|---|---|---|---|
| [`persistence/scheduled-tasks.ps1`](persistence/scheduled-tasks.ps1) | Identification | Active Responder | All scheduled tasks with binary paths, trigger types, and run-as accounts |
| [`persistence/startup-entries.ps1`](persistence/startup-entries.ps1) | Identification | Active Responder | Run/RunOnce keys, Startup folders, and service auto-starts across all hives |
| [`persistence/wmi-subscriptions.ps1`](persistence/wmi-subscriptions.ps1) | Identification | Active Responder | WMI event subscriptions — a common fileless persistence mechanism |

### Lateral Movement
*Detect signs of attacker movement across the network.*

| Script | IR Phase | Permission | Description |
|---|---|---|---|
| [`lateral-movement/smb-sessions.ps1`](lateral-movement/smb-sessions.ps1) | Identification | Active Responder | Active SMB sessions, open shares, recent network connections |
| [`lateral-movement/psremoting-activity.ps1`](lateral-movement/psremoting-activity.ps1) | Identification | Active Responder | PowerShell remoting sessions, WSMan activity, WinRM configuration |

### Credential Indicators
*Look for signs of credential access or harvesting.*

| Script | IR Phase | Permission | Description |
|---|---|---|---|
| [`credential-indicators/lsass-access.ps1`](credential-indicators/lsass-access.ps1) | Identification | Active Responder | Process handles on LSASS, suspicious memory access patterns |
| [`credential-indicators/credential-files.ps1`](credential-indicators/credential-files.ps1) | Identification | Active Responder | Credential store files, credential manager entries, DPAPI artefacts |

### File System IOCs
*Find malicious files by behaviour, not just signature.*

| Script | IR Phase | Permission | Description |
|---|---|---|---|
| [`file-system-iocs/recent-file-changes.ps1`](file-system-iocs/recent-file-changes.ps1) | Identification | Active Responder | Recently created/modified files in staging dirs, temp paths, user downloads |
| [`file-system-iocs/suspicious-archives.ps1`](file-system-iocs/suspicious-archives.ps1) | Identification | Active Responder | Zip/rar/7z files in unusual locations — common tool staging artefact |

### Remediation
*Containment and eradication actions — always run with care.*

| Script | IR Phase | Permission | Description |
|---|---|---|---|
| [`remediation/kill-process.ps1`](remediation/kill-process.ps1) | Containment | Active Responder | Kill process by PID or name — captures evidence first, supports dry-run |
| [`remediation/isolate-prep-checks.ps1`](remediation/isolate-prep-checks.ps1) | Containment | Active Responder | Pre-isolation checklist — GO / CAUTION / NO-GO recommendation |
| [`remediation/kill-process.ps1`](remediation/kill-process.ps1) *(eradication variant)* | Eradication | RTR Admin | Full kill with optional binary deletion; logs path/owner/parent before acting |
| [`remediation/remove-scheduled-task.ps1`](remediation/remove-scheduled-task.ps1) | Eradication | RTR Admin | Export full task XML for case notes then permanently unregister it |
| [`remediation/remove-service.ps1`](remediation/remove-service.ps1) | Eradication | RTR Admin | Stop service, sc.exe delete, optionally delete the binary |
| [`remediation/remove-registry-run-key.ps1`](remediation/remove-registry-run-key.ps1) | Eradication | RTR Admin | Show all Run/RunOnce entries then remove the named value; verifies post-removal |

---

## Script Reference — macOS (8 scripts)

All macOS scripts are Bash/Zsh. Upload as `.sh` files with the `macos/` path prefix.

### Triage

| Script | IR Phase | Description |
|---|---|---|
| [`macos/triage/host-summary.sh`](macos/triage/host-summary.sh) | Identification | OS version, serial, uptime, local admins, network interfaces, EDR agent status, FileVault + SIP state |
| [`macos/triage/active-connections.sh`](macos/triage/active-connections.sh) | Identification | Established sockets and listening ports mapped to process via lsof; ARP cache; application firewall state |
| [`macos/triage/logged-on-users.sh`](macos/triage/logged-on-users.sh) | Identification | Current sessions, recent login history, failed auth events, active SSH connections |

### Process Investigation

| Script | IR Phase | Description |
|---|---|---|
| [`macos/process-investigation/process-tree.sh`](macos/process-investigation/process-tree.sh) | Identification | Full parent→child process hierarchy; flags browsers/Office spawning shells, suspicious path execution, top consumers |
| [`macos/process-investigation/unsigned-binaries.sh`](macos/process-investigation/unsigned-binaries.sh) | Identification | codesign + Gatekeeper assessment of all running process binaries; flags unsigned, ad-hoc signed, and high-risk-path executables |

### Artefact Collection

| Script | IR Phase | Description |
|---|---|---|
| [`macos/artefact-collection/browser-history.sh`](macos/artefact-collection/browser-history.sh) | Identification | Safari, Chrome, Firefox history (last 7 days) + macOS quarantine download log via sqlite3 |

### Persistence

| Script | IR Phase | Description |
|---|---|---|
| [`macos/persistence/launchd-entries.sh`](macos/persistence/launchd-entries.sh) | Identification | All LaunchDaemon/LaunchAgent plists (system + user); flags non-Apple/non-vendor entries; login items; cron |

### File System IOCs

| Script | IR Phase | Description |
|---|---|---|
| [`macos/file-system-iocs/recent-file-changes.sh`](macos/file-system-iocs/recent-file-changes.sh) | Identification | Files modified in LaunchD dirs, /tmp, usr/local/bin, Downloads, Desktop; flags executable scripts |

---

## Script Reference — Linux (6 scripts)

All Linux scripts are Bash. Upload as `.sh` files with the `linux/` path prefix.

### Triage

| Script | IR Phase | Description |
|---|---|---|
| [`linux/triage/host-summary.sh`](linux/triage/host-summary.sh) | Identification | Distro, kernel, hardware info, last boot, current users, privileged accounts, network interfaces, EDR agents |
| [`linux/triage/active-connections.sh`](linux/triage/active-connections.sh) | Identification | ss/netstat sockets with process info, DNS config, routes, neighbour cache, firewall state (ufw/firewalld/iptables) |

### Process Investigation

| Script | IR Phase | Description |
|---|---|---|
| [`linux/process-investigation/process-tree.sh`](linux/process-investigation/process-tree.sh) | Identification | Full process hierarchy; web-server→shell pairs (webshell indicator); deleted-binary and memfd execution; suspicious path processes |

### Credential Indicators

| Script | IR Phase | Description |
|---|---|---|
| [`linux/credential-indicators/credential-files.sh`](linux/credential-indicators/credential-files.sh) | Identification | passwd/shadow/sudoers status; UID-0 accounts; SSH authorized_keys; shell history credential scan; unusual SUID binaries; /proc/*/mem access |

### Persistence

| Script | IR Phase | Description |
|---|---|---|
| [`linux/persistence/systemd-services.sh`](linux/persistence/systemd-services.sh) | Identification | Services with non-standard ExecStart paths, all enabled units, timers, custom unit files, crontabs, rc.local, at jobs |

### File System IOCs

| Script | IR Phase | Description |
|---|---|---|
| [`linux/file-system-iocs/recent-file-changes.sh`](linux/file-system-iocs/recent-file-changes.sh) | Identification | Modified files in /tmp, /etc, /usr/local, home dirs; recently changed setuid binaries; passwd/shadow/sudoers changes |

---

## Usage

### CrowdStrike RTR

```bash
# Open an RTR session in Falcon Console, then:

# Windows
runscript -CloudFile="triage/host-summary.ps1"
runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-ProcessName 'malware.exe'"

# macOS
runscript -CloudFile="macos/triage/host-summary.sh"

# Linux
runscript -CloudFile="linux/triage/host-summary.sh"
```

**Uploading to Cloud Script Library:**
1. Falcon Console → **Response** → **Scripts** → **Upload Script**
2. Set platform (Windows / macOS / Linux) and permission level
3. Use the folder path as the script name (e.g. `triage/host-summary.ps1`)

### SentinelOne Singularity

1. **Sentinels** → select host → **Actions** → **Run Script**
2. Upload the script file and execute
3. View output in the activity log

### Microsoft Defender for Endpoint (Live Response)

> MDE requires uploading scripts to the library **before** using them in a session.

1. **Settings** → **Endpoints** → **Live Response** → **Upload files to library**
2. Open a Live Response session to the target host
3. Run the script:

```
putfile host-summary.ps1
run host-summary.ps1
```

**Note:** MDE Live Response on macOS has limited scripting support. CrowdStrike or SentinelOne are recommended for macOS endpoint IR.

---

## Design Principles

1. **Evidence before action** — eradication scripts log full details (binary path, owner, XML/reg dump) before making changes
2. **Dry-run support** — destructive scripts support `-DryRun` or equivalent to preview impact
3. **Explain the why** — comments explain *why* each check matters, not just *what* it does
4. **No unnecessary disk writes** — scripts avoid leaving artefacts on the host where possible
5. **Graceful degradation** — scripts handle access-denied and missing-module errors without crashing
6. **Confirm before destroy** — eradication scripts output what they found before removing it

---

## IR Phase Reference

| Phase | Focus | Script Examples |
|---|---|---|
| **Identification** | Understand what happened and what's running | host-summary, active-connections, process-tree, persistence scripts, credential-indicators |
| **Containment** | Stop the bleeding without losing evidence | kill-process (containment), isolate-prep-checks |
| **Eradication** | Remove attacker presence | kill-process (eradication), remove-scheduled-task, remove-service, remove-registry-run-key |

---

## Interactive Web Editor

The [`/web`](./web) directory contains a single-page application for browsing and editing scripts.

Features:
- **OS selector landing page** — choose Windows / macOS / Linux on arrival
- **Platform switcher** — CS / S1 / MDE deployment commands generated automatically
- **Monaco editor** with PowerShell and Bash syntax highlighting
- **Dynamic pre-deploy checklist** — context-aware items based on IR phase, with copy-to-clipboard
- **Parameter injection UI** — fill in script parameters, generates the full runscript command
- **IR Workflow modal** — phase-organised script browser
- **IR Playbooks** — 5 curated guided playbooks (Ransomware, Credential Theft, Persistence Hunt, macOS Triage, Linux Triage)
- **MITRE ATT&CK coverage modal** — technique grid with clickable script links
- **Script diff view** — Monaco diff editor comparing original vs your edits
- **Favourites / pinning** — star scripts to pin them at the top of the sidebar
- **Recently used** — quick access to last 4 scripts
- **Cross-OS search** — search all platforms simultaneously when a query is active
- **Export all** scripts as structured `.zip`
- URL hash routing — scripts are bookmarkable/shareable

```bash
# Run locally — no build step required
cd web && open index.html
# or:
npx serve web
```

---

## Disclaimer

- **Test before production.** Run scripts against a lab host before using in a live IR engagement.
- **Understand before running.** Read the script fully — know what it does and what it changes.
- **Eradication scripts are destructive and irreversible.** Always confirm the correct target. Capture forensic evidence first.
- **These scripts come with no warranty.** Verify they work in your environment and sensor version.
- This repo is not affiliated with or endorsed by CrowdStrike, SentinelOne, or Microsoft.

---

## Contributing

PRs welcome. If adding a new script please:
- Follow the existing `.SYNOPSIS` / `.IR_PHASE` / `.RTR_PERMISSION` (PowerShell) or equivalent comment block format
- Add inline comments explaining the *why* behind each check
- Add the script entry to [`web/scripts-data.js`](web/scripts-data.js) with `id`, `category`, `os`, `supportedPlatforms`, `name`, `shortDesc`, `irPhase`, `permission`, `description`, and `source`
- Tag `os` as `"windows"`, `"macos"`, or `"linux"`
