# CrowdStrike RTR Script Collection

A curated, heavily-commented library of PowerShell scripts for **Real Time Response (RTR)** sessions — covering host triage, process investigation, artefact collection, and safe remediation.

> **Try the scripts live:** An interactive web editor is included in [`/web`](./web) — load, edit, and syntax-check any script in the browser before deploying it to a real host.

---

## What is RTR?

**Real Time Response** is CrowdStrike Falcon's live-response capability. It lets authorised analysts open a command shell to any sensor-enrolled host — without needing VPN, jump servers, or firewall changes — via the Falcon backend's encrypted tunnel. From an RTR session you can:

- Run PowerShell or batch scripts uploaded to the Cloud Script Library
- Transfer files to/from the host (`put` / `get`)
- Interact with the registry, processes, services, and scheduled tasks
- Trigger host network isolation

RTR is available in **Falcon Prevent**, **Falcon Insight XDR**, and **Falcon for Incident Response** subscriptions.

---

## Prerequisites & Permissions

### Falcon Roles Required

| Permission Level | What it unlocks |
|---|---|
| **RTR Analyst** | Read-only cmdlets (`ls`, `reg query`, `netstat`). No script execution. |
| **Active Responder** | Script execution, file transfer, process listing. Required for most scripts here. |
| **RTR Admin** | All of the above + killing protected processes, registry writes, service control. |

Each script in this repo is tagged with the minimum role required.

### Host Prerequisites

- CrowdStrike Falcon sensor **7.0+** (PowerShell execution requires sensor with RTR PowerShell support)
- **PowerShell 5.1** or higher on the target host
- Scripts that query the **Security event log** require the sensor to be running as SYSTEM with log read permissions (default in most deployments)
- The `get-WindowsFeature` cmdlet (used in `isolate-prep-checks.ps1`) is only available on **Windows Server** SKUs

---

## Script Reference

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
| [`artefact-collection/prefetch-dump.ps1`](artefact-collection/prefetch-dump.ps1) | Identification / Eradication | Active Responder | List all Prefetch files with timestamps + IOC name matching |
| [`artefact-collection/browser-history.ps1`](artefact-collection/browser-history.ps1) | Identification | Active Responder | Chrome, Edge, Firefox history from all user profiles (last 7 days) |

### Remediation

*Containment actions — always run with care.*

| Script | IR Phase | Permission | Description |
|---|---|---|---|
| [`remediation/kill-process.ps1`](remediation/kill-process.ps1) | Containment | Active Responder | Kill process by PID or name — captures evidence first, supports dry-run |
| [`remediation/isolate-prep-checks.ps1`](remediation/isolate-prep-checks.ps1) | Containment | Active Responder | Pre-isolation checklist — GO / CAUTION / NO-GO recommendation |

---

## Usage Examples

### Running a script in an RTR session

```
# Open RTR session to host in Falcon console, then:
runscript -CloudFile="triage/host-summary.ps1"
```

### Passing parameters (kill-process example)

```powershell
# Dry run first — see what you'd kill without actually killing it
runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-TargetName 'suspicious.exe' -DryRun $true"

# Then execute for real
runscript -CloudFile="remediation/kill-process.ps1" -CommandLine="-TargetPID 4832"
```

### Uploading scripts to the Falcon Cloud Script Library

1. Falcon Console → **Response** → **Scripts**
2. Click **Upload Script**
3. Set the platform to **Windows**, permission level to **Active Responder**
4. Paste or upload the `.ps1` file

Scripts can be organised into folders matching this repo's structure using the script name path (e.g. `triage/host-summary.ps1`).

---

## Design Principles

Every script in this collection follows these rules:

1. **Evidence before action** — remediation scripts always capture forensic metadata before making changes
2. **Dry-run mode** — destructive scripts support a `-DryRun` flag to preview impact
3. **Explain the why** — comments explain *why* each check matters, not just *what* it does
4. **No unnecessary disk writes** — scripts avoid leaving artefacts on the host where possible
5. **Graceful degradation** — scripts handle access-denied and missing-module errors without crashing

---

## IR Phase Reference

| Phase | Focus | Scripts |
|---|---|---|
| **Identification** | Understand what happened and what's running | host-summary, active-connections, logged-on-users, process-tree, unsigned-processes, prefetch-dump, browser-history |
| **Containment** | Stop the bleeding without losing evidence | kill-process, isolate-prep-checks |
| **Eradication** | Confirm removal of attacker presence | prefetch-dump (validate execution history is clean) |

---

## Interactive Web Editor

The [`/web`](./web) directory contains a single-page application for browsing and editing scripts before deployment.

Features:
- Monaco editor (same engine as VS Code) with PowerShell syntax highlighting
- Full script library browsable in the sidebar
- Script metadata panel (IR phase, permission level, description)
- Export edited script ready for Falcon upload

```bash
# Run locally — no build step required
cd web && open index.html
# or serve it:
npx serve web
```

---

## Disclaimer

- **Test before production.** Run scripts in a lab or against a sacrificial VM before using in a live IR engagement.
- **Understand before running.** Read the script and its comments fully — know what it does and what it changes.
- **These scripts come with no warranty.** Verify they work correctly in your environment and Falcon version.
- **Remediation scripts can cause outages.** Always run `isolate-prep-checks.ps1` before isolating. Always use `-DryRun` before killing processes.
- This repo is not affiliated with or endorsed by CrowdStrike, Inc.

---

## Contributing

PRs welcome. If adding a new script, please follow the existing `.SYNOPSIS` / `.IR_PHASE` / `.RTR_PERMISSION` comment block format and include inline comments explaining the *why* behind each decision.
