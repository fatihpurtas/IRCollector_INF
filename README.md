# IRCollector_INF — Invoke-IRCollector

A comprehensive single-file PowerShell **Incident Response (IR) / DFIR triage** collector for Windows.
Run it on a live Windows host or a booted forensic clone; it gathers all high-value artifacts into a
single timestamped folder, writes a SHA-256 hash for every file to a manifest, and packages the output.

> Defensive / authorized IR use only.

## Requirements
- Windows + **PowerShell 5.1+**
- **Administrator** session for full collection
- (Optional) NTFS for `$MFT`; VSS for locked files; 7-Zip for large archives

## Usage
```powershell
# Collect everything (including $MFT / $UsnJrnl)
powershell -ExecutionPolicy Bypass -File .\Invoke-IRCollector.ps1 -Full

# Selective
.\Invoke-IRCollector.ps1 -UseVSS -CollectRegistryHives -DaysBack 7
.\Invoke-IRCollector.ps1 -CollectMFT
```

### Parameters
| Parameter | Description |
|---|---|
| `-OutputPath` | Output root folder (default `<SystemDrive>\IR_Collection`) |
| `-DaysBack` | Look-back window for time-based collection (default 7) |
| `-UseVSS` | Volume Shadow Copy for locked files |
| `-CollectRegistryHives` | SYSTEM/SOFTWARE/SAM/SECURITY + NTUSER/UsrClass |
| `-CollectBrowserArtifacts` | Chrome/Edge/Brave/Firefox artifacts |
| `-HashRunningBinaries` | Hash + Authenticode status of running binaries |
| `-CollectMFT` | `$MFT` + `$UsnJrnl` (raw NTFS) |
| `-NoCompress` | Skip final packaging |
| `-Full` | Enable all heavy modules |

## What it collects (15 modules)
System · Users/Accounts · Network (connection-to-process mapping, firewall, DNS, SMB) · Processes
(command line, signature, loaded DLLs) · Services · **Persistence** (Run/Winlogon/LSA/IFEO/
WMI-subscription/scheduled-task) · Scheduled Tasks · **Event Logs** (raw EVTX export + parsed key
events) · **Registry hives** · **Forensic** (Prefetch/Amcache/SRUM/Shimcache/USBSTOR/`$MFT`/`$UsnJrnl`) ·
Browser · Defender/AV (including exclusions) · Filesystem timeline · PowerShell history ·
Veeam (auto-detected when present).

## Resilience
- Each module is wrapped in its own `try/catch` — one failure does not stop the rest
- Fallback chains: `Get-LocalUser`→`net user`, VSS↔direct copy, `reg save HKU\<SID>` for locked hives,
  time-filtered↔full EVTX export, 7-Zip↔Compress-Archive
- Environment-agnostic: auto-detects the system drive; works across domain/workgroup and
  server/workstation

## Output
`IR_<HOST>_<timestamp>/` (00_Collection … 15_Veeam) + `manifest_sha256.csv` + `SUMMARY.json` +
a `.7z`/`.zip` archive (with SHA-256).

---
InfinitumIT · Incident Response
