# Coverage and product intent

Living map of **what Foton is for**, **what each layer already captures**, and **what is still missing**. Update this file when you add a collector, baseline provider, or parser. Schema version numbers stay in `Foton.psd1`; this file is the *inventory*.

Sources that shaped the gap list (industry practice, not a vendor checklist):

- Sysinternals **Autoruns** ASEP categories ([Microsoft](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)): logon, services, drivers, scheduled tasks, WMI, Winlogon, AppInit, IFEO, LSA, print monitors, KnownDLLs, Winsock, codecs, Office, boot execute.
- MITRE ATT&CK persistence (TA0003): T1547 (Run/Startup/Winlogon/SSP), T1053.005 tasks, T1543.003 services, T1546 (WMI, IFEO, AppInit, COM), T1197 BITS.
- Live-response kits in the same niche (NovaTrace-style IR zips, SANS baselining papers): volatile first, then persistence, then execution evidence (Prefetch, Amcache, SRUM, BAM), then EVTX - hashed package, admin preferred, standard-user gaps recorded.
- Configuration-drift practice: compare a **known-good** snapshot to later state; Defender/`Get-MpPreference` and local admin membership are high-value *stable* surfaces, not “malware scores.”

Foton must not become Autoruns, Velociraptor, WinPmem, or a CIS benchmark scorer. It automates **enough Windows DFIR** that an examiner gets a hashed package and a honest diff, then goes deeper with specialist tools.

---

## Use cases (in scope)

| Use case | Layer | Success looks like |
|----------|--------|-------------------|
| **Live triage** | Collect | One file on the endpoint; volatile + persistence + logs + coverage JSON; HTML observations; no “infected” banner |
| **What changed?** | Baseline temporal | Two snapshots of *stable* config; field-level Added/Removed/Modified; HTML compare |
| **Host vs golden** | Baseline fleet | Same engine; wording says role image, not a clean-host certificate |
| **Harden / audit snapshot** | Baseline + Collect security tasks | UAC/WDigest/SMB/Defender facts; drift vs a provisioning baseline |
| **Offline execution evidence** | Parse | Prefetch, LNK, later Amcache/EVTX/SRUM from files *in the package* |
| **IOC sweep** | Analyze | Text/CSV IOC against package rows, not a live host |

## Use cases (out of scope unless we change product charter)

- RAM acquisition, kernel dumps, packet capture
- Full NTFS MFT/USN/$LogFile carving in PowerShell (see `docs/CARVE.md`)
- Live VirusTotal / any Analyze-layer network
- Remediation, quarantine, disabling startup apps
- Domain-wide hunting (DCSync, GPO at the DC). Endpoint *may* later record “this host is Entra-joined” as a fact
- Replacing EDR telemetry or Sysmon

---

## Collect vs Baseline (do not conflate)

**Collect** answers “what is on this host *right now*, including volatile evidence?” PIDs, connections, Prefetch listing **and copied `.pf` files**, Amcache/SRUM copies, Defender detections, sessions. Coverage gaps (`SkippedNotElevated`) are findings.

**Baseline** answers “did *stable configuration* change between two observations?” Same machine state must hash the same. Exclude PIDs, connection 4-tuples, uptime, last-run times, ephemeral UDP, BITS transfer progress.

A surface can exist in **both** (services, tasks, WMI) with different fields. Collect includes HKCU Run and `startup_approved`. Baseline **Autorun** is HKLM; **UserAutorun** is loaded-hive HKCU; **StartupApproved** is Settings/Task Manager enable bits. **Settings → Startup apps** is not the Startup folder.

If Collect already captures a fact and Baseline does not, the examiner can still *see* it in a triage package; they cannot *diff* it over weeks without a provider.

---

## Collect today (v1 / flatten)

Nine categories. Facts only. See `src/Public/Collect/*.ps1` task names.

| Category | In tree (high level) |
|----------|----------------------|
| System | OS, time sync, **Entra/workplace join / MDM enrollment (local registry)**, hotfixes, Secure Boot/TPM/BitLocker, disks, env, VSS |
| Users | Local users/groups, profiles, sessions, RDP, secedit (admin), credential manager listing |
| Processes | Process list + tree, **named pipes**, nonstandard modules, PS history, RecentDocs |
| Network | Connections, listeners, IP/ARP/DNS/hosts, firewall, shares, proxy, Wi-Fi profiles |
| Persistence | Machine **and** per-user Run keys, Startup folders, **StartupApproved**, tasks + task XML listing, services, WMI, Winlogon/LSA/IFEO/AppInit, **cmd_autorun**, **session_manager_boot**, **known_dlls**, **winsock_lsp**, **active_setup**, **silent_process_exit**, **netsh_helpers**, **time_providers**, **screensaver**, accessibility binaries, COM hijack *candidates*, BITS, Office add-ins |
| Security | Defender status/prefs/detections, hardening CSV, auditpol (admin), SMB/WinRM, PS policy, non-MS roots, AppLocker/WDAC summary |
| EventLogs | Capped queries + log configuration |
| Filesystem | User-writable executables, recent System32 churn, Prefetch listing + **copied `.pf`** (capped), **Amcache.hve** (+ logs), **SRUM** (+ WAL/SHM), **BAM/DAM UserSettings**, **AppCompatCache.bin export**, **OneDrive/Teams local inventory**, ADS, Recycle Bin, USB, LNK/jumplist *inventory*, odd root items |
| Software | Uninstall keys, drivers, browser extensions, RAT name hits, AppX |

**Collect gaps (priority).** Common in IR kits and still thin or missing as *package artifacts*:

| Priority | Gap | Why it matters | Note |
|----------|-----|----------------|------|
| done (1.2.0) | Copy Prefetch `.pf`, Amcache.hve, SRUM DB (capped) | Parse cannot run on a listing CSV | Locked files: `Copy-FotonHostFile` FileShare.ReadWrite; failures in the copy CSV |
| done (1.5.0) | BAM/DAM UserSettings + raw AppCompatCache.bin | Execution evidence when Prefetch is off | Admin. Shimcache entries not parsed |
| done (1.4.0) | Named pipes | Classic IR volatile | Collect only; names churn |
| done (1.3.0) | Named CSVs: cmd_autorun, session_manager_boot, known_dlls, winsock_lsp, active_setup | Autoruns tabs as dedicated files | Folded winlogon_lsa CSV still exists |
| done (1.6.0) | Entra / workplace join / MDM enrollment facts | Modern endpoints | Local registry only. No dsregcmd, Graph, or tenant lookup. Unloaded hives are a visibility gap |
| done (1.7.0) | OneDrive/Teams local artifacts | Modern endpoints | Inventory only. No Graph, no cookie/IndexedDB copy, no cloud-tree walk |
| done (1.8.0) | Screensaver, SilentProcessExit, netsh helpers, time providers | Lower-volume ASEPs | Screensaver Collect-only (user churn). Others also baseline 1.13.0 |
| P3 | Memory, pcap, full MFT | Wrong runtime | External tools |

Standard-user Collect is **intentional**. Security log, Prefetch, other users’ hives stay skipped, not empty-success.

---

## Baseline today (schema 1.13.0)

See `src/Public/Baseline/README.md` for identity keys.

Present: Service, Driver, ScheduledTask, Autorun (HKLM Run/RunOnce), **UserAutorun** (loaded hives), StartupFile, StartupApproved, **DefenderPreference**, **RemoteAccessConfig**, **LsaPackage**, **PrintMonitor**, **BitsJob**, **CmdAutoRun**, **SessionManager**, **KnownDll**, **ProxyConfig**, **WinsockLsp**, **ActiveSetup**, **SilentProcessExit**, **NetshHelper**, **TimeProvider**, LocalAccount, LocalGroupMember, HardeningRegistry, InstalledSoftware, FirewallRule, Certificate, Listener (TCP + non-ephemeral UDP), NetworkShare, SystemBinary, HostsEntry, MachineEnvironment, WmiPermanentEvent, ImageFileExecution, Winlogon, AppInitDll.

**Baseline gaps (priority).** Prefer these over exotic ASEPs. Each needs a stable identity key and documented false positives.

| Priority | RecordType (proposed) | Identity sketch | Why / FP |
|----------|----------------------|-----------------|----------|
| done (1.5.0) | RemoteAccessConfig | Setting | RDP NLA/port/layer; WinRM policy; SMBv1 DWORD. FP: helpdesk RDP. Enable flag remains HardeningRegistry |
| done (1.6.0) | LsaPackage | Kind + Package | T1547.005. One token per row. FP: MFA/EDR SSP |
| done (1.7.0) | PrintMonitor | Name | Spooler SYSTEM DLL. FP: printer installs |
| done (1.8.0) | BitsJob | JobId | T1197. Type/notify, **not** bytes. FP: Windows Update jobs |
| done (1.9.0) | CmdAutoRun | Hive + Key | cmd.exe AutoRun. FP: doskey/clink/conda |
| done (1.10.0) | SessionManager | Kind + Name | BootExecute family + AppCertDlls. **Not** PFRO. FP: autocheck, disk tools |
| done (1.11.0) | KnownDll | Name | Search-order map. FP: feature updates |
| done (1.11.0) | ProxyConfig | Scope + Setting | WinHTTP + IE settings. FP: PAC. Not DefaultConnectionSettings |
| done (1.12.0) | WinsockLsp | Kind + Entry | Catalog LibraryPath. FP: VPN/EDR |
| done (1.12.0) | ActiveSetup | Key + Guid | HKLM StubPath. Version = Info. HKCU once-run is Collect-only |
| done (1.13.0) | SilentProcessExit | ImageName | MonitorProcess ASEP. FP: procmon/debug dumps |
| done (1.13.0) | NetshHelper | Key + Name | T1546.007. FP: VPN/EDR helpers |
| done (1.13.0) | TimeProvider | Name | W32Time DLLs. FP: VMIC/GPO Enabled. Not NTP peers |
| Collect-only | Screensaver | - | `screensaver` CSV; Desktop/policy SCRNSAVE.EXE. User churn |
| Collect-only | ComHijack | - | `com_hijack_candidates` CSV; too noisy for a stable baseline |
| Collect-only | OfficeAddin | - | `office_addins_and_templates`; user churn |
| P2 | OptionalFeature / Appx (pinned) | Name | Noisy on consumer SKUs |
| P3 | Codecs, gadgets, IE BHO | - | Low ROI unless hunting a specific family |
| never | Ephemeral UDP, PIDs, last-run, bytes-in-flight | - | Destroys payload hash |

**Hive load:** per-user baseline rows (StartupApproved, UserAutorun) only see **loaded** NTUSER hives unless we add optional `reg load` (always `finally`, disclose footprint). Document visibility gaps in `coverage.json`.

---

## Parse / Analyze / Carve

| Layer | Have | Next (useful DFIR, still offline) |
|-------|------|-----------------------------------|
| Parse | Prefetch (uncompressed SCCA), LNK, **EVTX (selected IDs, capped)**, **jumplists (DestList + custom LNK)** | Amcache *parser* (raw hive, not invented fields), shellbags, SRUM *parser* (ESE), browser DB - **fixtures first**. Collect copies Amcache/SRUM; do not fake a parse. |
| Analyze | Triage heuristics + IOC file | Rules that consume *parsed* rows and baseline diffs; never live WMI |
| Carve | MZ/PE signature scan of a blob | Not NTFS unallocated in PS |

---

## How to extend (refinement rules)

1. Map the **operator UI or ATT&CK technique** to the actual artifact (Startup apps → `StartupApproved`, not Startup folder).
2. Decide Collect, Baseline, or both. Volatile → Collect only.
3. New baseline provider: identity key, compared fields, false positives, schema bump, recapture day0.
4. New collect task: facts, `RequiresElevation` if needed, manifest skip, no severity.
5. If PowerShell cannot do it correctly (raw hive, memory), say so and point at a tool - do not emit a fake empty table.

When this inventory changes, bump nothing unless on-disk columns change; then bump Collect or Baseline schema as in `src/Private/Schema/README.md`.
