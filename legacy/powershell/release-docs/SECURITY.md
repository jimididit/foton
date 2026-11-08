# Security policy

## Supported versions

| Line | Status |
|------|--------|
| **1.38.x** (PowerShell, source in `legacy/powershell/`) | **Security fixes only** until Foton v2.0.0 ships. No new features. After v2.0.0 it is unsupported, but remains available on [Releases](https://github.com/jimididit/foton/releases) and the PowerShell Gallery for hosts older than Windows 10 / Server 2016. |
| **2.x** (C# executables on `main`) | Supported from v2.0.0. Prereleases (`v2.0.0-alpha.*`) are for testing and are not supported. |
| Older than 1.38 | Unsupported. Upgrade to the latest 1.38.x. |

Security fixes for 1.38.x ship as a new 1.38.x tag (GitHub release and PowerShell Gallery). Older releases are not backported unless a release advisory says otherwise.

## Reporting a vulnerability

**Do not** file a public GitHub issue for security-sensitive reports.

Prefer [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) on this repository when enabled. Otherwise email the maintainers listed on the GitHub org or profile with:

- Affected version or commit
- Reproduction steps or a minimal proof of concept
- Expected impact (for example package integrity, path traversal when opening a case, offline-layer network access)

You should receive an acknowledgement within a few business days.

## In scope

- Analyze / Parse / Carve reading the live host or network (must stay offline)
- Package or hash integrity bypasses
- Path traversal or unsafe handling when opening a case folder or ZIP
- Unintended credential or secret leakage in default logs or reports (SAM and SECURITY hives are deliberately not collected)

## Out of scope

- Antivirus false positives on `foton-collect.exe` or the 1.38.x Collect scripts (common for DFIR tooling; see [docs/USAGE.md](docs/USAGE.md))
- Findings that match legitimate admin tools (pattern lists are intentionally broad)
- Missing coverage of a Windows artifact (feature request)
- Expected live-collection side effects (Prefetch, event logs, `reg save` hive exports into the case folder, optional `-LoadUserHives` load/unload)-disclosed in operator docs

## Signing

Release executables are **not Authenticode-signed** yet, so Windows SmartScreen may warn on first run. Trust comes from two checks that need no certificate:

- `SHA256SUMS.txt` on each release lists the SHA-256 of every asset.
- Each asset carries a GitHub build provenance attestation: `gh attestation verify <file> --repo jimididit/foton` proves it was built by this repository's release workflow from a specific commit.

After both checks pass, `Unblock-File` removes the downloaded file's Mark-of-the-Web. Authenticode signing is planned once Foton sees wider public use; this document will be updated when it ships. The 1.38.x scripts and their ExecutionPolicy guidance are documented at the [v1.38.1 tag](https://github.com/jimididit/foton/blob/v1.38.1/docs/USAGE.md).
