# Security policy

## Supported versions

Fixes land on `main` and ship in the next tagged [release](https://github.com/jimididit/foton/releases) (also published to the PowerShell Gallery as `Foton`). Older releases are not backported unless a release advisory says otherwise.

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

- Antivirus / AMSI false positives on Collect flatten scripts (common for DFIR tooling; see [docs/USAGE.md](docs/USAGE.md))
- Findings that match legitimate admin tools (pattern lists are intentionally broad)
- Missing coverage of a Windows artifact (feature request)
- Expected live-collection side effects (Prefetch, event logs, `reg save` hive exports into the case folder, optional `-LoadUserHives` load/unload)-disclosed in operator docs

## Signing and ExecutionPolicy

Release scripts are **not Authenticode-signed** yet. Trust comes from two checks that need no certificate:

- `SHA256SUMS.txt` on each release lists the SHA-256 of every asset.
- Each asset carries a GitHub build provenance attestation: `gh attestation verify <file> --repo jimididit/foton` proves it was built by this repository's release workflow from a specific commit.

Endpoint scripts run with a process-scoped bypass that changes nothing on the target:

```powershell
powershell -ExecutionPolicy Bypass -File .\Foton-Collect_v<module>_schema<collect>.ps1
```

Workstation ExecutionPolicy and Mark-of-the-Web handling are in [docs/USAGE.md](docs/USAGE.md) ("Getting Foton"). Authenticode signing is planned; this document will be updated when it ships.
