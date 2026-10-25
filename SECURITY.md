# Security policy

## Supported versions

Fixes land on `main` and the latest tagged release. Older tags are not backported unless a release advisory says otherwise.

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
- Unintended credential or secret leakage in default logs or reports

## Out of scope

- Antivirus / AMSI false positives on Collect flatten scripts (common for DFIR tooling; see [docs/USAGE.md](docs/USAGE.md))
- Findings that match legitimate admin tools (pattern lists are intentionally broad)
- Missing coverage of a Windows artifact (feature request)
- Expected live-collection side effects (Prefetch, event logs, optional hive load)—disclosed in operator docs

## Signing and ExecutionPolicy

Endpoint scripts are **unsigned** in current public builds. Operators typically run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Foton-Collect.ps1
```

Verify SHA-256 of release assets before use. Authenticode-signed releases are planned; this document will be updated when they ship.
