# Security policy

## Supported versions

| Line | Status |
|------|--------|
| **3.x** (C# executables on `main`) | Supported: the latest release. Prereleases (tags with a suffix, such as `-alpha.1`) are for testing and are not supported. |
| **2.x** | Unsupported since v3.0.0. Upgrade to the latest release; packages and baselines from 2.x still open in 3.x. |
| **1.38.x** (PowerShell; source at the [v1.38.2 tag](https://github.com/jimididit/foton/tree/v1.38.2/legacy/powershell)) | Unsupported since v2.0.0. 1.38.2 is the final release and stays available on [Releases](https://github.com/jimididit/foton/releases/tag/v1.38.2) and the PowerShell Gallery for hosts older than Windows 10 / Server 2016. |
| Older than 1.38 | Unsupported. |

Security fixes ship in a new release on the current line. Older releases are not backported unless a release advisory says otherwise.

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
- `foton update` accepting a release not signed by a pinned release key, installing files that do not match the signed hashes, or writing outside its staging and install folders

## Out of scope

- Antivirus false positives on the Foton executables or the 1.38.x Collect scripts (common for DFIR tooling; see [docs/USAGE.md](docs/USAGE.md))
- Findings that match legitimate admin tools (pattern lists are intentionally broad)
- Missing coverage of a Windows artifact (feature request)
- Expected live-collection side effects (Prefetch, event logs, `reg save` hive exports into the case folder, optional `-LoadUserHives` load/unload)-disclosed in operator docs

## Signing

Release executables are **not Authenticode-signed** yet, so Windows SmartScreen may warn on first run. Trust comes from two checks that need no certificate:

- `SHA256SUMS.txt` on each release lists the SHA-256 of every asset. It catches a corrupted or swapped download, but it is published on the same release page as the files, so on its own it does not prove who built them.
- Each asset carries a GitHub build provenance attestation. With the [GitHub CLI](https://cli.github.com/), `gh attestation verify <file> --repo jimididit/foton` proves it was built by this repository's release workflow from a specific commit.

[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md#2-check-the-download) has the commands for both checks. A file downloaded with a browser carries Mark-of-the-Web, which only makes SmartScreen warn when it is started from File Explorer; after both checks pass, `Unblock-File` removes it. Authenticode signing is planned once Foton sees wider public use; this document will be updated when it ships. The 1.38.x scripts and their ExecutionPolicy guidance are documented in the [1.38.2 operator guide](https://github.com/jimididit/foton/blob/v1.38.2/legacy/powershell/release-docs/docs/USAGE.md).

### Release signature (updates)

From 3.3.0, each release also carries `foton-release.json`, which lists the SHA-256 of the release ZIP and of each executable. The maintainer signs it offline with the Foton release key (ECDSA P-256) and attaches the signature, `foton-release.json.sig`. The key never touches GitHub, so access to the repository or its workflows alone cannot sign a release. [`foton update`](docs/USAGE.md#updates) installs nothing without that signature, and checks every file against the signed hashes. The public halves are pinned in `src/Foton.Tools/Update/ReleaseKeys.cs`, with these SHA-256 fingerprints:

- Primary: `010afa6652bf2e495118bc711f484e88c7ea87d0c6db5781a4b4b8cd6a17bf02`
- Backup, used only if the primary is lost or retired: `a0f42ace5da28ddca292c6f17bf307a755eae6dc70d8360f6ec9c2fbf95a7596`

A change to these keys ships in a release signed with a key already pinned, and is announced in its notes.
