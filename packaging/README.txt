Foton {VERSION} for Windows 10 / Server 2016 and newer
https://github.com/jimididit/foton

  foton-console.exe   Analyst workstation, in a window: open and analyze case packages,
                      compare baselines, build collectors for endpoints.
  foton.exe           The same workstation work from a terminal (run it alone to list its verbs).
  foton-collect.exe   Endpoint: live triage into a hashed case package.
  foton-baseline.exe  Endpoint: snapshot of stable configuration, to compare later.

Each is one file; nothing to install. Only a collector goes to an endpoint: copy it there,
or let foton-console.exe (Collectors tab) or foton.exe bundle build the folder to send.

Check the files before you run them (they are not code-signed yet):
  Get-FileHash .\*.exe -Algorithm SHA256
      compare each with its line in SHA256SUMS.txt
  gh attestation verify .\foton-console.exe --repo jimididit/foton
      proves GitHub built it from this repository (needs the GitHub CLI)
Then, to start them from Explorer without a SmartScreen warning:
  Unblock-File .\*.exe

Getting started: https://github.com/jimididit/foton/blob/v{VERSION}/docs/GETTING-STARTED.md
Every switch, verb, and tab: https://github.com/jimididit/foton/blob/v{VERSION}/docs/USAGE.md
License: MIT (LICENSE in this folder)
