# tests/

Pester 5 tests. Run `.\tests\Invoke-FotonTests.ps1`. CI runs the same suite on every PR.

| Folder | Role |
|--------|------|
| `Unit/` | One file per area (Analyze, Build, Collect, Core, Parse, Tools, ...) plus module smoke tests |
| `Fixtures/` | Tiny real or synthesized artifacts - never client data |

`Analyze.Tests.ps1` loads mock records into the session with `InModuleScope Foton`, then calls `Invoke-FotonAnalysis` (and `New-FotonReport` where needed), so rules are tested without a live host. Each rule has one mock that fires and one that must not.

`Build.Tests.ps1` builds both flattens and fails if one calls a Foton function it does not define. `Foton.Tests.ps1` fails if the README badge, USAGE version line, or example flatten filenames drift from `Foton.psd1`.

Compose tests use fake `.cmd` tools and an empty tool root, so they do not depend on what is installed on the machine running them.
