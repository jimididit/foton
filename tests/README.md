# tests/

Pester 5 tests. Run `.\tests\Invoke-FotonTests.ps1`.

| Folder | Role |
|--------|------|
| `Unit/` | One file per public function (or module smoke tests) |
| `Fixtures/` | Tiny real or synthesized artifacts — never client data |

When Analyze exists, keep a harness that loads mock records, calls `Invoke-FotonAnalysis` and `New-FotonReport`, without Windows if possible.
