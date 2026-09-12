# Landscape, strengths, and development direction

Contributor and agent guidance: **how Foton should grow relative to specialist Windows DFIR tools.** Artifact inventory stays in [COVERAGE.md](COVERAGE.md). Ordered backlog and public-release bar stay in [TODO.md](TODO.md). Workstation tool install design stays in [TOOLS.md](TOOLS.md). This file is the **strategy**: what to keep, what to compose, what not to rebuild in PowerShell — including the post-landscape course check so we do not restart from a new plan every audit.

Landscape snapshot: August 2026 (module **1.24.0** / collect **1.8.0** / baseline **1.13.0**). **Course check: September 2026** against module **1.27.0**, collect schema **1.10.0**, baseline schema **1.14.0**. Tool capabilities change; the *composition* rule and the anti-monstrosity rule do not.

When you write a development plan from this document, treat the **Recommended build strategy**, **Product thesis**, and **Planning constraints** sections as requirements, not suggestions.

---

## Product thesis (north star)

**Win as the go-to Windows audit / known-good baseline tool**, and stay a credible first-pass IR / triage toolkit by composing specialists — not by absorbing them.

| Use case | Foton should be | Peer still owns deep work |
|----------|-----------------|---------------------------|
| **What changed since provision / golden?** | Best-in-class: identity keys, deterministic hash, field-level HTML compare, coverage honesty | — |
| **Harden / audit snapshot** | Best-in-class for *this host vs last week / role image* (facts + drift), not a CIS pass/fail scorer | CIS-CAT / Intune for policy benchmarks |
| **Live triage → hashed case** | Competitive: one `.ps1`, RMM-friendly, volatile + persistence + raw copies + HTML observations | KAPE/ORC for full disk targets; Velociraptor for fleet |
| **Offline EVTX hunt / Prefetch depth** | Competitive **only via compose** (Hayabusa, EZ Tools) inside the case | Hayabusa, EZ Tools as engines |

That is how to be a top-tier *solution for several use cases* without becoming a kitchen-sink. Competing on “more CSVs of the same live APIs” or “another Prefetch parser in PowerShell” is the path to a monstrosity. Competing on **hashed case + known-good config diff + honest first-pass report that specialists feed** is the path that was already working.

**Anti-monstrosity rule:** every new feature must either (a) strengthen Baseline/audit, (b) make Collect or the package more useful to specialists, or (c) make compose/analyze *convenient and reproducible*. If it is “completeness for its own sake” (another ASEP tab, native Sigma, TUI before the release bar), it waits or dies in [TODO.md](TODO.md) Considering.

---

## Direct answer

Foton is a coherent IR + configuration-drift toolkit with examiner-grade ethics (hashed package, coverage gaps disclosed, observations not verdicts). It is **not** overcomplicated for a five-layer product. It **is** still below par if judged as KAPE + Hayabusa + Autoruns in one PowerShell binary — and that judgment is the wrong target.

The combination is uncommon:

- One-file PowerShell 5.1 live triage (no install, RMM-friendly)
- Deterministic field-level baseline **beyond** ASEP (Defender, RDP/WinRM, certs, firewall, listeners, LSA, BITS, hardening, WDAC policy hash)
- Offline parse / analyze / report on a hashed package
- Findings that refuse to say “compromised”
- Compose path that attributes the collector’s own EVTX footprint instead of accusing the host

Individual layers already have better specialists. **Improve by composing those tools, not cloning them.** A full Foton toolkit remains the right product idea: Foton owns the case, the known-good diff, and the report. Specialists own deep parse, Sigma EVTX hunting, exotic ASEP tabs, and raw-disk copies.

**PowerShell is the right language for Collect and Baseline capture.** It is the wrong language for gold-standard Prefetch/Amcache/EVTX/ESE/NTFS work. Industry already splits this way: script or dropper collect, C#/Rust parse.

---

## Course check (did landscape work pull us off course?)

**No. Direction is right; unfinished work is packaging and finish, not a strategy reset.**

What the landscape plan said to do, and what landed through **1.27.0**:

| Landscape bet | Status | Keep / stop |
|---------------|--------|-------------|
| Copy raw artifacts specialists need (hives, LNK, Tasks XML, browser DBs, wider EVTX, optional USN) | **Done** (collect 1.9.0) | Keep. Do not grow `$MFT` in PS unless charter changes. |
| Compose Hayabusa on copied EVTX → findings | **Done and verified** on a real package; collector-footprint exclusion added | Keep. Chainsaw ingest still open — thin, not a rewrite. |
| Compose PECmd / EvtxECmd → findings | **Done in 1.29.0** (coverage, user-writable paths, high-attention EventIds) | Keep thin; do not grow native Prefetch/EVTX parsers for this. |
| Analyze reads parsed rows + baseline diffs | **Started** — still thin | Keep prioritizing rules over new collectors. |
| Do not rebuild Sigma / ESE / NTFS in PowerShell | **Held** | Keep holding. |
| Operator packaging / release bar | **Partial** — AMSI fixed; lab ticks automated; tool install (Hayabusa); analyze-without-clone + Authenticode still open | Finish release-bar before novelty. |
| Exotic ASEP “for completeness” | **Not scheduled** (codecs, BHO, …) | Correct. |

**Wrong-direction traps to refuse now:**

1. Growing native `ConvertFrom-Foton*` to chase EZ Tools quality.
2. Adding baseline providers that Autoruns already covers better (codecs, gadgets, IE BHO).
3. Putting network / interactive install prompts inside `compose` or `analyze` (see [TOOLS.md](TOOLS.md)).
4. Building TUI/GUI or an in-report CSV browser before the public-release bar is mostly green.
5. Becoming a CIS scorer, EDR, memory imager, or fleet agent — that abandons the uncommon niche.

**Right-direction finish line for “top tier”:** Baseline/audit is already the strongest unique slice — polish trust and operator path (release bar, tool install, analyze zip). Triage becomes top-tier when compose is *one setup + one chain on a case folder*, and Analyze consumes what compose wrote — not when Foton reimplements Hayabusa.

---

## What Foton is doing well (protect this)

| Area | Why it matters |
|------|----------------|
| Layer split | Collect/Baseline capture may touch a live host. Parse, Carve, Analyze never do. Same input → same output. |
| Flatten deploy | Endpoint gets one `.ps1`, not a module tree. Matches constrained-channel / RMM reality. |
| Package as unit of I/O | Hashed folder or ZIP, manifest, coverage JSON. Later work composes without returning to the host. |
| Honesty | `SkippedNotElevated`, empty findings ≠ clean host, post-incident baseline is a picture of *that* state, no “infected” banner. |
| Baseline identity keys | Field-level Added/Removed/Modified with documented keys and false-positive notes. Schema versions refuse incompatible diffs. |
| Privilege-aware coverage | Standard-user collect is intentional; gaps are Info findings, not silent empty tables. |
| Provider/collector files | One surface per file so the toolkit grows without a 3k-line script. |
| Restraint already in COVERAGE.md | Not Autoruns, not Velociraptor, not WinPmem, not a CIS scorer. Memory/pcap/full MFT named as wrong runtime. |
| Compose honesty | Hayabusa hits caused by the collection itself are attributed and excluded from severity bands (methodology finding), so the report does not accuse the host of the examiner’s script blocks. |
| AMSI-aware flatten | Suspicious-command pattern list is not embedded in Collect; workstation Analyze derives hits; build fails if the flatten is blocked at load. |

First-time PowerShell at this size usually looks like one giant script that prints “malware detected.” Foton does not. Keep that charter.

---

## Verdict by worry

| Worry | Assessment |
|-------|------------|
| Best practices | Strong: flatten deploy, SHA-256, UTC, fail-into-manifest, identity keys, schema versions, standard-user honesty, AMSI load check in build. |
| Missing collect | Live API/registry coverage is good. Raw copies largely closed in 1.9.0; still thinner than KAPE/ORC on `$MFT` / full disk (by design for now). |
| Baseline / audit | **Strongest product claim.** Above typical Autoruns-CSV diffs. ASEP tabs still not exhaustive (by design). Path to “go-to” is trust + docs + fleet/golden workflows, not more exotic providers. |
| Automation / “is it compromised?” | Triage heuristics exist; they must not decide compromise. Hayabusa bands work. **Unused potential:** rules that consume EZ-tool CSV, thicker parsed-row / baseline-diff rules. |
| PowerShell-only | Correct for RMM/no-install collect. Incorrect as the only parser runtime. |
| Overcomplicated? | Charter is wide but the file-per-provider model prevents a 3k-line script. Complexity matches intent. The trap is more native parsers, UI shells, and “completeness” providers. |
| Peer parity | Behind on workstation convenience (PATH, no tool install, ZIP staging) and on feeding compose output into findings. Ahead on baseline identity-key drift + honesty model. |

---

## Similar and equivalent tools

Nothing else is the same five-layer PowerShell product. Many tools occupy **one slice** better. Use them as the example to follow for that slice.

| Tool | Intent | Vs Foton | Steal this / do not steal |
|------|--------|----------|---------------------------|
| **KAPE** | Industry default for targeted Windows artifact *copy* + module parse | Collects more files, faster. Does not replace identity-keyed config baseline or findings ethics. | Study targets (hives, USN, browsers). Copy bytes into the package. Do not reimplement KAPE’s module ecosystem in PS. |
| **Velociraptor** | Fleet hunt / remote VQL (offline collector exists) | Wins at scale. Loses on “one unsigned `.ps1` over RMM, no agent.” | Artifact lists and hunt *ideas*. Do not become a C2 or require an always-on agent. |
| **CyLR / DFIR-ORC / FastIR** | Native or Python live collectors; ORC is ANSSI-grade file snapshot | Better at MFT/hives/raw disk. Weaker “what changed in config” and HTML narrative. | ORC/KAPE for disk artifacts; Foton for API-visible state + baseline. |
| **Kansa / Invoke-LiveResponse** | PowerShell IR frameworks (often WinRM, modular collectors) | Closest cousins. Kansa is fleet remoting; Foton is single-host flatten + package + baseline. | **Kansa module list as a collect checklist**, not as a remoting model (WinRM is often disabled). |
| **Autoruns / autorunsc / [p0w3rsh3ll AutoRuns](https://github.com/p0w3rsh3ll/autoruns/)** | ASEP inventory + CSV baseline of autostarts | Deeper ASEP tabs (codecs, BHOs). Foton baseline is *broader* than persistence. | Optional workstation pass of `autorunsc`. Do not duplicate every Autoruns tab as a Foton provider. |
| **EZ Tools** (PECmd, LECmd, EvtxECmd, AmcacheParser, …) | Gold-standard offline Windows parsers | `ConvertFrom-Foton*` will not match this depth in PowerShell. | Collect bytes; run EZ Tools on the workstation; import structured output. That *is* Foton Parse when the format is too hard for PS. |
| **Hayabusa / Chainsaw** | Sigma/rule EVTX hunt and timelines | Selected-ID capped EVTX in Foton is a sample, not a hunt. | Copy `.evtx` (already in collect). Analyze with Hayabusa. Import hits as findings. Do not rebuild Sigma in PS. |
| **osquery** | SQL endpoint state + scheduled diffs | Continuous fleet; needs an agent; not a hashed IR case. | Table schemas as field inspiration. Not a deploy model for Collect. |
| **CIS-CAT / DSC / Intune compliance** | Score against a published hardening benchmark | Different question (pass/fail policy vs this host vs last week). | Do not become a CIS scorer. Keep hardening registry rows as **facts**. |

### Common (do not reinvent)

Live process/network/persistence dumps, Prefetch *listings*, EVTX copies, hashed zips, HTML overviews. KAPE, CyLR, FastIR, Kansa, Invoke-LiveResponse, and similar kits all do variants. Competing on “more CSVs of the same live APIs” is a losing race.

### Uncommon (protect this)

Deterministic baseline hash; field-level Added/Removed/Modified with documented identity keys; privilege-aware `collection_coverage.json` / `coverage.json`; findings that refuse “compromised”; Collect flatten that is still PowerShell 5.1 with no install. p0w3rsh3ll AutoRuns baselines ASEP only. osquery diffs need an agent. CIS-CAT scores a benchmark, not this host vs last week.

---

## Where Foton is behind (actionable gaps)

| Area | Gap | Why it matters | Direction |
|------|-----|----------------|-----------|
| Raw artifact copies | **Largely closed in collect 1.9.0**: machine + user hives with sidecars, LNK/jumplists, Tasks XML, browser DBs, host text logs, wider EVTX, optional USN `$J`. `$MFT` and `$LogFile` still not copied. | Parse/carve and EZ Tools need **bytes**, not CSV summaries. | Remaining: decide whether `$MFT` belongs here or stays a KAPE/ORC job. Do not parse any of it in PS 5.1 on the endpoint. |
| Analyze automation | **1.29.0**: rules read collect CSVs, thin `parsed_records` / `baseline_diff`, Hayabusa, **PECmd**, and **EvtxECmd** compose CSV. Chainsaw still inventory-only. | Highest ROI without new collect. | Chainsaw ingest next. Still observations, not verdicts. |
| EVTX hunting | **Implemented and verified** via `Invoke-FotonExternalParse` + Hayabusa; collector-footprint attribution excludes self-hits from severity bands. Chainsaw wiring untested; EZ Tools often `NotOnPath`. | Wrong to rebuild Hayabusa in PowerShell. Composing a hunt engine means owning the collector’s footprint **and** making the tool findable. | [TOOLS.md](TOOLS.md) install (Hayabusa first); verify Chainsaw; same footprint model for other hunt engines. |
| Parse correctness | MAM Prefetch, SRUM ESE, shellbags, Shimcache *entries*, legacy Amcache `File\*` | PowerShell is the wrong runtime. | Copy + EZ Tools (or documented “unsupported,” never guessed fields). Native ConvertFrom-* stays air-gap fallback. |
| Operator packaging | Authenticode/ExecutionPolicy story, analyze-without-clone zip, lab ticks still open. **AMSI fixed in 1.27.0.** ZIP open stages a new temp dir each time — chaining `compose` then `analyze` on a ZIP loses tool output (documented: extract first). | This is what makes the tool feel “not ready,” not missing another Winlogon value. | Finish [TODO.md](TODO.md) public-release bar; build tool install; keep ZIP staging documented until a deliberate package-session fix exists. |
| ASEP completeness | Codecs, gadgets, IE BHO marked low ROI; COM too noisy for baseline | Correct product call. | Use Autoruns when hunting those families. Do not add those providers “for completeness.” |
| Baseline as go-to | Capture + compare + HTML exist and are strong. Fleet/golden framing, operator docs, and release trust are thinner than the engine. | “Go-to audit/baseline” is won on trust and workflow, not on the 35th provider. | Document golden-image / temporal recipes in USAGE; close lab ticks; resist exotic ASEP. |

Collect P3 (memory, pcap, full MFT) and Carve-as-NTFS remain **wrong runtime** — point at WinPmem / KAPE / DFIR-ORC / a disk image. See [CARVE.md](CARVE.md).

---

## Recommended build strategy

Ordered for the north star. Detail and checkboxes live in [TODO.md](TODO.md).

### 1. Finish (trust and convenience — product, not novelty)

- Public-release lab ticks and Authenticode / ExecutionPolicy story.
- Analyze zip that does not require cloning the repo.
- `Install-FotonTool` (Hayabusa first) per [TOOLS.md](TOOLS.md); compose stays offline.

### 2. Compose (default for Parse / hunt / exotic ASEP)

Foton’s job on the **endpoint** is Collect + Baseline capture in PowerShell 5.1.

Foton’s job on the **workstation** is: open the package, run what PowerShell can do *correctly*, and **orchestrate better languages/tools** for the rest:

1. Hayabusa (or Chainsaw) on exported `.evtx` → timeline / Sigma hits → import as findings (cite the tool and rule; exclude collector footprint).
2. EZ Tools on copied `.pf`, LNK, jumplists, Amcache, hives → structured records in the package; **Analyze must read those outputs**, not only hash them.
3. Optional `autorunsc` when the question is “every Autoruns tab,” not “did *this* identity-keyed surface change.”
4. Optional KAPE/ORC *in addition to* Foton when the case needs MFT — until Collect explicitly owns `$MFT`.

Existing `ConvertFrom-Foton*` parsers stay useful as **no-dependency** fallbacks. They are not the quality ceiling.

### 3. Deepen Baseline / audit (the uncommon wedge)

- Prefer operator workflows (provision day0 → later compare; host vs golden) and more **diff → findings** rules over new record types.
- Add a provider only when identity key + false positives are documented and COVERAGE.md gains a row — never “for completeness.”

### Stop (do not schedule)

Named in COVERAGE.md / TODO.md as low ROI or wrong runtime — keep that list:

- Full ESE SRUM parser in PowerShell
- NTFS unallocated carve in PowerShell
- MAM Prefetch inflate in PowerShell (use PECmd compose instead)
- In-process Sigma engine
- CIS benchmark scorer / “risk score”
- TUI/GUI before the public-release bar is mostly green
- Codecs, gadgets, IE BHO baseline providers
- Domain-wide hunting, live VirusTotal, remediation
- Interactive install prompts inside compose/analyze
- Mutating the user `PATH` from Foton

That restraint is professional, not incomplete.

---

## How Foton should use other people’s work

| Layer | Foton owns | Follow specialists by |
|-------|------------|------------------------|
| Collect | One-file PS5.1, volatile order, coverage JSON, hashed package | KAPE/ORC **target lists** for which *files* to copy; Kansa **module list** as a checklist |
| Baseline | Identity keys, deterministic JSON, field-level diff, HTML compare | Autoruns only for ASEP completeness checks; do not shrink Foton to ASEP-only |
| Parse | Package layout, hashes, “unsupported format” records, optional native PS parsers | EZ Tools as the default quality path for Prefetch, LNK, EVTX, Amcache, hives |
| Analyze | Findings model (tier, WhyItMatters, no verdict), IOC file match, HTML report | Hayabusa/Chainsaw for EVTX; ingest their output; never live WMI |
| Carve | Honest limit (MZ/PE blob scan today) | External imagers and NTFS tools; do not fake NTFS in PS |
| Report | Offline search/nav, escaped HTML | Do not add CDN “compromised” dashboards |

---

## Planning constraints (for a follow-on development plan)

Any plan generated from this file should:

1. **Keep** Collect/Baseline as PowerShell 5.1 flatten scripts. Do not require .NET 8, Python, or an agent on the endpoint.
2. **Treat the workstation as a composition host.** New parse/hunt quality comes from invoking or documenting EZ Tools / Hayabusa (and storing their output in the package), not from larger `ConvertFrom-Foton*` surface area — unless the format is small, fixture-tested, and PowerShell can be *correct*.
3. **Prioritize** (a) public-release bar and tool install convenience, (b) Analyze consuming compose + baseline diffs, (c) Baseline/audit operator workflows — over exotic ASEP providers and new native parsers.
4. **Update** [COVERAGE.md](COVERAGE.md) when collect targets or “parsed by external tool” rows change; update [USAGE.md](USAGE.md) when operators gain a documented workstation pipeline; bump schemas only when on-disk columns or baseline records change.
5. **Stay honest.** Findings remain observations. External-tool hits are Tier 2 unless they are raw facts (hash match, Event ID present). Name the tool in Artifact / WhyItMatters.
6. **Do not** expand charter into EDR, memory imaging, CIS scoring, or fleet C2.
7. **Do not** start a parallel strategy doc. Course checks update *this* file and [TODO.md](TODO.md). Inventory stays in COVERAGE; tool install design stays in TOOLS.

---

## Bottom line

Specialists will beat each layer. The product job is to be the **hashed case** and the **known-good config diff** those specialists feed — and to automate first-pass observations without lying.

Foton should remain a full toolkit without becoming a monstrosity: PowerShell collects and baselines; better languages and existing tools parse and hunt; Foton owns the case, the drift story, and the report. Landscape work through 1.27.0 moved the right levers. Finish trust and compose convenience next — that is how Foton becomes the go-to audit/baseline tool and a competitive IR desk, not by cloning KAPE or Hayabusa into PowerShell.
