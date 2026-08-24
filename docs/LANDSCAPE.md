# Landscape, strengths, and development direction

Contributor and agent guidance: **how Foton should grow relative to specialist Windows DFIR tools.** Artifact inventory stays in [COVERAGE.md](COVERAGE.md). The public-release checklist stays in [TODO.md](TODO.md). This file is the **strategy**: what to keep, what to compose, what not to rebuild in PowerShell.

Landscape snapshot: August 2026. Foton versions at the time of writing: module **1.24.0**, collect schema **1.8.0**, baseline schema **1.13.0**. Tool capabilities change; the *composition* rule does not.

When you write a development plan from this document, treat the **Recommended build strategy** and **Planning constraints** sections as requirements, not suggestions.

---

## Direct answer

Foton is a coherent IR + configuration-drift toolkit with examiner-grade ethics (hashed package, coverage gaps disclosed, observations not verdicts). It is **not** overcomplicated for a five-layer product. It **is** below par if judged as KAPE + Hayabusa + Autoruns in one PowerShell binary.

The combination is uncommon:

- One-file PowerShell 5.1 live triage (no install, RMM-friendly)
- Deterministic field-level baseline **beyond** ASEP (Defender, RDP/WinRM, certs, firewall, listeners, LSA, BITS, hardening)
- Offline parse / analyze / report on a hashed package
- Findings that refuse to say “compromised”

Individual layers already have better specialists. **Improve by composing those tools, not cloning them.** A full Foton toolkit remains the right product idea: Foton owns the case, the known-good diff, and the report. Specialists own deep parse, Sigma EVTX hunting, exotic ASEP tabs, and raw-disk copies.

**PowerShell is the right language for Collect and Baseline capture.** It is the wrong language for gold-standard Prefetch/Amcache/EVTX/ESE/NTFS work. Industry already splits this way: script or dropper collect, C#/Rust parse.

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

First-time PowerShell at this size usually looks like one giant script that prints “malware detected.” Foton does not. Keep that charter.

---

## Verdict by worry

| Worry | Assessment |
|-------|------------|
| Best practices | Strong: flatten deploy, SHA-256, UTC, fail-into-manifest, identity keys, schema versions, standard-user honesty. |
| Missing collect | Live API/registry coverage is good. File-level forensic copies (full hives, USN, browser DBs) still thinner than KAPE / DFIR-ORC. |
| Baseline details | Above typical Autoruns-CSV diffs (Defender, RDP/WinRM, certs, firewall, listeners, LSA, BITS). ASEP tabs still not exhaustive (by design). |
| Automation / “is it compromised?” | Triage heuristics exist (Defender off, WDigest, IFEO, unsigned user-path processes, …). They must not decide compromise. **Unused potential:** rules that consume parsed Prefetch/Amcache/LNK and baseline diffs. |
| PowerShell-only | Correct for RMM/no-install collect. Incorrect as the only parser runtime. |
| Overcomplicated? | Charter is wide. File-per-provider is how you avoid a 3k-line script. Complexity matches intent. The trap is more parsers in PowerShell. |

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
| Raw artifact copies | Full hive copies, USN/`$LogFile`, browser DBs, more EVTX, optional MFT *listing* | Parse/carve and EZ Tools need **bytes**, not CSV summaries. | Collect more files (KAPE-style targets). Do not parse them in PS 5.1 on the endpoint. |
| Analyze automation | Heuristics are live-CSV triage; parsed Prefetch/Amcache/diff rows are barely consumed | Highest ROI without new collect. COVERAGE.md already says this. | Rules that read `analysis/parsed_records.csv` and `Compare-FotonBaseline` output. Still observations, not verdicts. |
| EVTX hunting | Capped selected IDs vs Sigma timelines | Wrong to rebuild Hayabusa in PowerShell. | Export EVTX; workstation Hayabusa/Chainsaw; ingest hits. |
| Parse correctness | MAM Prefetch, SRUM ESE, shellbags, Shimcache *entries*, legacy Amcache `File\*` | PowerShell is the wrong runtime. | Copy + EZ Tools (or documented “unsupported,” never guessed fields). |
| Operator packaging | Authenticode, analyze-without-clone zip, public-release lab ticks | This is what makes the tool feel “not ready,” not missing another Winlogon value. | Finish [TODO.md](TODO.md) public-release bar. |
| ASEP completeness | Codecs, gadgets, IE BHO marked low ROI; COM too noisy for baseline | Correct product call. | Use Autoruns when hunting those families. Do not add those providers “for completeness.” |

Collect P3 (memory, pcap, full MFT) and Carve-as-NTFS remain **wrong runtime** — point at WinPmem / KAPE / DFIR-ORC / a disk image. See [CARVE.md](CARVE.md).

---

## Recommended build strategy

### Compose (default for Parse / hunt / exotic ASEP)

Foton’s job on the **endpoint** is Collect + Baseline capture in PowerShell 5.1.

Foton’s job on the **workstation** is: open the package, run what PowerShell can do *correctly*, and **orchestrate better languages/tools** for the rest:

1. Hayabusa (or Chainsaw) on exported `.evtx` → timeline / Sigma hits → import as findings (cite the tool and rule).
2. EZ Tools on copied `.pf`, LNK, jumplists, Amcache, hives → structured records in the package (`analysis/`). Existing `ConvertFrom-Foton*` output already lands in `analysis/parsed_records.csv`.
3. Optional `autorunsc` when the question is “every Autoruns tab,” not “did *this* identity-keyed surface change.”
4. Optional KAPE/ORC *in addition to* Foton when the case needs MFT/USN/full hives Foton has not copied yet — until Collect grows those copies.

Existing `ConvertFrom-Foton*` parsers stay useful as **no-dependency** fallbacks (lab, air-gap, “good enough”). They are not the quality ceiling. Prefer “copied, parsed by EZ Tools” over a new incomplete PowerShell parser. Prefer “copied, not parsed” over a wrong ESE/NTFS implementation (already the SRUM rule).

### Finish (product, not novelty)

- Public-release bar in [TODO.md](TODO.md): Authenticode / ExecutionPolicy story, analyze zip that does not require cloning the repo, remaining lab ticks.
- Analyze rules that consume **parsed rows and baseline diffs**.
- Collect: more **raw files** that specialists need (hives, USN, browser DBs), still hashed, still fail-into-manifest.

### Stop (do not schedule)

Named in COVERAGE.md / TODO.md as low ROI or wrong runtime — keep that list:

- Full ESE SRUM parser in PowerShell
- NTFS unallocated carve in PowerShell
- MAM Prefetch inflate until a correct non-PS approach exists
- In-process Sigma engine
- CIS benchmark scorer / “risk score”
- TUI/GUI before the public-release bar is mostly green
- Codecs, gadgets, IE BHO baseline providers
- Domain-wide hunting, live VirusTotal, remediation

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
3. **Prioritize** (a) public-release bar, (b) analyze-on-parsed-and-diff, (c) more file copies for specialists, over exotic ASEP providers.
4. **Update** [COVERAGE.md](COVERAGE.md) when collect targets or “parsed by external tool” rows change; update [USAGE.md](USAGE.md) when operators gain a documented workstation pipeline; bump schemas only when on-disk columns or baseline records change.
5. **Stay honest.** Findings remain observations. External-tool hits are Tier 2 unless they are raw facts (hash match, Event ID present). Name the tool in Artifact / WhyItMatters.
6. **Do not** expand charter into EDR, memory imaging, CIS scoring, or fleet C2.

---

## Bottom line

Specialists will beat each layer. The product job is to be the **hashed case** and the **known-good config diff** those specialists feed — and to automate first-pass observations without lying.

Foton should remain a full toolkit. PowerShell collects. Better languages and existing tools analyze and parse. Follow their example instead of reinventing their engines.
