using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Baseline.Compare;
using Foton.Core;
using static Foton.Analyze.Ps;

namespace Foton.Analyze.Rules
{
    /// <summary>
    /// Workstation outputs written into analysis\ after collection: parsed_records.csv, baseline_diff.csv, and the
    /// Hayabusa / PECmd / EvtxECmd compose CSVs. Thin ingest only: name the tool, never re-parse or re-hunt.
    /// </summary>
    static class OfflineInputRules
    {
        /// <summary>
        /// Top-N "key (count)" by count, highest first. Ties fall back to key order (1.38.x left them in hashtable
        /// order, which is not reproducible), so the same input always gives the same text.
        /// </summary>
        static IEnumerable<KeyValuePair<string, int>> Top(Dictionary<string, int> counts, int n) =>
            counts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).Take(n);

        static string TopText(Dictionary<string, int> counts, int n, string format = "{0} ({1})") =>
            string.Join("; ", Top(counts, n).Select(kv => F(format, kv.Key, kv.Value)));

        static void Bump(Dictionary<string, int> d, string key) => d[key] = d.TryGetValue(key, out var v) ? v + 1 : 1;

        static List<Dictionary<string, string?>>? ReadCsv(string path)
        {
            try { return Csv.Read(path); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException) { return null; }
        }

        static string V(Dictionary<string, string?> row, string name)
        {
            foreach (var kv in row) if (string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)) return kv.Value ?? "";
            return "";
        }

        public static void Run(AnalysisContext c, Dictionary<string, object?> svcIndex, string hostSys32)
        {
            var root = c.CaseRoot;
            if (root == null || !Directory.Exists(root)) return;
            ParsedRecords(c, root);
            BaselineDiff(c, root);
            Hayabusa(c, root);
            PeCmd(c, root);
            EvtxECmd(c, root, svcIndex, hostSys32);
            ReCmd(c, root);
        }

        static void ParsedRecords(AnalysisContext c, string root)
        {
            var path = Path.Combine(root, "analysis", "parsed_records.csv");
            if (!File.Exists(path)) return;
            var rows = ReadCsv(path);
            if (rows == null) return;
            var hits = new List<string>();
            foreach (var r in rows)
            {
                var p = V(r, "LocalBasePath");
                if (p.Length == 0) p = V(r, "Path");
                if (p.Length == 0) p = V(r, "LowerCaseLongPath");
                if (p.Length == 0) p = V(r, "Identity");
                if (p.Length == 0) continue;
                if (c.UserWritablePath(p) && !hits.Contains(p, StringComparer.Ordinal)) hits.Add(p);
            }
            if (hits.Count > 0)
                c.Add("Medium", "Execution", 2, "Parsed artifacts reference user-writable paths",
                    F("analysis/parsed_records.csv contains {0} distinct path(s) under user-writable locations. Sample: {1}", hits.Count, string.Join("; ", hits.Take(8))),
                    "Prefetch/LNK/Amcache rows are observations about files that were referenced. A user-writable path is a review item (updater, user binary, or unexpected drop). This is not a verdict of compromise.",
                    "analysis/parsed_records.csv",
                    "Open the parsed row, hash the file if it is still in the package, and compare to software inventory / baseline diffs.");
        }

        static readonly string[] PersistenceTypes = { "Service", "Autorun", "UserAutorun", "ScheduledTask", "Winlogon", "AppInitDll", "ImageFileExecution", "StartupFile", "StartupApproved", "WmiPermanentEvent", "BitsJob", "CmdAutoRun", "SessionManager", "KnownDll", "WinsockLsp", "ActiveSetup", "SilentProcessExit", "NetshHelper", "PrintMonitor", "LsaPackage", "Driver" };
        static readonly string[] UserTypes = { "LocalGroupMember", "LocalAccount", "Certificate" };
        static readonly string[] SecurityTypes = { "DefenderPreference", "HardeningRegistry", "RemoteAccessConfig", "WdacApplockerPolicy", "HostsEntry", "NetworkShare", "SystemBinary", "MachineEnvironment" };

        static void BaselineDiff(AnalysisContext c, string root)
        {
            var path = Path.Combine(root, "analysis", "baseline_diff.csv");
            if (!File.Exists(path)) return;
            var rows = ReadCsv(path);
            if (rows == null) return;
            // Lift High-attention surfaces only, grouped so one finding covers many identities of the same kind.
            var groups = new Dictionary<string, List<Dictionary<string, string?>>>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in rows.Where(r => V(r, "RecordType").Length > 0))
            {
                var change = new BaselineChange
                {
                    RecordType = V(d, "RecordType"), Identity = V(d, "Identity"), ChangeType = V(d, "ChangeType"),
                    Field = V(d, "Field"), OldValue = V(d, "OldValue"), NewValue = V(d, "NewValue"),
                };
                if (ChangeSeverity.Of(change) != "High") continue;
                string key;
                if (Eq(change.RecordType, "Service") && (Eq(change.ChangeType, "Added") || Eq(change.Field, "PathName"))) key = "Service|PathOrAdded";
                else if (Eq(change.RecordType, "LocalGroupMember") && Eq(change.ChangeType, "Added") && Like(change.Identity, "Administrators|*")) key = "LocalGroupMember|AdministratorsAdded";
                else if (Eq(change.RecordType, "DefenderPreference") && Like(change.Identity, "*DisableRealtimeMonitoring*")) key = "DefenderPreference|DisableRealtimeMonitoring";
                else key = $"{change.RecordType}|{change.ChangeType}|{change.Field}";
                if (!groups.TryGetValue(key, out var list)) groups[key] = list = new List<Dictionary<string, string?>>();
                list.Add(d);
            }
            foreach (var key in groups.Keys.OrderBy(k => k, StringComparer.InvariantCultureIgnoreCase))
            {
                var g = groups[key];
                var rt = V(g[0], "RecordType");
                var ct = V(g[0], "ChangeType");
                var fld = V(g[0], "Field");
                var ids = string.Join("; ", g.Select(r => V(r, "Identity")).Distinct(StringComparer.Ordinal).Take(8));
                string title;
                if (key == "Service|PathOrAdded") title = "Baseline diff: service ImagePath or new service";
                else if (key == "LocalGroupMember|AdministratorsAdded") title = "Baseline diff: Administrators membership added";
                else if (key == "DefenderPreference|DisableRealtimeMonitoring") title = "Baseline diff: Defender real-time monitoring setting changed";
                else title = fld.Length > 0 ? F("Baseline diff: {0} {1}.{2}", ct, rt, fld) : F("Baseline diff: {0} {1}", ct, rt);
                var fp = BaselineFalsePositives.Of(rt);
                var why = "A baseline_diff.csv High-attention row is a stable-config fact between two snapshots. It does not establish who changed it or that the host is compromised.";
                if (fp.Length > 0) why += F(" Common benign sources for {0}: {1}", rt, fp);
                var cat = In(rt, PersistenceTypes) ? "Persistence" : In(rt, UserTypes) ? "Users" : In(rt, SecurityTypes) ? "Security" : "Baseline";
                c.Add("High", cat, 1, title,
                    F("Compare-FotonBaseline records show {0} High-attention {1} change(s) ({2}{3}). Identities: {4}", g.Count, rt, ct, fld.Length > 0 ? "/" + fld : "", ids),
                    why, "analysis/baseline_diff.csv",
                    "Open baseline_diff.csv for OldValue/NewValue, confirm against change control or the role golden image, and corroborate with Collect persistence CSVs when a triage package is available.");
            }
        }

        static readonly Regex HayabusaHead = new Regex("^\"(?<ts>[^\"]*)\",\"(?<t>[^\"]*)\",\"(?<l>[^\"]*)\"");

        static void Hayabusa(AnalysisContext c, string root)
        {
            var dir = Path.Combine(root, "analysis", "external", "hayabusa");
            if (!Directory.Exists(dir)) return;
            // A timeline is routinely hundreds of MB: stream it and read only Timestamp, RuleTitle, Level (the first
            // three fields, ahead of the free-text Details). Rows the collector caused (script block logging records
            // Foton's own PowerShell) are counted apart: inside the collection window, or naming a Foton function.
            var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var titles = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);
            var selfCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var selfTitles = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);
            int selfTotal = 0, selfByWindow = 0, selfByName = 0, read = 0;
            const int maxLines = 2000000;
            bool capped = false;
            var window = CollectionWindow.FromCase(root);
            foreach (var file in SafeFiles(dir, "*.csv"))
            {
                try
                {
                    using (var reader = new StreamReader(file))
                    {
                        reader.ReadLine();
                        for (var line = reader.ReadLine(); line != null; line = reader.ReadLine())
                        {
                            if (++read > maxLines) { capped = true; break; }
                            var m = HayabusaHead.Match(line);
                            if (!m.Success) continue;
                            var lvl = m.Groups["l"].Value.ToLowerInvariant();
                            var ttl = m.Groups["t"].Value;
                            bool self = false, byWindow = false;
                            if (window != null && DateTimeOffset.TryParse(m.Groups["ts"].Value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var ts)
                                && window.Contains(ts.UtcDateTime))
                                self = byWindow = true;
                            if (!self && EventLogRules.NamesCollector(line)) self = true;
                            var cnt = self ? selfCounts : counts;
                            var ttls = self ? selfTitles : titles;
                            if (self) { selfTotal++; if (byWindow) selfByWindow++; else selfByName++; }
                            Bump(cnt, lvl);
                            if (!ttls.TryGetValue(lvl, out var t)) ttls[lvl] = t = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                            Bump(t, ttl);
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                if (capped) break;
            }

            string Describe(Dictionary<string, Dictionary<string, int>> map, string level) =>
                map.TryGetValue(level, out var t) ? TopText(t, 6) : "";
            var capNote = capped ? F(" Row scan capped at {0} lines; counts are a floor, not a total.", maxLines) : "";
            var selfNote = selfTotal > 0 ? F(" Excludes {0} row(s) attributable to the Foton collector itself; see the collector-footprint finding.", selfTotal) : "";

            // Hayabusa abbreviates levels in CSV output ("med", "crit"); accept both spellings.
            var bands = new[]
            {
                new { Levels = new[] { "emergency", "emer", "critical", "crit" }, Severity = "High", Label = "critical-level" },
                new { Levels = new[] { "high" }, Severity = "High", Label = "high-level" },
                new { Levels = new[] { "medium", "med" }, Severity = "Medium", Label = "medium-level" },
            };
            foreach (var band in bands)
            {
                int total = 0;
                var samples = new List<string>();
                foreach (var l in band.Levels)
                {
                    if (!counts.TryGetValue(l, out var n)) continue;
                    total += n;
                    var d = Describe(titles, l);
                    if (d.Length > 0) samples.Add(d);
                }
                if (total <= 0) continue;
                c.Add(band.Severity, "EventLogs", 2, F("Hayabusa reported {0} rule hits on copied EVTX", band.Label),
                    F("{0} {1} detection(s) in analysis/external/hayabusa. Top rules: {2}.{3}{4}", total, band.Label, string.Join("; ", samples), capNote, selfNote),
                    "These are Hayabusa/Sigma rule hits, not a Foton engine and not a verdict. Sigma rules fire on legitimate administration, backup software, and management agents, and a Foton collection can itself trigger hive-access and script-execution rules. Judge each rule against what was expected on this host.",
                    "analysis/external/hayabusa",
                    "Filter the Hayabusa CSV to these RuleTitle values, note the RuleID and Timestamp, and corroborate against process, persistence, and account artifacts before drawing any conclusion.");
            }

            int lowVol = new[] { "low", "info", "informational" }.Sum(l => counts.TryGetValue(l, out var n) ? n : 0);
            if (lowVol > 0)
                c.Add("Info", "EventLogs", 1, "Hayabusa low and informational event volume",
                    F("{0} low/informational Hayabusa row(s) recorded. These are mostly normal telemetry (process execution, DNS queries, file creation) and are context for a timeline, not indicators.{1}{2}", lowVol, capNote, selfNote),
                    "Volume here reflects how much Sysmon/audit telemetry the host was producing. It is useful for timeline coverage and for spotting where telemetry stops.",
                    "analysis/external/hayabusa",
                    "Use these rows to bound the observable window rather than as suspicion.");

            if (selfTotal > 0)
            {
                var selfSamples = selfCounts.Keys.OrderBy(k => k, StringComparer.InvariantCultureIgnoreCase)
                    .Select(l => new { l, d = Describe(selfTitles, l) }).Where(x => x.d.Length > 0).Select(x => F("{0}: {1}", x.l, x.d));
                var winText = window != null
                    ? F("collection window {0} to {1} UTC", FotonTime.Format(window.StartUtc), FotonTime.Format(window.EndUtc))
                    : @"no collection window could be read from 00_Collection\collection.log";
                c.Add("Info", "Methodology", 2, "Hayabusa hits caused by the Foton collection itself",
                    F("{0} Hayabusa row(s) are attributed to the collection and excluded from the severity bands above: {1} fell inside the {2}, and {3} named the Foton collector outside it. By level - {4}.",
                        selfTotal, selfByWindow, winText, selfByName, string.Join(" | ", selfSamples)),
                    "The collector's own activity is logged like any other: script blocks of the 1.38.x PowerShell collector, and process creation for foton-collect.exe and the System32 tools it starts (reg, wevtutil, auditpol, secedit, and others). Sigma rules for suspicious scripting, registry export, and credential or policy access fire on that footprint. Left in the counts, that footprint is reported as host activity and can dominate a severity band. Attribution is inference, not process identity: rows are matched by time and by name, so genuine host activity that happened during the collection window is excluded here too, and an earlier Foton run on this host is included.",
                    "analysis/external/hayabusa",
                    "If a real event could have coincided with the collection, filter the Hayabusa CSV to that window and read the Details column directly rather than relying on this exclusion.");
            }
        }

        // DFIRBatch categories whose values name code that runs (persistence and hunting surfaces). "Program Execution"
        // is left out: UserAssist/BAM rows for per-user installs under AppData are mostly benign and PECmd covers execution.
        static readonly string[] RecmdPathCategories = { "Autoruns", "Services", "Threat Hunting" };

        /// <summary>
        /// RECmd batch CSV (recmd.csv at the top of analysis\external\RECmd; plugin detail files sit in a subfolder):
        /// HivePath, HiveType, Description, Category, KeyPath, ValueName, ValueType, ValueData, ValueData2, ValueData3,
        /// Comment, Recursive, Deleted, LastWriteTimestamp, PluginDetailFile. RECmd reads the copied hives, including
        /// users whose hives were not loaded at collection time, so this can see what Collect's live reads could not.
        /// </summary>
        static void ReCmd(AnalysisContext c, string root)
        {
            var dir = Path.Combine(root, "analysis", "external", "RECmd");
            if (!Directory.Exists(dir)) return;
            const int max = 200000;
            int rows = 0;
            bool capped = false;
            var categories = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var hiveTypes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var hunting = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var deleted = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            int deletedRows = 0;
            var writable = new List<string>();
            foreach (var file in SafeFiles(dir, "*.csv"))
            {
                var data = ReadCsv(file);
                if (data == null || data.Count == 0 || !data[0].Keys.Any(k => string.Equals(k, "HivePath", StringComparison.OrdinalIgnoreCase))) continue;
                foreach (var row in data)
                {
                    if (++rows > max) { capped = true; break; }
                    var category = V(row, "Category");
                    var description = V(row, "Description");
                    if (category.Length > 0) Bump(categories, category);
                    if (V(row, "HiveType").Length > 0) Bump(hiveTypes, V(row, "HiveType"));
                    if (string.Equals(category, "Threat Hunting", StringComparison.OrdinalIgnoreCase) && description.Length > 0) Bump(hunting, description);
                    if (string.Equals(V(row, "Deleted"), "True", StringComparison.OrdinalIgnoreCase))
                    {
                        deletedRows++;
                        Bump(deleted, description.Length > 0 ? description : category);
                    }
                    if (!RecmdPathCategories.Contains(category, StringComparer.OrdinalIgnoreCase)) continue;
                    // ValueName too: some entries (Defender exclusion paths) carry the path as the value's name.
                    foreach (var data1 in new[] { V(row, "ValueName"), V(row, "ValueData"), V(row, "ValueData2"), V(row, "ValueData3") })
                        foreach (Match m in EmbeddedPath.Matches(data1))
                        {
                            var p = m.Value.TrimEnd(',', ';', ')');
                            if (c.UserWritablePath(p) && !writable.Contains(p, StringComparer.OrdinalIgnoreCase)) writable.Add(p);
                        }
                }
                if (capped) break;
            }
            if (rows == 0) return;
            const string art = "analysis/external/RECmd";
            c.Add("Info", "Persistence", 1, "RECmd batch rows present in compose output",
                F("RECmd wrote {0} row(s) under analysis/external/RECmd from hive types {1}. Top categories: {2}.{3}{4}", rows, TopText(hiveTypes, 6), TopText(categories, 8),
                    hunting.Count > 0 ? F(" Threat Hunting entries: {0}.", TopText(hunting, 8)) : "",
                    capped ? F(" Row scan capped at {0}; counts are a floor.", max) : ""),
                "These are Eric Zimmerman RECmd batch results over the registry hives copied into the package, including users whose hives were not loaded when Collect ran. A batch entry is a place worth reading, not a verdict: most rows describe ordinary configuration.",
                art,
                "Open recmd.csv, filter by Category (Autoruns, Threat Hunting, Program Execution), and corroborate entries against Collect's persistence tables and baseline diffs.");
            if (writable.Count > 0)
                c.Add("Medium", "Persistence", 2, "RECmd persistence entries reference user-writable paths",
                    F("RECmd Autoruns/Services/Threat Hunting values name {0} distinct path(s) under user-writable locations. Sample: {1}", writable.Count, string.Join("; ", writable.Take(8))),
                    "Code that starts from a user-writable location is a common persistence pattern, and so are per-user installers and updaters (Teams, OneDrive, browser updaters). RECmd reported the registry value; this finding does not establish that the file is malicious.",
                    art,
                    "Hash the file if it is in the package, check its signature, and compare against software inventory and a baseline from provisioning.");
            if (deletedRows > 0)
                c.Add("Info", "Persistence", 1, "RECmd recovered deleted registry keys or values",
                    F("RECmd marked {0} row(s) as deleted (recovered from free space in the copied hives). Top entries: {1}.", deletedRows, TopText(deleted, 8)),
                    "Deleted keys and values are routine after uninstalls and updates, and are also what cleanup of persistence leaves behind. Hives exported with reg save are compacted and carry little free space, so absence here is not evidence that nothing was deleted.",
                    art,
                    "Read the deleted rows' KeyPath and LastWriteTimestamp, and place them on the timeline next to installs and service changes.");
        }

        static IEnumerable<string> SafeFiles(string dir, string pattern)
        {
            try { return Directory.GetFiles(dir, pattern).OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList(); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return new string[0]; }
        }

        static readonly Regex PieceSplit = new Regex(@"[,;\r\n]+");

        static void PeCmd(AnalysisContext c, string root)
        {
            var dir = Path.Combine(root, "analysis", "external", "PECmd");
            if (!Directory.Exists(dir)) return;
            int rows = 0;
            const int max = 200000;
            bool capped = false;
            var names = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var writable = new List<string>();
            foreach (var file in SafeFiles(dir, "*.csv"))
            {
                // Timeline CSV is one row per run; the main CSV carries FilesLoaded / Directories.
                var data = ReadCsv(file);
                if (data == null) continue;
                foreach (var row in data)
                {
                    if (++rows > max) { capped = true; break; }
                    var exe = V(row, "ExecutableName");
                    if (exe.Length > 0) Bump(names, exe);
                    var blobs = new List<string> { V(row, "FilesLoaded"), V(row, "Directories"), V(row, "SourceFilename") };
                    if (exe.Length > 0 && exe.IndexOf('\\') >= 0) blobs.Add(exe);
                    foreach (var blob in blobs.Where(b => b.Length > 0))
                        foreach (var piece in PieceSplit.Split(blob))
                        {
                            var p = piece.Trim().Trim('"');
                            if (p.Length == 0 || p.IndexOf('\\') < 0) continue;
                            if (c.UserWritablePath(p) && !writable.Contains(p, StringComparer.OrdinalIgnoreCase)) writable.Add(p);
                        }
                }
                if (capped) break;
            }
            if (rows > 0)
                c.Add("Info", "Execution", 1, "PECmd Prefetch rows present in compose output",
                    F("PECmd wrote {0} Prefetch row(s) under analysis/external/PECmd. Top ExecutableName values: {1}.{2}", rows, TopText(names, 8),
                        capped ? F(" Row scan capped at {0}; counts are a floor.", max) : ""),
                    "These are Eric Zimmerman PECmd facts about Prefetch already copied into the package, not a Foton-native Prefetch parse and not a verdict. Prefetch is often disabled on servers and is incomplete for short-lived processes.",
                    "analysis/external/PECmd",
                    "Open pecmd.csv for RunCount/LastRun and corroborate interesting executables against process, persistence, and software inventory.");
            if (writable.Count > 0)
                c.Add("Medium", "Execution", 2, "PECmd Prefetch references user-writable paths",
                    F("PECmd FilesLoaded/Directories (and path-like ExecutableName) include {0} distinct user-writable path(s). Sample: {1}", writable.Count, string.Join("; ", writable.Take(8))),
                    "A Prefetch-referenced path under a user-writable location is a review item (updater, user binary, or unexpected drop). PECmd reported the reference; this finding does not establish that the file is malicious.",
                    "analysis/external/PECmd",
                    "Hash the path if the bytes are still in the package and compare to software inventory / baseline diffs.");
        }

        static readonly Regex EmbeddedPath = new Regex(@"(?i)[A-Za-z]:\\[^\s\|""]+");
        static readonly string[] CommandEventIds = { "4688", "1", "4104", "4697", "7045", "4698", "4702" };

        static void EvtxECmd(AnalysisContext c, string root, Dictionary<string, object?> svcIndex, string hostSys32)
        {
            var dir = Path.Combine(root, "analysis", "external", "EvtxECmd");
            if (!Directory.Exists(dir)) return;
            var attention = new Dictionary<string, KeyValuePair<string, string>>
            {
                ["1102"] = new KeyValuePair<string, string>("High", "Security audit log cleared"),
                ["104"] = new KeyValuePair<string, string>("High", "Event log cleared"),
                ["4697"] = new KeyValuePair<string, string>("Medium", "Service installed (Security 4697)"),
                ["7045"] = new KeyValuePair<string, string>("Medium", "Service installed (System 7045)"),
                ["4698"] = new KeyValuePair<string, string>("Medium", "Scheduled task created"),
            };
            int rows = 0, perUserSkipped = 0, self = 0;
            const int max = 2000000;
            bool capped = false;
            var ids = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var attCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var attNames = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            var writable = new List<string>();
            var susp = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            // The collector's own process creation and script blocks land in these logs too: rows inside the
            // collection window are excluded from the path and pattern counts and reported separately.
            var window = CollectionWindow.FromCase(root);
            var winStart = window != null ? FotonTime.Format(window.StartUtc) : null;
            var winEnd = window != null ? FotonTime.Format(window.EndUtc) : null;
            foreach (var file in SafeFiles(dir, "*.csv"))
            {
                if (capped) break;
                var data = ReadCsv(file);
                if (data == null) continue;
                foreach (var raw in data)
                {
                    if (++rows > max) { capped = true; rows = max; break; }
                    var row = PackageData.CsvRow(raw);
                    string? eid = V(raw, "EventId");
                    if (eid.Length > 0)
                    {
                        Bump(ids, eid);
                        if (attention.ContainsKey(eid))
                        {
                            var svcName = "";
                            if (eid == "4697" || eid == "7045")
                            {
                                svcName = EventHelpers.ServiceName(row);
                                if (EventHelpers.PerUserServiceEvent(row, svcIndex, hostSys32)) { perUserSkipped++; eid = null; }
                            }
                            if (eid != null)
                            {
                                Bump(attCounts, eid);
                                if (!attNames.TryGetValue(eid, out var set)) attNames[eid] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                if (svcName.Length > 0) set.Add(svcName);
                            }
                        }
                    }
                    var execInfo = V(raw, "ExecutableInfo");
                    if (execInfo.Length == 0) continue;
                    var ts = V(raw, "TimeCreated");
                    if (winStart != null && ts.Length >= 19)
                    {
                        var t19 = ts.Substring(0, 19);
                        if (string.CompareOrdinal(t19, winStart) >= 0 && string.CompareOrdinal(t19, winEnd) <= 0) { self++; continue; }
                    }
                    if (c.UserWritablePath(execInfo)) { if (!writable.Contains(execInfo, StringComparer.OrdinalIgnoreCase)) writable.Add(execInfo); }
                    else
                        foreach (Match m in EmbeddedPath.Matches(execInfo))
                            if (c.UserWritablePath(m.Value) && !writable.Contains(m.Value, StringComparer.OrdinalIgnoreCase)) writable.Add(m.Value);
                    if (In(V(raw, "EventId"), CommandEventIds))
                    {
                        var hit = c.SuspiciousCommand(execInfo);
                        if (hit != null) Bump(susp, hit);
                    }
                }
            }
            if (rows > 0)
                c.Add("Info", "EventLogs", 1, "EvtxECmd event rows present in compose output",
                    F("EvtxECmd wrote {0} event row(s) under analysis/external/EvtxECmd. Top EventId values: {1}.{2}", rows, TopText(ids, 8, "EventId {0} ({1})"),
                        capped ? F(" Row scan capped at {0}; counts are a floor.", max) : ""),
                    "These are Eric Zimmerman EvtxECmd facts about EVTX already copied into the package. Volume reflects which channels were collected and how noisy they were - not a compromise score.",
                    "analysis/external/EvtxECmd",
                    "Filter evtxecmd.csv by EventId and Channel for the investigation window; use Hayabusa/Chainsaw compose for Sigma-style hunts.");
            foreach (var eid in attCounts.Keys.OrderBy(k => k, StringComparer.InvariantCultureIgnoreCase))
            {
                var meta = attention[eid];
                var svcNames = attNames[eid].OrderBy(n => n, StringComparer.InvariantCultureIgnoreCase).ToList();
                var extra = svcNames.Count > 0 ? F(" Services: {0}.", string.Join("; ", svcNames.Take(12))) : "";
                if ((eid == "4697" || eid == "7045") && perUserSkipped > 0)
                    extra += F(" Excludes {0} per-user service instance(s) of known Windows templates (OneSyncSvc_<hex> and similar) hosted by System32 svchost.exe, which Windows creates at every logon. The event does not record ServiceDll; it was checked in services.csv for instances that still existed at collection time, and instances removed at logoff could not be checked.", perUserSkipped);
                c.Add(meta.Key, "EventLogs", 1, F("EvtxECmd: {0}", meta.Value),
                    F("EvtxECmd reported {0} EventId {1} row(s) in analysis/external/EvtxECmd.{2}", attCounts[eid], eid, extra),
                    "This EventId is a high-attention audit fact when present. Benign administrators, installers, and management agents also clear logs, install services, and create tasks. EvtxECmd reported the row; this is not attribution.",
                    "analysis/external/EvtxECmd",
                    F("Open the EvtxECmd CSV filtered to EventId {0}, note TimeCreated/UserName/ExecutableInfo, and corroborate against persistence and account artifacts.", eid));
            }
            if (writable.Count > 0)
                c.Add("Medium", "Execution", 2, "EvtxECmd ExecutableInfo references user-writable paths",
                    F("EvtxECmd ExecutableInfo fields include {0} distinct user-writable path(s). Sample: {1}", writable.Count, string.Join("; ", writable.Take(8))),
                    "Mapped ExecutableInfo often carries process paths, service ImagePath, or task actions. A user-writable location is a review item, not proof of compromise.",
                    "analysis/external/EvtxECmd",
                    "Corroborate the path against Prefetch/PECmd, persistence CSVs, and software inventory.");
            if (susp.Count > 0)
                c.Add("Medium", "Execution", 2, "EvtxECmd ExecutableInfo matched suspicious-command patterns",
                    F("EvtxECmd command text (process creation, script block, service, and task events) matched {0} distinct suspicious-command pattern(s). Sample: {1}", susp.Count, TopText(susp, 6)),
                    "These are the same workstation pattern matches used on collected process rows, applied to EvtxECmd-mapped command text. Admin scripts and installers often match. Not a verdict.",
                    "analysis/external/EvtxECmd",
                    "Read the matching EvtxECmd rows in full and corroborate against process creation and persistence artifacts.");
            if (self > 0)
                c.Add("Info", "Methodology", 2, "EvtxECmd rows inside the collection window were excluded",
                    F("{0} EvtxECmd row(s) with ExecutableInfo fell inside the collection window ({1} to {2} UTC) and were excluded from the user-writable path and suspicious-command counts above.", self, winStart, winEnd),
                    "The collector's own processes and script blocks are logged like any other activity, and its output folder is usually user-writable. Attribution is by time only, so genuine host activity during the collection minutes is excluded too.",
                    "analysis/external/EvtxECmd",
                    "If something could have coincided with the collection, filter evtxecmd.csv to that window and read the rows directly.");
        }
    }
}
