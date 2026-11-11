using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Core;
using Foton.Package;

namespace Foton.Parse
{
    public sealed class ParseRun
    {
        public List<ParseRecord> Records { get; } = new List<ParseRecord>();
        public List<ParsedRow> Rows { get; } = new List<ParsedRow>();
        public string? CsvPath { get; internal set; }
        public string? HtmlPath { get; internal set; }
        /// <summary>Why nothing was parsed (a visibility gap, not a clean host); null when rows exist.</summary>
        public string? EmptyReason { get; internal set; }
    }

    /// <summary>
    /// Runs every parser over a package (folder or ZIP) or one file (Invoke-FotonParse). Offline: reads only
    /// copied bytes. A package run writes analysis\parsed_records.csv and analysis\Foton_Parse.html (a ZIP's in its
    /// extraction beside it). Never writes findings or touches the collect hashes.
    /// </summary>
    public static class ParseRunner
    {
        public static ParseRun Run(string path, StatusLog log)
        {
            var full = Path.GetFullPath(path);
            if (File.Exists(full) && !full.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                var single = new ParseRun();
                log.Write("Parsing 1 Prefetch/LNK/jumplist/EVTX/Amcache file(s) (offline)", StatusLevel.Step);
                single.Records.AddRange(ParseFile(full, log));
                foreach (var r in single.Records) single.Rows.Add(ToRow(r, null));
                Summarize(single, log);
                return single;
            }
            if (!File.Exists(full) && !Directory.Exists(full)) throw new FileNotFoundException("Parse path not found: " + path, path);

            var pkg = FotonPackage.Open(full);
            if (pkg.ZipNote != null) log.Write(pkg.ZipNote, StatusLevel.Info);
            return RunPackage(pkg, log);
        }

        static ParseRun RunPackage(FotonPackage pkg, StatusLog log)
        {
            var run = new ParseRun();
            var files = Candidates(pkg.CaseRoot, pkg.NestedDuplicate).ToList();
            log.Write($"Parsing {files.Count} Prefetch/LNK/jumplist/EVTX/Amcache file(s) (offline)", StatusLevel.Step);
            foreach (var f in files) run.Records.AddRange(ParseFile(f, log));
            foreach (var r in run.Records) run.Rows.Add(ToRow(r, pkg.CaseRoot));
            if (run.Records.Count == 0) run.EmptyReason = EmptyReason(pkg);
            Summarize(run, log);

            var host = Hostname(pkg);
            var analysis = Path.Combine(pkg.CaseRoot, "analysis");
            Directory.CreateDirectory(analysis);
            run.CsvPath = Path.Combine(analysis, "parsed_records.csv");
            run.HtmlPath = Path.Combine(analysis, ParseReport.FileName);
            Csv.Write(run.CsvPath, run.Rows);
            log.Write("Wrote " + run.CsvPath, StatusLevel.Good);
            ParseReport.Write(run.Rows, run.HtmlPath, host, run.EmptyReason);
            log.Write("Parse report: " + run.HtmlPath, StatusLevel.Good);
            log.Write($"Open {run.HtmlPath} (this is not findings.csv; that file is triage Analyze)", StatusLevel.Good);
            return run;
        }

        /// <summary>
        /// Parser inputs under the case root, in Get-ChildItem -Recurse order (a folder's files, then each
        /// subfolder), skipping hidden items, analysis\ output, and a nested copy of the package itself.
        /// </summary>
        internal static IEnumerable<string> Candidates(string caseRoot, string? nestedDuplicate)
        {
            var pending = new Stack<string>();
            pending.Push(caseRoot);
            while (pending.Count > 0)
            {
                var dir = pending.Pop();
                if (nestedDuplicate != null && CaseTree.IsUnder(dir, nestedDuplicate)) continue;
                if (!string.Equals(dir, caseRoot, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(Path.GetFileName(dir), "analysis", StringComparison.OrdinalIgnoreCase)) continue;
                string[] files, dirs;
                try { files = Directory.GetFiles(dir); dirs = Directory.GetDirectories(dir); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { continue; }
                foreach (var f in files)
                    if (!Hidden(f) && IsParserInput(f)) yield return f;
                // A junction or directory symlink inside a package could point outside the evidence folder.
                for (int i = dirs.Length - 1; i >= 0; i--)
                    if (!Hidden(dirs[i]) && !Reparse(dirs[i])) pending.Push(dirs[i]);
            }
        }

        static bool Hidden(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.Hidden) != 0; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return true; }
        }

        static bool Reparse(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return true; }
        }

        static bool IsParserInput(string f)
        {
            var name = Path.GetFileName(f);
            var ext = Path.GetExtension(f);
            return Ext(ext, ".pf") || Ext(ext, ".lnk") || Ext(ext, ".evtx")
                || name.EndsWith(".automaticDestinations-ms", StringComparison.OrdinalIgnoreCase)
                || name.EndsWith(".customDestinations-ms", StringComparison.OrdinalIgnoreCase)
                || string.Equals(name, "Amcache.hve", StringComparison.OrdinalIgnoreCase)
                || (Ext(ext, ".hve") && string.Equals(Path.GetFileName(Path.GetDirectoryName(f)), "amcache", StringComparison.OrdinalIgnoreCase));
        }

        static bool Ext(string ext, string want) => string.Equals(ext, want, StringComparison.OrdinalIgnoreCase);

        /// <summary>One file through its parser. A file that cannot be read becomes a row, never an aborted run.</summary>
        internal static List<ParseRecord> ParseFile(string f, StatusLog log)
        {
            var name = Path.GetFileName(f);
            var ext = Path.GetExtension(f);
            try
            {
                if (Ext(ext, ".pf")) return new List<ParseRecord> { PrefetchParser.Parse(f) };
                if (Ext(ext, ".lnk")) return new List<ParseRecord> { LnkParser.Parse(f) };
                if (Ext(ext, ".evtx")) return EvtxParser.Parse(f);
                if (name.EndsWith(".automaticDestinations-ms", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".customDestinations-ms", StringComparison.OrdinalIgnoreCase))
                    return JumplistParser.Parse(f);
                if (Ext(ext, ".hve")) return AmcacheParser.Parse(f);
                log.Write("Skipped (not .pf/.lnk/.evtx): " + name, StatusLevel.Info);
                return new List<ParseRecord>();
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return Failed(f, "Unsupported-ReadError", "File could not be read: " + TextFile.OneLine(ex.Message) + ". Nothing was guessed.");
            }
            catch (Exception ex)
            {
                // Parsers fail closed on malformed bytes; anything they did not anticipate stays one file's problem.
                return Failed(f, "Unsupported-ParseError", "Parser stopped on malformed content: " + TextFile.OneLine(ex.GetType().Name + ": " + ex.Message) + ". Nothing was guessed.");
            }
        }

        static List<ParseRecord> Failed(string f, string format, string note)
        {
            long size = 0;
            try { size = new FileInfo(f).Length; } catch (Exception e2) when (e2 is IOException || e2 is UnauthorizedAccessException) { }
            return new List<ParseRecord>
            {
                new ParseRecord { SourcePath = Path.GetFullPath(f), SizeBytes = size, SHA256 = Bin.Sha256(f), Format = format, Note = note },
            };
        }

        static ParsedRow ToRow(ParseRecord r, string? caseRoot)
        {
            var src = r.SourcePath;
            if (caseRoot != null)
            {
                var root = caseRoot.TrimEnd('\\', '/');
                if (src.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase)) src = src.Substring(root.Length).TrimStart('\\', '/');
            }
            return new ParsedRow { SourcePath = src, Format = r.Format, Supported = r.Supported, Identity = r.Identity, SizeBytes = r.SizeBytes, SHA256 = r.SHA256, Note = r.Note };
        }

        static void Summarize(ParseRun run, StatusLog log)
        {
            if (run.Records.Count == 0)
            {
                if (run.EmptyReason != null) log.Write(run.EmptyReason, StatusLevel.Info);
                return;
            }
            int supported = run.Records.Count(r => r.Supported);
            int mam = run.Records.Count(r => r.Format == "MAM-compressed");
            int ev = run.Records.Count(r => r.Format == "EVTX" && r.Supported);
            log.Write($"Parsed {run.Records.Count} row(s): {supported} supported name(s), {mam} MAM-compressed, {ev} EVTX row(s)", StatusLevel.Good);
        }

        static string EmptyReason(FotonPackage pkg)
        {
            var pf = pkg.Manifest.FirstOrDefault(m => m.TryGetValue("Task", out var t) && t == "prefetch_files");
            var status = pf != null && pf.TryGetValue("Status", out var s) ? s : null;
            if (status == "NotSelected")
                return "prefetch_files was not selected by this collection's profile, so the package has no copied .pf files. Collect again with the Filesystem category to parse Prefetch.";
            if (status == "SkippedNotElevated")
                return "prefetch_files was skipped (not elevated). This package has no copied .pf files. Re-collect elevated with Foton-Collect.ps1 that includes Collect schema 1.2.0.";
            if (status == "NoData")
                return "prefetch_files ran but copied nothing. Prefetch may be disabled or empty; see 08_Filesystem/prefetch_files.csv.";
            if (pf == null)
                return "This package has no prefetch_files task (older collect). Listing CSV is not parseable. Re-collect with module 1.9+ / schema 1.2.0.";
            return "No .pf, .lnk, jumplist, .evtx, or Amcache.hve files were in that path. Parse does not read live Prefetch, event logs, or Amcache.";
        }

        static string? Hostname(FotonPackage pkg)
        {
            if (pkg.Artifacts.TryGetValue("os_info", out var a) && a.Json is IDictionary<string, object> d && d.TryGetValue("Hostname", out var h) && h != null)
                return Convert.ToString(h, System.Globalization.CultureInfo.InvariantCulture);
            return null;
        }
    }
}
