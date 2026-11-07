using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Core;
using Foton.Package;

namespace Foton.Tools
{
    /// <summary>One external_parse_inventory.csv row: what a tool did with this package, and the hash of each output file.</summary>
    public sealed class ComposeRow
    {
        public string Tool { get; set; } = "";
        /// <summary>Copied, Retained, NotOnPath, NoInput, NoBatch, NoRules, MissingRuntime, NoOutput, ToolError, or SwapError.</summary>
        public string Status { get; set; } = "";
        public string DestRelative { get; set; } = "";
        public string SHA256 { get; set; } = "";
        public string Version { get; set; } = "";
        public string RulesVersion { get; set; } = "";
        public string Note { get; set; } = "";
    }

    public sealed class ComposeRun
    {
        public List<ComposeRow> Rows { get; } = new List<ComposeRow>();
        public string InventoryPath { get; set; } = "";
    }

    /// <summary>
    /// Compose (Invoke-FotonExternalParse): runs EZ Tools, Hayabusa, and Chainsaw on copied package files, writing
    /// under analysis\external\&lt;tool&gt;\ with every output hashed. Offline: never downloads a tool and never reads the
    /// live host. A missing tool is an Info coverage row, not a parse failure; hits from these engines are named to the
    /// tool, never a Foton verdict. To add a tool, add a job here and its executable names to ComposeTools.
    /// </summary>
    public static class ComposeRunner
    {
        const string StdErr = "tool_stderr.txt", StdOut = "tool_stdout.txt";

        sealed class Skip
        {
            public string Status = "", Note = "";
        }

        sealed class Job
        {
            public string Tool = "";
            public string[] Names = new string[0];
            public string NeedDir = "";
            /// <summary>A file the tool reads directly (not a folder walk); NoInput when absent.</summary>
            public string? NeedFile;
            public Func<string, Skip?>? Pre;
            public Func<string, string, string, List<string>> Args = (exe, input, output) => new List<string>();
        }

        /// <param name="toolPaths">Explicit executable per tool name; wins over tools.json and PATH.</param>
        /// <param name="pathEnv">PATH to search (tests); the process PATH when null.</param>
        public static ComposeRun Run(string packagePath, StatusLog log, string? toolRoot = null,
            IDictionary<string, string>? toolPaths = null, string? pathEnv = null)
        {
            var full = Path.GetFullPath(packagePath);
            if (File.Exists(full))
                throw new InvalidOperationException("Compose writes tool output into the case folder, so it needs an extracted package. Extract the ZIP and run compose on the folder.");
            var pkg = FotonPackage.Open(full);
            var root = pkg.CaseRoot.TrimEnd('\\', '/');
            log.Write("Running external parsers on copied package files (offline)", StatusLevel.Step);

            var overrides = new Dictionary<string, string>(toolPaths ?? new Dictionary<string, string>(), StringComparer.OrdinalIgnoreCase);
            var extRoot = Path.Combine(root, "analysis", "external");
            Directory.CreateDirectory(extRoot);
            var fs = CaseCategories.FolderOf("Filesystem");
            var prefetch = Path.Combine(root, fs, "prefetch");
            var lnk = Path.Combine(root, fs, "lnk_jumplist");
            var evtx = Path.Combine(root, CaseCategories.FolderOf("EventLogs"), "evtx");
            var amcache = Path.Combine(root, fs, "amcache");
            var hives = Path.Combine(root, fs, "hives");

            List<string> Ez(string input, string output, string csvName) => new List<string> { "-d", input, "--csv", output, "--csvf", csvName };
            var jobs = new[]
            {
                new Job { Tool = "PECmd", Names = new[] { "PECmd.exe", "PECmd" }, NeedDir = prefetch, Args = (e, i, o) => Ez(i, o, "pecmd.csv") },
                new Job { Tool = "LECmd", Names = new[] { "LECmd.exe", "LECmd" }, NeedDir = lnk, Args = (e, i, o) => Ez(i, o, "lecmd.csv") },
                new Job { Tool = "JLECmd", Names = new[] { "JLECmd.exe", "JLECmd" }, NeedDir = lnk, Args = (e, i, o) => Ez(i, o, "jlecmd.csv") },
                new Job { Tool = "EvtxECmd", Names = new[] { "EvtxECmd.exe", "EvtxECmd" }, NeedDir = evtx, Args = (e, i, o) => Ez(i, o, "evtxecmd.csv") },
                new Job
                {
                    Tool = "AmcacheParser", Names = new[] { "AmcacheParser.exe", "AmcacheParser" }, NeedDir = amcache,
                    NeedFile = Path.Combine(amcache, "Amcache.hve"),
                    Args = (e, i, o) => new List<string> { "-f", Path.Combine(i, "Amcache.hve"), "--csv", o, "--csvf", "amcacheparser.csv" },
                },
                // RECmd exports nothing without a search switch; with only -d/--csv it logs a warning and exits.
                // A batch file is the whole point of running it here.
                new Job
                {
                    Tool = "RECmd", Names = new[] { "RECmd.exe", "RECmd" }, NeedDir = hives,
                    Pre = e => ComposeSupport.RecmdBatch(e) != null ? null : new Skip
                    {
                        Status = "NoBatch",
                        Note = @"RECmd found but no BatchExamples\DFIRBatch.reb or Kroll_Batch.reb beside it. RECmd does nothing without a batch or search switch; reinstall EZ Tools with BatchExamples.",
                    },
                    Args = (e, i, o) => new List<string> { "-d", i, "--bn", ComposeSupport.RecmdBatch(e)!, "--csv", o, "--csvf", "recmd.csv" },
                },
                new Job { Tool = "Hayabusa", Names = new[] { "hayabusa.exe", "hayabusa" }, NeedDir = evtx, Args = HayabusaArgs },
                // Hunt with Sigma/Chainsaw rules shipped beside the binary. Without rules there is nothing to hunt; a
                // dump would re-serialise every EVTX record (hundreds of MB) and duplicate EvtxECmd, so it is not run.
                new Job
                {
                    Tool = "Chainsaw", Names = new[] { "chainsaw.exe", "chainsaw" }, NeedDir = evtx,
                    Pre = e =>
                    {
                        var r = ComposeSupport.ChainsawRulesFor(e);
                        return r.RulesPath != null || r.SigmaPath != null ? null : new Skip
                        {
                            Status = "NoRules",
                            Note = @"Chainsaw found but no rules\ or sigma\ (with mappings\sigma-event-logs-all.yml) beside it. Install the Chainsaw release that bundles rules, then compose again. EvtxECmd and Hayabusa cover the EVTX meanwhile.",
                        };
                    },
                    Args = (e, i, o) =>
                    {
                        var r = ComposeSupport.ChainsawRulesFor(e);
                        var a = new List<string> { "hunt", i };
                        if (r.RulesPath != null) a.AddRange(new[] { "-r", r.RulesPath });
                        if (r.SigmaPath != null) a.AddRange(new[] { "-s", r.SigmaPath, "--mapping", r.MappingPath! });
                        a.AddRange(new[] { "--csv", "--output", o, "--skip-errors" });
                        return a;
                    },
                },
            };

            var run = new ComposeRun();
            var rows = run.Rows;
            bool anyTool = false;
            foreach (var j in jobs)
            {
                overrides.TryGetValue(j.Tool, out var over);
                var resolved = ToolResolver.Resolve(j.Tool, j.Names, over, toolRoot, pathEnv);
                var exe = resolved?.Path;
                var ver = resolved?.Version ?? "";
                var rulesVer = resolved?.RulesVersion ?? "";
                var src = resolved?.Source ?? "";
                var lower = j.Tool.ToLowerInvariant();
                var toolDir = Path.Combine(extRoot, lower);
                Directory.CreateDirectory(toolDir);
                ComposeRow Row(string status, string dest, string note) =>
                    new ComposeRow { Tool = j.Tool, Status = status, DestRelative = dest, Version = ver, RulesVersion = rulesVer, Note = note };
                // When this run does not execute the tool, output from an earlier compose is kept (it may be the only
                // copy) but listed as Retained, so the inventory still describes every file analyze will read.
                void Retained(string why)
                {
                    foreach (var f in Outputs(toolDir))
                        rows.Add(new ComposeRow
                        {
                            Tool = j.Tool, Status = "Retained", DestRelative = Relative(f, root), SHA256 = Hashing.SafeHash(f, false),
                            Note = $"Output from an earlier compose run; {j.Tool} did not run this time ({why}). Tool version for this file is not recorded here.",
                        });
                }

                if (exe == null)
                {
                    var hint = j.Tool == "Hayabusa"
                        ? "Run foton tools Hayabusa, then compose again. Native foton parse remains the air-gap fallback."
                        : "If it is installed elsewhere, register it once: foton tools EZTools <folder> (or foton tools Chainsaw <folder>). Native foton parse is the fallback. This is a coverage gap, not a parse error.";
                    rows.Add(Row("NotOnPath", "", $"{j.Tool} was not found via Foton tools.json or PATH. {hint}"));
                    Retained("NotOnPath");
                    continue;
                }
                anyTool = true;
                if (!Directory.Exists(j.NeedDir))
                {
                    rows.Add(Row("NoInput", "", $"Tool found ({src}) but input folder is missing: {j.NeedDir}. Re-collect elevated if the copy task was skipped."));
                    Retained("NoInput");
                    continue;
                }
                if (j.NeedFile != null && !File.Exists(j.NeedFile))
                {
                    rows.Add(Row("NoInput", "", $"Tool found ({src}) but input file is missing: {j.NeedFile}. Re-collect elevated if the copy task was skipped."));
                    Retained("NoInput");
                    continue;
                }
                var skip = j.Pre?.Invoke(exe);
                if (skip != null)
                {
                    rows.Add(Row(skip.Status, "", skip.Note));
                    Retained(skip.Status);
                    continue;
                }

                // Run into a staging folder; earlier output is replaced only when this run actually produces files, so
                // a failed rerun cannot destroy the last good one.
                var stage = Path.Combine(extRoot, $".{lower}.staging-{Guid.NewGuid():N}");
                Directory.CreateDirectory(stage);
                int? exitCode = null;
                // Run in the tool's own install tree: Hayabusa resolves config\ relative to the working directory. Every
                // path passed in is absolute, so this is safe for the EZ Tools too.
                var workDir = Path.GetDirectoryName(exe);
                if (string.IsNullOrEmpty(workDir) || !Directory.Exists(workDir)) workDir = toolDir;
                try
                {
                    var args = CommandLine.Join(j.Args(exe, j.NeedDir, stage));
                    log.Write($"{j.Tool}: {exe} {args}", StatusLevel.Info);
                    exitCode = ToolProcess.RunToFiles(exe, args, workDir!, Path.Combine(stage, StdOut), Path.Combine(stage, StdErr));
                }
                catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is InvalidOperationException || ex is IOException || ex is UnauthorizedAccessException)
                {
                    try { TextFile.Write(Path.Combine(stage, StdErr), ex.Message); } catch (IOException) { }
                }
                bool ok = exitCode == 0;

                var fresh = Outputs(stage).ToList();
                if (fresh.Count > 0)
                {
                    var swapError = Swap(toolDir, stage, Path.Combine(extRoot, $".{lower}.prev-{Guid.NewGuid():N}"));
                    if (swapError != null)
                    {
                        rows.Add(Row("SwapError", Relative(stage, root),
                            $"{j.Tool} produced output, but it could not replace the earlier output ({swapError}); a file in that folder may be open. The new output was left in the staging folder."));
                        Retained("SwapError");
                        continue;
                    }
                }
                else
                {
                    // Nothing new: keep earlier output, but replace the logs so they describe only this run (a log this
                    // run did not write is removed, never left to be read as this run's).
                    Directory.CreateDirectory(toolDir);
                    foreach (var leaf in new[] { StdErr, StdOut })
                    {
                        var from = Path.Combine(stage, leaf);
                        var to = Path.Combine(toolDir, leaf);
                        try
                        {
                            if (File.Exists(to)) File.Delete(to);
                            if (File.Exists(from)) File.Move(from, to);
                        }
                        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                    }
                }
                try { if (Directory.Exists(stage)) Directory.Delete(stage, true); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }

                var dirRel = @"analysis\external\" + lower;
                // .NET 10 builds (AmcacheParser has no other) print this and exit when the runtime is absent.
                if (fresh.Count == 0 && !ok && ComposeSupport.MissingRuntime(Path.Combine(toolDir, StdErr), Path.Combine(toolDir, StdOut)))
                {
                    rows.Add(Row("MissingRuntime", dirRel,
                        $"{j.Tool} needs a .NET runtime that is not installed on this workstation (see tool_stdout.txt / tool_stderr.txt). Install the runtime it names, then compose again."));
                    Retained("MissingRuntime");
                    continue;
                }
                if (fresh.Count == 0)
                {
                    var status = ok ? "NoOutput" : "ToolError";
                    rows.Add(Row(status, dirRel, $"{j.Tool} ran but produced no output files. See tool_stderr.txt. Native parse remains valid."));
                    Retained(status);
                    continue;
                }
                // A tool that fails partway often still writes valid rows for the inputs it finished, so the output is kept,
                // but the row says the run did not complete.
                var partial = ok ? "" : $" The tool exited with {(exitCode.HasValue ? "code " + exitCode.Value : "a start error")}, so this output may be partial; see tool_stderr.txt.";
                foreach (var f in Outputs(toolDir))
                {
                    var row = Row("Copied", Relative(f, root),
                        $"Hashed output from {j.Tool} (resolved via {src}). Hits from this engine are observations named to the tool, not a Foton verdict.{partial}");
                    row.SHA256 = Hashing.SafeHash(f, false);
                    rows.Add(row);
                }
            }

            if (!anyTool)
                rows.Add(new ComposeRow
                {
                    Tool = "*", Status = "NotOnPath",
                    Note = "No EZ Tools / Hayabusa / Chainsaw binaries were found. For Hayabusa: foton tools Hayabusa. Use foton parse for the native parser fallback.",
                });

            run.InventoryPath = Path.Combine(extRoot, "external_parse_inventory.csv");
            Csv.Write(run.InventoryPath, rows);
            log.Write($"Compose: {rows.Count(r => r.Status == "Copied")} output file(s) hashed; inventory {run.InventoryPath}", StatusLevel.Good);
            return run;
        }

        static List<string> HayabusaArgs(string exe, string input, string output)
        {
            // v4 renamed csv-timeline to dfir-timeline. Probe the built-in help rather than guessing, so both work.
            var exeDir = Path.GetDirectoryName(exe);
            var help = ToolProcess.Capture(exe, "--help", exeDir, 30000);
            var sub = help != null && (help.StdOut + help.StdErr).Contains("csv-timeline") ? "csv-timeline" : "dfir-timeline";
            // -w skips the interactive rule wizard. -U writes UTC; the default is the workstation's local zone, which is
            // neither the host's zone nor the package's UTC convention. Rules resolve relative to the working
            // directory, so point -r/-c at the install tree next to the binary.
            var a = new List<string> { sub, "-d", input, "-o", Path.Combine(output, "hayabusa.csv"), "-w", "-C", "-U" };
            var rules = Path.Combine(exeDir ?? "", "rules");
            if (Directory.Exists(rules) || File.Exists(rules))
            {
                a.AddRange(new[] { "-r", rules });
                var cfg = Path.Combine(rules, "config");
                if (Directory.Exists(cfg) || File.Exists(cfg)) a.AddRange(new[] { "-c", cfg });
            }
            return a;
        }

        /// <summary>
        /// Swap by directory rename (same volume): the earlier output is deleted only after the new folder is in place,
        /// and is restored if that rename fails. Null on success, else the error.
        /// </summary>
        static string? Swap(string toolDir, string stage, string prev)
        {
            try
            {
                if (!Directory.Exists(toolDir))
                {
                    Directory.Move(stage, toolDir);
                    return null;
                }
                Directory.Move(toolDir, prev);
                try { Directory.Move(stage, toolDir); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    try { Directory.Move(prev, toolDir); }
                    catch (Exception restore) when (restore is IOException || restore is UnauthorizedAccessException)
                    {
                        return $"{ex.Message} The earlier output could not be put back either and is in {prev}";
                    }
                    return ex.Message;
                }
                try { Directory.Delete(prev, true); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
                return null;
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return ex.Message; }
        }

        /// <summary>Tool output files (not the captured logs), in Get-ChildItem -Recurse order.</summary>
        static IEnumerable<string> Outputs(string dir) =>
            !Directory.Exists(dir) ? Enumerable.Empty<string>()
            : FileSearch.Find(dir, "*", int.MaxValue).Where(f => !string.Equals(Path.GetFileName(f), StdErr, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(Path.GetFileName(f), StdOut, StringComparison.OrdinalIgnoreCase));

        static string Relative(string path, string root) => path.Substring(root.Length).TrimStart('\\', '/');
    }
}
