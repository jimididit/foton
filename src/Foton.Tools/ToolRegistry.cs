using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Tools
{
    public sealed class RegistrationRow
    {
        public string Name { get; set; } = "";
        /// <summary>Registered or NotFound.</summary>
        public string Status { get; set; } = "";
        public string Version { get; set; } = "";
        public string ExecutablePath { get; set; } = "";
        public string ObservedSha256 { get; set; } = "";
    }

    /// <summary>
    /// Records an already-installed tool (or the EZ Tools folder) in tools.json without downloading anything or
    /// touching PATH (Register-FotonLocalTool). EZ Tools unpack into per-tool subfolders (EvtxeCmd\, RECmd\) that one
    /// PATH entry never covers; recording each executable's full path lets compose find them. Upstream publishes no
    /// per-file hashes, so the SHA-256 written here is what Foton observed on disk, not a verification.
    /// </summary>
    public static class ToolRegistry
    {
        public static IReadOnlyList<RegistrationRow> Register(string name, string path, string? toolRoot)
        {
            var wanted = ComposeTools.Expand(name);
            // Full first (GetFullPath throws at 260 characters under net462), then the existence checks on the prefixed form.
            var full = LongPath.Full(path);
            bool isDir = Directory.Exists(LongPath.For(full));
            if (!isDir && !File.Exists(LongPath.For(full))) throw new FileNotFoundException("Path not found: " + path, path);
            var root = ToolManifest.Root(toolRoot);

            var rows = new List<RegistrationRow>();
            foreach (var tool in wanted)
            {
                string? exe = null;
                foreach (var pattern in tool.Patterns)
                {
                    // Depth 2 covers EZTools\EvtxeCmd\EvtxECmd.exe without walking a whole drive.
                    exe = isDir
                        ? FileSearch.Find(full, pattern, 2).OrderBy(f => f.Length).FirstOrDefault()
                        : FileSearch.Like(Path.GetFileName(full), pattern) ? full : null;
                    if (exe != null) break;
                }
                if (exe == null)
                {
                    rows.Add(new RegistrationRow { Name = tool.Name, Status = "NotFound" });
                    continue;
                }

                var ver = VersionOf(tool.Name, exe);
                var dir = LongPath.ParentOf(exe);
                var rulesPath = new[] { "rules", "sigma" }.Select(leaf => Path.Combine(dir, leaf))
                    .FirstOrDefault(p => Directory.Exists(LongPath.For(p))) ?? "";
                var sha = Hashing.Sha256Hex(exe);
                ToolManifest.Save(root, new Dictionary<string, object?>
                {
                    ["Name"] = tool.Name,
                    ["Version"] = ver,
                    ["SourceUrl"] = "registered local install",
                    ["ArchiveSha256"] = "",
                    ["ObservedSha256"] = sha,
                    ["Verified"] = false,
                    ["InstallDateUtc"] = FotonTime.Format(DateTime.UtcNow),
                    ["InstallPath"] = dir,
                    ["ExecutablePath"] = exe,
                    ["RulesPath"] = rulesPath,
                    ["RulesVersion"] = rulesPath.Length > 0 ? "local-unversioned" : "",
                    ["License"] = "",
                });
                rows.Add(new RegistrationRow { Name = tool.Name, Status = "Registered", Version = ver, ExecutablePath = exe, ObservedSha256 = sha });
            }
            return rows;
        }

        /// <summary>The executable's file version, else the version the tool prints (Chainsaw); "" when neither is known.</summary>
        public static string VersionOf(string tool, string exe)
        {
            var ver = FileVersion(exe);
            return ver.Length > 0 ? ver : CliVersion(tool, exe);
        }

        /// <summary>The version resource only; runs nothing. "" when the file has none.</summary>
        public static string FileVersion(string exe)
        {
            try { return (FileVersionInfo.GetVersionInfo(LongPath.For(exe)).FileVersion ?? "").Trim(); }
            catch (Exception ex) when (ex is IOException || ex is ArgumentException || ex is UnauthorizedAccessException || ex is NotSupportedException) { return ""; }
        }

        /// <summary>
        /// Version printed by the tool itself, for binaries with no file version resource (Chainsaw is a Rust build:
        /// "chainsaw --version" prints "chainsaw 2.17.1"). Only tools listed here are run, with a short timeout; "" when unknown.
        /// </summary>
        public static string CliVersion(string tool, string exe, int timeoutMs = 5000)
        {
            if (!string.Equals(tool, "Chainsaw", StringComparison.OrdinalIgnoreCase)) return "";
            var r = ToolProcess.Capture(exe, "--version", null, timeoutMs);
            if (r == null) return "";
            foreach (var text in new[] { r.StdOut, r.StdErr })
            {
                var m = Regex.Match(text, @"\d+\.\d+(?:\.\d+){0,2}");
                if (m.Success) return m.Value;
            }
            return "";
        }
    }

    /// <summary>File lookups in Get-ChildItem -Recurse order (a folder's files, then each subfolder), never following junctions.</summary>
    static class FileSearch
    {
        public static IEnumerable<string> Find(string root, string pattern, int maxDepth)
        {
            var pending = new Stack<KeyValuePair<string, int>>();
            pending.Push(new KeyValuePair<string, int>(root, 0));
            while (pending.Count > 0)
            {
                var item = pending.Pop();
                string[] files, dirs;
                // Enumerated with the long-path form (a rule tree under the tool root is often past 260 characters); the
                // names handed back and pushed are the normal form, so callers and tools.json never see the prefix.
                try { files = Directory.GetFiles(LongPath.For(item.Key)); dirs = Directory.GetDirectories(LongPath.For(item.Key)); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { continue; }
                foreach (var found in files)
                {
                    var f = LongPath.Plain(found);
                    if (Like(f.Substring(f.LastIndexOf('\\') + 1), pattern)) yield return f;
                }
                if (item.Value >= maxDepth) continue;
                for (int i = dirs.Length - 1; i >= 0; i--)
                {
                    var d = LongPath.Plain(dirs[i]);
                    if (!Reparse(d)) pending.Push(new KeyValuePair<string, int>(d, item.Value + 1));
                }
            }
        }

        /// <summary>PowerShell -like: * and ? wildcards, case-insensitive, whole name.</summary>
        public static bool Like(string name, string pattern) =>
            Regex.IsMatch(name, "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$", RegexOptions.IgnoreCase | RegexOptions.Singleline);

        static bool Reparse(string path)
        {
            try { return (File.GetAttributes(LongPath.For(path)) & FileAttributes.ReparsePoint) != 0; }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { return true; }
        }
    }
}
