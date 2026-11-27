using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Core;

namespace Foton.Tools
{
    public sealed class ResolvedTool
    {
        public string Path { get; set; } = "";
        /// <summary>ToolPath, Manifest, or PATH.</summary>
        public string Source { get; set; } = "";
        public string Version { get; set; } = "";
        public string RulesVersion { get; set; } = "";
    }

    /// <summary>
    /// Finds a tool for compose (Resolve-FotonExternalTool). Order, do not change lightly: an explicit path for this
    /// tool, then tools.json under the tool root, then PATH. Never changes PATH.
    /// </summary>
    public static class ToolResolver
    {
        public static ResolvedTool? Resolve(string tool, IEnumerable<string> executableNames, string? toolPath, string? toolRoot, string? pathEnv = null)
        {
            // Every output in the compose inventory names the tool version that wrote it: tools.json records it for
            // installs and registrations; anything else is read from the executable's version resource as found
            // (nothing is run here; compose asks a tool without one only when it is about to run it).
            if (!string.IsNullOrWhiteSpace(toolPath) && File.Exists(LongPath.For(toolPath!.Trim())))
            {
                var path = LongPath.Full(toolPath.Trim());
                // An explicit path to the executable tools.json already records is that install: report what it recorded.
                // A damaged tool root must not stop a valid explicit path, so this lookup is best effort.
                var recorded = TryFind(tool, toolRoot);
                var fromRecord = recorded == null ? null : TryFromRecord(recorded, path);
                if (fromRecord != null) return fromRecord;
                return new ResolvedTool { Path = path, Source = "ToolPath", Version = ToolRegistry.FileVersion(path), RulesVersion = LocalRules(path) };
            }

            var installed = ToolManifest.Find(tool, toolRoot);
            var exe = installed != null ? ToolManifest.Get(installed, "ExecutablePath") : "";
            if (exe.Length > 0 && File.Exists(LongPath.For(exe)))
                return FromManifest(installed!, LongPath.Full(exe), "Manifest");

            foreach (var name in executableNames)
            {
                var hit = OnPath(name, pathEnv ?? Environment.GetEnvironmentVariable("PATH") ?? "");
                if (hit != null) return new ResolvedTool { Path = hit, Source = "PATH", Version = ToolRegistry.FileVersion(hit), RulesVersion = LocalRules(hit) };
            }
            return null;
        }

        /// <summary>Best-effort tools.json lookup for an explicit path. Any failure means "not tracked here": the explicit
        /// path still resolves, reported from the file itself. Broad on purpose; the lookup must never block the caller.</summary>
        static Dictionary<string, object?>? TryFind(string tool, string? toolRoot)
        {
            try { return ToolManifest.Find(tool, toolRoot); }
            catch (Exception) { return null; }
        }

        /// <summary>The recorded install, when the explicit path is its executable; null otherwise or when the row is damaged.</summary>
        static ResolvedTool? TryFromRecord(Dictionary<string, object?> recorded, string path)
        {
            try
            {
                return SameFile(ToolManifest.Get(recorded, "ExecutablePath"), path) ? FromManifest(recorded, path, "ToolPath") : null;
            }
            catch (Exception) { return null; }
        }

        static ResolvedTool FromManifest(Dictionary<string, object?> installed, string path, string source)
        {
            var recorded = ToolManifest.Get(installed, "Version");
            return new ResolvedTool
            {
                Path = path, Source = source,
                Version = recorded.Length > 0 ? recorded : ToolRegistry.FileVersion(path),
                // A row from before the RulesVersion field has no key: read it like an untracked tool. A recorded empty value
                // means the install found no rules, and stays empty.
                RulesVersion = installed.ContainsKey("RulesVersion") ? ToolManifest.Get(installed, "RulesVersion") : LocalRules(path),
            };
        }

        static bool SameFile(string recorded, string path)
        {
            // File.Exists is checked first: a damaged ExecutablePath with invalid path characters must not make GetFullPath throw.
            if (recorded.Length == 0 || !File.Exists(LongPath.For(recorded))) return false;
            return string.Equals(LongPath.Full(recorded), path, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>An untracked executable has no recorded rule set. If a rules or sigma folder sits beside it, the rules
        /// are local and unversioned (the same convention ToolRegistry records); otherwise there are none to report. Only a
        /// folder counts: a plain file with that name is not a rule set. Presence, not attribution: a shared folder with an
        /// unrelated rules\ is reported too, because that is what the tool itself loads from beside its executable.</summary>
        static string LocalRules(string exePath)
        {
            var cut = exePath.LastIndexOf('\\');
            var dir = cut < 0 ? "" : exePath.Substring(0, cut);
            return new[] { "rules", "sigma" }.Any(leaf => Directory.Exists(LongPath.For(Path.Combine(dir, leaf))))
                ? "local-unversioned" : "";
        }

        /// <summary>The first PATH directory holding the name (with a PATHEXT extension when it has none), as Get-Command finds it.</summary>
        static string? OnPath(string name, string pathEnv)
        {
            var exts = Path.HasExtension(name)
                ? new[] { "" }
                : (Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD").Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var dir in pathEnv.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).Select(d => d.Trim().Trim('"')).Where(d => d.Length > 0))
                foreach (var ext in exts)
                {
                    try
                    {
                        var candidate = Path.Combine(dir, name + ext);
                        if (File.Exists(candidate)) return Path.GetFullPath(candidate);
                    }
                    catch (Exception ex) when (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException) { }
                }
            return null;
        }
    }
}
