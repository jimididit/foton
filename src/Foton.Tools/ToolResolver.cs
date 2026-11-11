using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

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
            if (!string.IsNullOrWhiteSpace(toolPath) && File.Exists(toolPath!.Trim()))
            {
                var path = Path.GetFullPath(toolPath.Trim());
                return new ResolvedTool { Path = path, Source = "ToolPath", Version = ToolRegistry.FileVersion(path) };
            }

            var installed = ToolManifest.Find(tool, toolRoot);
            var exe = installed != null ? ToolManifest.Get(installed, "ExecutablePath") : "";
            if (exe.Length > 0 && File.Exists(exe))
            {
                var path = Path.GetFullPath(exe);
                var recorded = ToolManifest.Get(installed!, "Version");
                return new ResolvedTool
                {
                    Path = path, Source = "Manifest",
                    Version = recorded.Length > 0 ? recorded : ToolRegistry.FileVersion(path), RulesVersion = ToolManifest.Get(installed!, "RulesVersion"),
                };
            }

            foreach (var name in executableNames)
            {
                var hit = OnPath(name, pathEnv ?? Environment.GetEnvironmentVariable("PATH") ?? "");
                if (hit != null) return new ResolvedTool { Path = hit, Source = "PATH", Version = ToolRegistry.FileVersion(hit) };
            }
            return null;
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
