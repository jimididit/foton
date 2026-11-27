using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Tools
{
    public sealed class ChainsawRules
    {
        public string? RulesPath { get; set; }
        public string? SigmaPath { get; set; }
        public string? MappingPath { get; set; }
    }

    /// <summary>Files a tool needs beside its binary before compose runs it (Find-FotonComposeSupport).</summary>
    public static class ComposeSupport
    {
        /// <summary>
        /// RECmd batch shipped beside the binary. DFIRBatch.reb is Eric Zimmerman's broad DFIR set; Kroll_Batch.reb is
        /// the older equivalent. Null when neither exists.
        /// </summary>
        public static string? RecmdBatch(string recmdPath)
        {
            var dir = FolderOf(recmdPath);
            if (dir.Length == 0) return null;
            return new[] { "DFIRBatch.reb", "Kroll_Batch.reb" }
                .Select(leaf => Path.Combine(dir, "BatchExamples", leaf))
                .FirstOrDefault(p => File.Exists(LongPath.For(p)));
        }

        /// <summary>
        /// Chainsaw rule sources beside the binary: rules\ (Chainsaw rules) and sigma\ (Sigma rules, which need
        /// mappings\sigma-event-logs-all.yml to run).
        /// </summary>
        public static ChainsawRules ChainsawRulesFor(string chainsawPath)
        {
            var dir = FolderOf(chainsawPath);
            var result = new ChainsawRules();
            // No folder to look in (a bare name): report nothing rather than search the working folder.
            if (dir.Length == 0) return result;
            var rules = Path.Combine(dir, "rules");
            if (Directory.Exists(LongPath.For(rules))) result.RulesPath = rules;
            var sigma = Path.Combine(dir, "sigma");
            var mapping = new[] { Path.Combine(dir, "mappings", "sigma-event-logs-all.yml"), Path.Combine(dir, "sigma-event-logs-all.yml") }
                .FirstOrDefault(p => File.Exists(LongPath.For(p)));
            if (Directory.Exists(LongPath.For(sigma)) && mapping != null)
            {
                result.SigmaPath = sigma;
                result.MappingPath = mapping;
            }
            return result;
        }

        // Wording differs across .NET host versions; match the known variants.
        static readonly Regex MissingRuntimeText = new Regex(
            @"You must install (?:or update )?\.NET|install the missing framework|It was not possible to find any compatible framework version|The framework 'Microsoft\.(?:NETCore|WindowsDesktop)\.App', version '[^']+' (?:\([^)]*\) )?was not found",
            RegexOptions.IgnoreCase);

        /// <summary>True when a tool's captured output says its .NET runtime is not installed.</summary>
        public static bool MissingRuntime(params string[] outputFiles)
        {
            foreach (var p in outputFiles)
            {
                if (string.IsNullOrEmpty(p) || !File.Exists(p)) continue;
                try { if (MissingRuntimeText.IsMatch(File.ReadAllText(p))) return true; }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            }
            return false;
        }

        /// <summary>
        /// The folder a tool's executable sits in. Full path first (GetFullPath throws on 260 characters or more under
        /// net462), then the text before its last backslash, so a deep tool folder still resolves.
        /// </summary>
        static string FolderOf(string exePath)
        {
            // A bare name has no folder of its own. Full would resolve it against the working folder and pick up files there.
            if (exePath.IndexOf('\\') < 0 && exePath.IndexOf('/') < 0) return "";
            return LongPath.ParentOf(LongPath.Full(exePath));
        }
    }
}
