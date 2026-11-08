using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

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
            var dir = Path.GetDirectoryName(Path.GetFullPath(recmdPath)) ?? "";
            return new[] { "DFIRBatch.reb", "Kroll_Batch.reb" }
                .Select(leaf => Path.Combine(dir, "BatchExamples", leaf))
                .FirstOrDefault(File.Exists);
        }

        /// <summary>
        /// Chainsaw rule sources beside the binary: rules\ (Chainsaw rules) and sigma\ (Sigma rules, which need
        /// mappings\sigma-event-logs-all.yml to run).
        /// </summary>
        public static ChainsawRules ChainsawRulesFor(string chainsawPath)
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(chainsawPath)) ?? "";
            var result = new ChainsawRules();
            var rules = Path.Combine(dir, "rules");
            if (Directory.Exists(rules)) result.RulesPath = rules;
            var sigma = Path.Combine(dir, "sigma");
            var mapping = new[] { Path.Combine(dir, "mappings", "sigma-event-logs-all.yml"), Path.Combine(dir, "sigma-event-logs-all.yml") }
                .FirstOrDefault(File.Exists);
            if (Directory.Exists(sigma) && mapping != null)
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
    }
}
