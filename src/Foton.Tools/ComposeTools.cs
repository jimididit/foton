using System;
using System.Collections.Generic;
using System.Linq;

namespace Foton.Tools
{
    /// <summary>A tool compose runs and the executable leaf names (wildcards allowed) it is found by.</summary>
    public sealed class ComposeTool
    {
        public ComposeTool(string name, params string[] patterns) { Name = name; Patterns = patterns; }
        public string Name { get; }
        public IReadOnlyList<string> Patterns { get; }
    }

    /// <summary>The tools compose knows (Get-FotonComposeToolExecutables). EZTools is the Eric Zimmerman tools compose runs.</summary>
    public static class ComposeTools
    {
        public static readonly IReadOnlyList<ComposeTool> All = new[]
        {
            new ComposeTool("PECmd", "PECmd.exe"),
            new ComposeTool("LECmd", "LECmd.exe"),
            new ComposeTool("JLECmd", "JLECmd.exe"),
            new ComposeTool("EvtxECmd", "EvtxECmd.exe"),
            new ComposeTool("AmcacheParser", "AmcacheParser.exe"),
            new ComposeTool("RECmd", "RECmd.exe"),
            new ComposeTool("AppCompatCacheParser", "AppCompatCacheParser.exe"),
            new ComposeTool("SBECmd", "SBECmd.exe"),
            new ComposeTool("Hayabusa", "hayabusa.exe", "hayabusa-*.exe"),
            new ComposeTool("Chainsaw", "chainsaw.exe"),
        };

        static readonly string[] EzTools = { "PECmd", "LECmd", "JLECmd", "EvtxECmd", "AmcacheParser", "RECmd", "AppCompatCacheParser", "SBECmd" };

        public static IReadOnlyList<ComposeTool> Expand(string name)
        {
            if (string.Equals(name, "EZTools", StringComparison.OrdinalIgnoreCase))
                return All.Where(t => EzTools.Contains(t.Name)).ToList();
            var one = All.FirstOrDefault(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase));
            if (one != null) return new[] { one };
            throw new ArgumentException($"Unknown tool '{name}'. Use EZTools, {string.Join(", ", All.Select(t => t.Name).Take(All.Count - 1))}, or {All[All.Count - 1].Name}.");
        }
    }
}
