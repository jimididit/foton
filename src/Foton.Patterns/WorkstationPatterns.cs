using System.Collections.Generic;
using System.IO;
using System.Text;
using Foton.Core;

namespace Foton.Patterns
{
    /// <summary>The suspicious-command pattern list (workstation analysis only).</summary>
    public static class WorkstationPatterns
    {
        public static IReadOnlyList<string> SuspiciousCommands { get; } = Load();

        static IReadOnlyList<string> Load()
        {
            using (var s = typeof(WorkstationPatterns).Assembly.GetManifestResourceStream("Foton.Patterns.SuspiciousCommandPatterns.txt"))
            {
                if (s == null) throw new FileNotFoundException("Missing embedded SuspiciousCommandPatterns.txt");
                using (var r = new StreamReader(s, Encoding.UTF8)) return PatternLists.Lines(r.ReadToEnd());
            }
        }
    }
}
