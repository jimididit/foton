using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Foton.Core
{
    /// <summary>
    /// Heuristic lists that are safe to ship in endpoint executables (1.38.x embedded the same two in the Collect
    /// flatten): user-writable path regexes and remote-access tool names. One trimmed, non-comment line each.
    /// </summary>
    public static class PatternLists
    {
        public static IReadOnlyList<string> UserWritable { get; } = Load("Foton.Core.UserWritablePatterns.txt");
        public static IReadOnlyList<string> RemoteAccessToolNames { get; } = Load("Foton.Core.RemoteAccessToolNames.txt");

        public static List<string> Lines(string text) =>
            text.Replace("\r\n", "\n").Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("#")).ToList();

        internal static IReadOnlyList<string> Load(string resource)
        {
            using (var s = typeof(PatternLists).Assembly.GetManifestResourceStream(resource))
            {
                if (s == null) throw new FileNotFoundException("Missing embedded " + resource);
                using (var r = new StreamReader(s, Encoding.UTF8)) return Lines(r.ReadToEnd());
            }
        }
    }
}
