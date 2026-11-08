using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Foton.Tools
{
    /// <summary>
    /// One Windows command line that CommandLineToArgvW splits back unchanged (ConvertTo-FotonCommandLine), so a
    /// case path such as D:\My Cases\CASE-0001 reaches the tool as one argument. MSVCRT rules, which the EZ Tools
    /// (.NET), Hayabusa and Chainsaw (Rust) all use.
    /// </summary>
    public static class CommandLine
    {
        static readonly Regex NeedsQuotes = new Regex(@"[\s""]");

        public static string Join(IEnumerable<string> arguments) => string.Join(" ", arguments.Select(Quote));

        static string Quote(string s)
        {
            if (s.Length > 0 && !NeedsQuotes.IsMatch(s)) return s;
            var sb = new StringBuilder("\"");
            int slashes = 0;
            foreach (var ch in s)
            {
                if (ch == '\\') { slashes++; continue; }
                if (ch == '"') sb.Append('\\', 2 * slashes + 1).Append('"');
                else sb.Append('\\', slashes).Append(ch);
                slashes = 0;
            }
            return sb.Append('\\', 2 * slashes).Append('"').ToString();
        }
    }
}
