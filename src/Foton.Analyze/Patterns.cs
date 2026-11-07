using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Foton.Analyze
{
    /// <summary>
    /// Pattern-list matching (Test-FotonSuspiciousCommand). The lists themselves are data passed in by the caller:
    /// the workstation loads them from Foton.Patterns; the endpoint ships without the suspicious-command list.
    /// </summary>
    public static class Patterns
    {
        static readonly Regex Flag = new Regex("^-[a-z0-9]+$", RegexOptions.IgnoreCase);
        static readonly Regex Bare = new Regex("^[a-z0-9]+$", RegexOptions.IgnoreCase);

        /// <summary>
        /// Matched pattern names joined ", ", or null. Flags (-enc) and short bare tokens need a word boundary so a
        /// flag does not hit inside a longer hyphenated word; longer patterns are plain substrings.
        /// </summary>
        public static string? SuspiciousHits(string? text, IReadOnlyList<string> patterns)
        {
            if (string.IsNullOrWhiteSpace(text)) return null;
            var lower = text!.ToLowerInvariant();
            var hits = new List<string>();
            foreach (var pattern in patterns)
            {
                if (string.IsNullOrWhiteSpace(pattern)) continue;
                var p = pattern.ToLowerInvariant();
                var token = p.Trim();
                bool matched;
                if (Flag.IsMatch(token) || (token.Length <= 8 && Bare.IsMatch(token)))
                {
                    var re = token.StartsWith("-", StringComparison.Ordinal)
                        ? @"(?<![\w-])" + Regex.Escape(token) + @"\b"
                        : @"(?<![\w])" + Regex.Escape(token);
                    matched = Regex.IsMatch(lower, re);
                }
                else matched = lower.Contains(p);
                if (matched) hits.Add(pattern);
            }
            return hits.Count > 0 ? string.Join(", ", hits) : null;
        }
    }
}
