using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace Foton.Package
{
    /// <summary>
    /// HTML written on the endpoint (the package's own report, gpresult /h) as plain text. It is never rendered: a
    /// compromised host can put anything in it, and the in-box browser control is not a sandbox. Pure function. Hostile
    /// markup that runs a regex into its time limit falls back to a linear tag stripper, so this never throws on input.
    /// </summary>
    public static class HtmlText
    {
        static readonly TimeSpan Limit = TimeSpan.FromSeconds(5);
        static readonly Rules Default = new Rules(Limit);

        public static string ToText(string html) => ToText(html, Default);

        /// <summary>Tests: the same conversion with another regex time limit.</summary>
        internal static string ToText(string html, TimeSpan limit) => ToText(html, new Rules(limit));

        static string ToText(string html, Rules r)
        {
            string s;
            try
            {
                s = r.Hidden.Replace(html, "");
                s = r.Break.Replace(s, "\n");
                s = r.Cell.Replace(s, "\t");
                s = r.Tag.Replace(s, "");
            }
            catch (RegexMatchTimeoutException)
            {
                s = StripTags(html);
            }
            s = WebUtility.HtmlDecode(s);
            var lines = s.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n')
                .Select(l => l.Trim(' ', '\t').Length == 0 ? "" : l.TrimStart(' ').TrimEnd(' ', '\t'));
            return Collapse(string.Join("\r\n", lines));
        }

        /// <summary>Everything between '&lt;' and '&gt;' removed, one pass. Script and style text stays, as text.</summary>
        static string StripTags(string html)
        {
            var sb = new StringBuilder(html.Length);
            bool inTag = false;
            foreach (var ch in html)
            {
                if (ch == '<') inTag = true;
                else if (ch == '>' && inTag) inTag = false;
                else if (!inTag) sb.Append(ch);
            }
            return sb.ToString();
        }

        /// <summary>Runs of more than one blank line become one; leading and trailing line breaks removed. Linear.</summary>
        static string Collapse(string text)
        {
            var lines = text.Split(new[] { "\r\n" }, StringSplitOptions.None);
            var sb = new StringBuilder(text.Length);
            int blanks = 0;
            foreach (var line in lines)
            {
                if (line.Length == 0) { blanks++; continue; }
                if (sb.Length > 0) sb.Append(blanks > 0 ? "\r\n\r\n" : "\r\n");
                sb.Append(line);
                blanks = 0;
            }
            return sb.ToString();
        }

        sealed class Rules
        {
            public readonly Regex Hidden, Break, Cell, Tag;

            public Rules(TimeSpan limit)
            {
                Hidden = new Regex(@"<(script|style)\b[^>]*>.*?</\1\s*>|<!--.*?-->", RegexOptions.IgnoreCase | RegexOptions.Singleline, limit);
                Break = new Regex(@"<br\b[^>]*>|</(p|div|tr|li|h[1-6]|table|ul|ol)\s*>", RegexOptions.IgnoreCase, limit);
                Cell = new Regex(@"</t[dh]\s*>", RegexOptions.IgnoreCase, limit);
                Tag = new Regex(@"<[^>]*>", RegexOptions.None, limit);
            }
        }
    }
}
