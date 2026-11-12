using System;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace Foton.Package
{
    /// <summary>
    /// HTML written on the endpoint (the package's own report, gpresult /h) as plain text. It is never rendered: a
    /// compromised host can put anything in it, and the in-box browser control is not a sandbox. Pure function.
    /// </summary>
    public static class HtmlText
    {
        static readonly TimeSpan Limit = TimeSpan.FromSeconds(5);
        static readonly Regex Hidden = new Regex(@"<(script|style)\b[^>]*>.*?</\1\s*>|<!--.*?-->", RegexOptions.IgnoreCase | RegexOptions.Singleline, Limit);
        static readonly Regex Break = new Regex(@"<br\b[^>]*>|</(p|div|tr|li|h[1-6]|table|ul|ol)\s*>", RegexOptions.IgnoreCase, Limit);
        static readonly Regex Cell = new Regex(@"</t[dh]\s*>", RegexOptions.IgnoreCase, Limit);
        static readonly Regex Tag = new Regex(@"<[^>]*>", RegexOptions.None, Limit);
        static readonly Regex Blank = new Regex(@"(\r\n){3,}", RegexOptions.None, Limit);

        public static string ToText(string html)
        {
            var s = Hidden.Replace(html, "");
            s = Break.Replace(s, "\n");
            s = Cell.Replace(s, "\t");
            s = Tag.Replace(s, "");
            s = WebUtility.HtmlDecode(s);
            var lines = s.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n')
                .Select(l => l.Trim(' ', '\t').Length == 0 ? "" : l.TrimStart(' ').TrimEnd(' ', '\t'));
            return Blank.Replace(string.Join("\r\n", lines), "\r\n\r\n").Trim('\r', '\n');
        }
    }
}
