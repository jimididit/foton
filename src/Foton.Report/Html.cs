using System.Text.RegularExpressions;

namespace Foton.Report
{
    /// <summary>
    /// HTML escaping for report bodies. Every untrusted string (anything from a package) goes through
    /// Encode. Identical to ConvertTo-FotonSafeHtml: &amp; &lt; &gt; " ' only, non-ASCII left as is
    /// (WebUtility.HtmlEncode would also rewrite Latin-1 characters, changing report text).
    /// </summary>
    public static class Html
    {
        public static string Encode(string? text)
        {
            if (text == null) return "";
            return text.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;");
        }

        static readonly Regex NonAlnum = new Regex("[^A-Za-z0-9]+");

        /// <summary>Anchor id for a section heading (Get-FotonReportSectionId).</summary>
        public static string SectionId(string? name)
        {
            var s = NonAlnum.Replace(name ?? "", "-").Trim('-');
            return "sec-" + (s.Length == 0 ? "section" : s);
        }
    }
}
