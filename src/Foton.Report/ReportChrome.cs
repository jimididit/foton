using System.IO;
using System.Text;

namespace Foton.Report
{
    /// <summary>
    /// Offline report chrome every HTML report must include: sticky search/filter bar, section table of
    /// contents, and the brand mark. No CDN. The search filters table rows, findings, and section titles.
    /// </summary>
    public static class ReportChrome
    {
        /// <summary>Complete &lt;style&gt; element; append after the report's own styles (uses its CSS variables).</summary>
        public static string NavCss => Load("nav.css");

        /// <summary>The search bar and table-of-contents container; place after the header.</summary>
        public static string NavBarHtml => Load("navbar.html");

        /// <summary>The &lt;script&gt; that builds the TOC from &lt;h2&gt; and filters; place before &lt;/body&gt;.</summary>
        public static string NavScript => Load("nav.js");

        /// <summary>The photon wave-packet mark (stroke uses currentColor).</summary>
        public static string MarkSvg => Load("mark.svg");

        /// <summary>Report-specific &lt;style&gt; elements (the 1.38.x here-strings), placed before NavCss.</summary>
        public static string BaselineCss => Load("baseline.css");
        public static string CompareCss => Load("compare.css");

        static string Load(string name)
        {
            using (var s = typeof(ReportChrome).Assembly.GetManifestResourceStream("Foton.Report." + name))
            {
                if (s == null) throw new FileNotFoundException("Missing embedded report resource " + name);
                using (var r = new StreamReader(s, new UTF8Encoding(false))) return r.ReadToEnd();
            }
        }
    }
}
