using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Foton.Report;

namespace Foton.Parse
{
    /// <summary>A parsed_records.csv row: the normalized view every parser shares.</summary>
    public sealed class ParsedRow
    {
        public string SourcePath { get; set; } = "";
        public string Format { get; set; } = "";
        public bool Supported { get; set; }
        public string Identity { get; set; } = "";
        public long SizeBytes { get; set; }
        public string SHA256 { get; set; } = "";
        public string Note { get; set; } = "";
    }

    /// <summary>
    /// HTML preview of parse rows grouped by Format (New-FotonParseReport). parsed_records.csv is the source of
    /// truth. Every cell escaped; it never says the host executed anything.
    /// </summary>
    public static class ParseReport
    {
        public const string FileName = "Foton_Parse.html";
        public const int DefaultMaxRows = 400;

        public static string Write(IReadOnlyList<ParsedRow> rows, string outputPath, string? hostname, string? emptyReason, int maxRows = DefaultMaxRows)
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(outputPath, Render(rows, hostname, emptyReason, maxRows), new UTF8Encoding(false));
            return outputPath;
        }

        public static string Render(IReadOnlyList<ParsedRow> rows, string? hostname, string? emptyReason, int maxRows = DefaultMaxRows)
        {
            var host = string.IsNullOrEmpty(hostname) ? "(unknown host)" : hostname!;
            int supported = rows.Count(r => r.Supported);
            int mam = rows.Count(r => r.Format == "MAM-compressed");
            int lnk = rows.Count(r => r.Format == "LNK");
            string N(long n) => n.ToString(CultureInfo.InvariantCulture);

            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.AppendLine("<title>Foton Parse - " + Html.Encode(host) + "</title>");
            sb.AppendLine(ReportChrome.ParseCss + ReportChrome.NavCss);
            sb.AppendLine("</head><body><div class=\"wrap\" id=\"top\">");
            sb.AppendLine("<header class=\"hero\">");
            sb.AppendLine("<div class=\"brand\">");
            sb.AppendLine(ReportChrome.MarkSvg);
            sb.AppendLine("<div class=\"brand-text\">");
            sb.AppendLine("<h1>Foton</h1>");
            sb.AppendLine("<div class=\"tagline\">Offline parse - Prefetch and LNK already in the package. Not triage findings. Not a compromise verdict.</div>");
            sb.AppendLine("</div></div>");
            sb.AppendLine("<div class=\"meta\">");
            sb.AppendLine("<div><b>Hostname</b>" + Html.Encode(host) + "</div>");
            sb.AppendLine("<div><b>Rows</b>" + N(rows.Count) + "</div>");
            sb.AppendLine("<div><b>Supported names</b>" + N(supported) + "</div>");
            sb.AppendLine("<div><b>MAM-compressed</b>" + N(mam) + "</div>");
            sb.AppendLine("<div><b>LNK</b>" + N(lnk) + "</div>");
            sb.AppendLine("</div>");
            sb.AppendLine("<div class=\"notice\"><b>Read this first.</b> " + Html.Encode(
                "CSV is the source of truth (analysis/parsed_records.csv). This HTML is a capped preview. MAM-compressed Prefetch is not inflated. EVTX rows are selected Event IDs only, capped. Amcache KeyLastWriteUtc is hive key last-write, not proof of execution. Legacy Amcache File keys and SRUM ESE copies are not parsed here.") + "</div>");
            sb.AppendLine("</header>");
            sb.AppendLine(ReportChrome.NavBarHtml);

            sb.AppendLine("<h2 id=\"sec-counts\">Parse counts</h2><div class=\"cards\">");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{N(rows.Count)}</div><div class=\"l\">Total</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{N(supported)}</div><div class=\"l\">Supported</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{N(mam)}</div><div class=\"l\">MAM Prefetch</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{N(lnk)}</div><div class=\"l\">LNK</div></div>");
            sb.AppendLine("</div>");

            var formats = rows.Select(r => r.Format).Where(f => f.Length > 0)
                .Distinct(StringComparer.InvariantCultureIgnoreCase).OrderBy(f => f, StringComparer.InvariantCultureIgnoreCase).ToList();
            if (formats.Count > 0)
            {
                sb.AppendLine("<div class=\"controls\">");
                sb.AppendLine("<button type=\"button\" class=\"btn on\" data-change=\"all\">All</button>");
                foreach (var f in formats)
                    sb.AppendLine($"<button type=\"button\" class=\"btn\" data-change=\"{Html.Encode(f)}\">{Html.Encode(f)}</button>");
                sb.AppendLine("</div>");
            }

            if (rows.Count == 0)
            {
                sb.AppendLine("<h2 id=\"sec-empty\">Nothing parsed</h2>");
                sb.AppendLine("<p class=\"dim\">" + Html.Encode(string.IsNullOrEmpty(emptyReason) ? "No Prefetch or LNK files were parsed." : emptyReason) + "</p>");
            }
            else
            {
                foreach (var fmt in formats)
                {
                    var chunk = rows.Where(r => string.Equals(r.Format, fmt, StringComparison.InvariantCultureIgnoreCase)).ToList();
                    var shown = chunk;
                    var extra = "";
                    if (shown.Count > maxRows)
                    {
                        extra = $" (showing {maxRows} of {shown.Count})";
                        shown = shown.Take(maxRows).ToList();
                    }
                    sb.AppendLine($"<h2 id=\"{Html.SectionId(fmt)}\">{Html.Encode(fmt)} <small>{chunk.Count} row(s){extra}</small></h2>");
                    sb.AppendLine("<table><thead><tr>");
                    foreach (var col in new[] { "Identity", "Supported", "SizeBytes", "SHA256", "SourcePath", "Note" })
                        sb.AppendLine("<th>" + Html.Encode(col) + "</th>");
                    sb.AppendLine("</tr></thead><tbody>");
                    foreach (var c in shown)
                    {
                        sb.AppendLine($"<tr data-change=\"{Html.Encode(c.Format)}\">");
                        sb.AppendLine("<td>" + Html.Encode(c.Identity) + "</td>");
                        sb.AppendLine("<td>" + (c.Supported ? "True" : "False") + "</td>");
                        sb.AppendLine("<td>" + N(c.SizeBytes) + "</td>");
                        sb.AppendLine("<td>" + Html.Encode(c.SHA256) + "</td>");
                        sb.AppendLine("<td>" + Html.Encode(c.SourcePath) + "</td>");
                        sb.AppendLine("<td>" + Html.Encode(c.Note) + "</td>");
                        sb.AppendLine("</tr>");
                    }
                    sb.AppendLine("</tbody></table>");
                }
            }

            sb.AppendLine("<footer>Foton parse report &middot; not findings.csv &middot; source of truth is parsed_records.csv</footer>");
            sb.AppendLine("</div>");
            sb.AppendLine(ReportChrome.NavScript);
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }
    }
}
