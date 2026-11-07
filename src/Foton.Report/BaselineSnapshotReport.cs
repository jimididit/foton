using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Foton.Core;

namespace Foton.Report
{
    /// <summary>
    /// HTML snapshot of one baseline observation (New-FotonBaselineReport). A capped preview: baseline.json stays
    /// the source of truth for Compare. Every cell is escaped. It never says the host is clean or compromised.
    /// </summary>
    public static class BaselineSnapshotReport
    {
        public const string FileName = "Foton_Baseline.html";
        public const int DefaultMaxRows = 200;

        /// <summary>Renders baseline.json (or a package folder) to Foton_Baseline.html beside it unless outputPath is given.</summary>
        public static string Write(string baselinePath, string? outputPath = null, int maxRows = DefaultMaxRows)
        {
            var json = BaselineDocument.ResolveJsonPath(baselinePath);
            var output = outputPath ?? Path.Combine(Path.GetDirectoryName(json)!, FileName);
            var dir = Path.GetDirectoryName(Path.GetFullPath(output));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(output, Render(BaselineDocument.Load(json), maxRows), new UTF8Encoding(false));
            return output;
        }

        public static string Render(BaselineDocument doc, int maxRows = DefaultMaxRows)
        {
            var h = doc.Header;
            var hostName = h.Hostname.Length > 0 ? h.Hostname : "(unknown host)";
            var meta = new Dictionary<string, ProviderMeta>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in doc.Providers) meta[p.RecordType] = p;

            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.AppendLine("<title>Foton Baseline Snapshot - " + Html.Encode(hostName) + "</title>");
            sb.AppendLine(ReportChrome.BaselineCss + ReportChrome.NavCss);
            sb.AppendLine("</head><body><div class=\"wrap\" id=\"top\">");
            sb.AppendLine("<header class=\"hero\">");
            sb.AppendLine("<div class=\"brand\">");
            sb.AppendLine(ReportChrome.MarkSvg);
            sb.AppendLine("<div class=\"brand-text\">");
            sb.AppendLine("<h1>Foton</h1>");
            sb.AppendLine("<div class=\"tagline\">Baseline snapshot - one observation of stable configuration. Not a triage report. Not a clean-host certificate.</div>");
            sb.AppendLine("</div></div>");
            sb.AppendLine("<div class=\"meta\">");
            sb.AppendLine("<div><b>Hostname</b>" + Html.Encode(hostName) + "</div>");
            sb.AppendLine("<div><b>Captured (UTC)</b>" + Html.Encode(h.CapturedUtc) + "</div>");
            sb.AppendLine("<div><b>Schema</b>" + Html.Encode(h.BaselineSchemaVersion) + "</div>");
            sb.AppendLine("<div><b>Tool</b>" + Html.Encode(h.ToolVersion) + "</div>");
            sb.AppendLine("<div><b>Privilege</b>" + (h.Elevated ? "Elevated (Administrator)" : "Standard user - some providers may be thin") + "</div>");
            sb.AppendLine("<div><b>Payload SHA-256</b>" + Html.Encode(h.PayloadSha256) + "</div>");
            sb.AppendLine("</div>");
            var caveat = h.Note.Length > 0 ? h.Note
                : "A baseline taken after an incident is a picture of that state. Diff proves change between two observations, never when or who.";
            sb.AppendLine("<div class=\"notice\"><b>Read this first.</b> " + Html.Encode(caveat) + " Full tables live in baseline.json. This HTML is a capped preview.</div>");
            sb.AppendLine("</header>");
            sb.AppendLine(ReportChrome.NavBarHtml);

            var types = doc.Records.Keys.OrderBy(k => k, StringComparer.InvariantCultureIgnoreCase).ToList();
            sb.AppendLine("<h2 id=\"sec-counts\">Record counts</h2><div class=\"cards\">");
            foreach (var type in types)
                sb.AppendLine($"<a class=\"card\" href=\"#{Html.SectionId(type)}\"><div class=\"n\">{doc.Records[type].Count}</div><div class=\"l\">{Html.Encode(type)}</div></a>");
            sb.AppendLine("</div>");

            foreach (var type in types)
            {
                var rows = doc.Records[type];
                meta.TryGetValue(type, out var m);
                var cols = new List<string>();
                if (m != null)
                    foreach (var f in m.IdentityFields.Concat(m.ComparedFields))
                        if (!cols.Contains(f)) cols.Add(f);
                if (cols.Count == 0 && rows.Count > 0) cols.AddRange(rows[0].Keys);

                var extra = "";
                if (rows.Count > maxRows)
                {
                    extra = $" (showing {maxRows} of {rows.Count})";
                    rows = rows.Take(maxRows).ToList();
                }
                sb.AppendLine($"<h2 id=\"{Html.SectionId(type)}\">{Html.Encode(type)} <small>{rows.Count} rows{extra}</small></h2>");
                if (m != null && m.FalsePositives.Length > 0)
                    sb.AppendLine("<p class=\"dim\">" + Html.Encode(m.FalsePositives) + "</p>");
                if (cols.Count == 0 || rows.Count == 0)
                {
                    sb.AppendLine("<p class=\"dim\">No rows.</p>");
                    continue;
                }
                sb.AppendLine("<table><thead><tr>");
                foreach (var c in cols) sb.AppendLine("<th>" + Html.Encode(c) + "</th>");
                sb.AppendLine("</tr></thead><tbody>");
                foreach (var row in rows)
                {
                    sb.AppendLine("<tr>");
                    foreach (var c in cols)
                        sb.AppendLine("<td>" + Html.Encode(row.TryGetValue(c, out var v) ? BaselineDocument.PsString(v) : "") + "</td>");
                    sb.AppendLine("</tr>");
                }
                sb.AppendLine("</tbody></table>");
            }

            sb.AppendLine($"<footer>Foton baseline snapshot v{Html.Encode(h.ToolVersion)} &middot; schema {Html.Encode(h.BaselineSchemaVersion)} &middot; {Html.Encode(hostName)} &middot; compare with Compare-FotonBaseline against baseline.json</footer>");
            sb.AppendLine("</div>");
            sb.AppendLine(ReportChrome.NavScript);
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }
    }
}
