using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Foton.Core;
using Foton.Report;

namespace Foton.Baseline.Compare
{
    /// <summary>
    /// HTML Added/Removed/Modified report for one compare (New-FotonBaselineCompareReport). Attention follows the
    /// same ranking as the findings. Capped; every cell escaped; never a compromise verdict.
    /// </summary>
    public static class BaselineCompareReport
    {
        public const string FileName = "Foton_BaselineCompare.html";
        public const int DefaultMaxRows = 400;

        public static string Write(CompareResult r, string outputPath, int maxRows = DefaultMaxRows)
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(outputPath));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(outputPath, Render(r, maxRows), new UTF8Encoding(false));
            return outputPath;
        }

        public static string Render(CompareResult r, int maxRows = DefaultMaxRows)
        {
            var rows = r.Changes;
            var mode = r.Mode.Length > 0 ? r.Mode : "Temporal";
            var refHost = r.ReferenceHeader.Hostname.Length > 0 ? r.ReferenceHeader.Hostname : "(unknown)";
            var difHost = r.DifferenceHeader.Hostname.Length > 0 ? r.DifferenceHeader.Hostname : "(unknown)";
            var schema = r.ReferenceHeader.BaselineSchemaVersion;

            int added = rows.Count(c => c.ChangeType == "Added");
            int removed = rows.Count(c => c.ChangeType == "Removed");
            int modified = rows.Count(c => c.ChangeType == "Modified");
            int high = rows.Count(c => ChangeSeverity.Of(c) == "High");

            var shown = rows;
            var extra = "";
            if (shown.Count > maxRows)
            {
                extra = $" (showing {maxRows} of {shown.Count})";
                shown = shown.Take(maxRows).ToList();
            }

            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.AppendLine("<title>Foton Baseline Compare - " + Html.Encode(difHost) + "</title>");
            sb.AppendLine(ReportChrome.CompareCss + ReportChrome.NavCss);
            sb.AppendLine("</head><body><div class=\"wrap\" id=\"top\">");
            sb.AppendLine("<header class=\"hero\">");
            sb.AppendLine("<div class=\"brand\">");
            sb.AppendLine(ReportChrome.MarkSvg);
            sb.AppendLine("<div class=\"brand-text\">");
            sb.AppendLine("<h1>Foton</h1>");
            sb.AppendLine("<div class=\"tagline\">Baseline compare - field-level change between two observations. Not a compromise verdict. Not a clean-host certificate.</div>");
            sb.AppendLine("</div></div>");
            sb.AppendLine("<div class=\"meta\">");
            sb.AppendLine("<div><b>Mode</b>" + Html.Encode(mode) + "</div>");
            sb.AppendLine("<div><b>Reference host</b>" + Html.Encode(refHost) + "</div>");
            sb.AppendLine("<div><b>Difference host</b>" + Html.Encode(difHost) + "</div>");
            sb.AppendLine("<div><b>Reference UTC</b>" + Html.Encode(r.ReferenceHeader.CapturedUtc) + "</div>");
            sb.AppendLine("<div><b>Difference UTC</b>" + Html.Encode(r.DifferenceHeader.CapturedUtc) + "</div>");
            sb.AppendLine("<div><b>Schema</b>" + Html.Encode(schema) + "</div>");
            sb.AppendLine("</div>");
            sb.AppendLine("<div class=\"notice\"><b>Read this first.</b> " + Html.Encode(
                "Diff proves change between two snapshots, never when or who. High attention marks persistence and trust surfaces that deserve review against change control. Software updates, GPO, and lab DNS overrides are common benign sources.") + "</div>");
            sb.AppendLine("</header>");
            sb.AppendLine(ReportChrome.NavBarHtml);

            sb.AppendLine("<h2 id=\"sec-counts\">Change counts</h2><div class=\"cards\">");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{rows.Count}</div><div class=\"l\">Total</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{added}</div><div class=\"l\">Added</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{removed}</div><div class=\"l\">Removed</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{modified}</div><div class=\"l\">Modified</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{high}</div><div class=\"l\">High attention</div></div>");
            sb.AppendLine("</div>");

            sb.AppendLine("<div class=\"controls\">");
            sb.AppendLine("<button type=\"button\" class=\"btn on\" data-change=\"all\">All</button>");
            sb.AppendLine("<button type=\"button\" class=\"btn\" data-change=\"Added\">Added</button>");
            sb.AppendLine("<button type=\"button\" class=\"btn\" data-change=\"Removed\">Removed</button>");
            sb.AppendLine("<button type=\"button\" class=\"btn\" data-change=\"Modified\">Modified</button>");
            sb.AppendLine("</div>");

            if (shown.Count == 0)
            {
                sb.AppendLine("<h2 id=\"sec-changes\">Changes</h2>");
                sb.AppendLine("<p class=\"dim\">No field-level differences in the compared payload.</p>");
            }
            else
            {
                // Sort-Object -Unique: culture order, case-insensitive; -eq groups case-insensitively too.
                var types = shown.Select(c => c.RecordType).Distinct(StringComparer.CurrentCultureIgnoreCase)
                    .OrderBy(t => t, StringComparer.CurrentCultureIgnoreCase).ToList();
                foreach (var type in types)
                {
                    var chunk = shown.Where(c => string.Equals(c.RecordType, type, StringComparison.CurrentCultureIgnoreCase)).ToList();
                    sb.AppendLine($"<h2 id=\"{Html.SectionId(type)}\">{Html.Encode(type)} <small>{chunk.Count} change(s){extra}</small></h2>");
                    sb.AppendLine("<table><thead><tr>");
                    foreach (var col in new[] { "Attention", "Change", "Identity", "Field", "OldValue", "NewValue" })
                        sb.AppendLine("<th>" + Html.Encode(col) + "</th>");
                    sb.AppendLine("</tr></thead><tbody>");
                    foreach (var c in chunk)
                    {
                        var sev = ChangeSeverity.Of(c);
                        sb.AppendLine($"<tr data-change=\"{c.ChangeType}\">");
                        sb.AppendLine($"<td class=\"sev-{sev}\">{Html.Encode(sev)}</td>");
                        sb.AppendLine($"<td class=\"ct-{c.ChangeType}\">{Html.Encode(c.ChangeType)}</td>");
                        sb.AppendLine("<td>" + Html.Encode(c.Identity) + "</td>");
                        sb.AppendLine("<td>" + Html.Encode(c.Field) + "</td>");
                        sb.AppendLine("<td>" + Html.Encode(c.OldValue) + "</td>");
                        sb.AppendLine("<td>" + Html.Encode(c.NewValue) + "</td>");
                        sb.AppendLine("</tr>");
                    }
                    sb.AppendLine("</tbody></table>");
                }
            }

            sb.AppendLine($"<footer>Foton baseline compare &middot; {Html.Encode(mode)} &middot; schema {Html.Encode(schema)} &middot; source of truth remains baseline.json</footer>");
            sb.AppendLine("</div>");
            sb.AppendLine(ReportChrome.NavScript);
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }
    }
}
