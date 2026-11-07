using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Foton.Core;
using Foton.Report;
using static Foton.Analyze.Ps;

namespace Foton.Analyze
{
    /// <summary>What the triage report renders: the loaded package and the findings analysis produced.</summary>
    public sealed class TriageReportInput
    {
        public PackageData Data { get; set; } = new PackageData();
        public IReadOnlyList<Finding> Findings { get; set; } = new Finding[0];
        public IReadOnlyList<Dictionary<string, string?>> Manifest { get; set; } = new Dictionary<string, string?>[0];
        public IReadOnlyList<Dictionary<string, string?>> Errors { get; set; } = new Dictionary<string, string?>[0];
        public string? CaseRoot { get; set; }
        public DateTime? CollectedUtc { get; set; }
        public string Version { get; set; } = FotonVersion.Product;
        public int EventLogDays { get; set; } = 14;
        /// <summary>Rendered beside a ZIP: relative artifact links do not resolve, and the report says so.</summary>
        public bool FromZip { get; set; }
    }

    /// <summary>
    /// The triage HTML overview (New-FotonReport). Every host- or artifact-derived string is escaped; each finding
    /// links to the artifact it cites. Observations, not conclusions: the report says so before anything else.
    /// </summary>
    public static class TriageReport
    {
        public const string FileName = "Foton_Report.html";

        static readonly Dictionary<string, int> SevOrder = new Dictionary<string, int> { ["High"] = 0, ["Medium"] = 1, ["Low"] = 2, ["Info"] = 3 };

        static string E(object? v) => Html.Encode(Str(v));

        /// <summary>
        /// A link to a path inside the package, or plain text. Paths come from package files, so only a relative path
        /// is clickable: no colon (a scheme, even one split by a tab or newline the browser strips, or a drive), no
        /// control characters, no leading slash (root or UNC).
        /// </summary>
        static string Link(string target, string text)
        {
            bool relative = target.Length > 0 && target.IndexOf(':') < 0 && !target.Any(ch => ch < 0x20 || ch == 0x7F)
                && target[0] != '/' && target[0] != '\\';
            return relative ? $"<a href=\"{Html.Encode(target)}\">{Html.Encode(text)}</a>" : Html.Encode(text);
        }

        /// <summary>
        /// Severity then category, with Sort-Object's algorithm (PsSort), so findings with equal keys land in the same
        /// order 1.38.x rendered them for the same findings.
        /// </summary>
        internal static List<Finding> Order(IEnumerable<Finding> findings)
        {
            var list = findings.ToList();
            int Rank(Finding f) => SevOrder.TryGetValue(f.Severity, out var r) ? r : -1;
            PsSort.Sort<Finding>(list, (a, b) =>
            {
                int c = Rank(a).CompareTo(Rank(b));
                return c != 0 ? c : string.Compare(a.Category, b.Category, StringComparison.InvariantCultureIgnoreCase);
            });
            return list;
        }

        /// <summary>ConvertTo-FotonObservationHtml: lead sentence as a paragraph, " ; " samples as a list.</summary>
        internal static string ObservationHtml(string text)
        {
            var safe = Html.Encode(text);
            const string marker = "Sample: ";
            int pos = safe.IndexOf(marker, StringComparison.Ordinal);
            var lead = "";
            List<string> items;
            if (pos >= 0)
            {
                lead = safe.Substring(0, pos).Trim();
                items = Split(safe.Substring(pos + marker.Length));
            }
            else if (safe.Contains(" ; ")) items = Split(safe);
            else return $"<div class=\"obs\"><p class=\"obs-lead\">{safe}</p></div>";
            var html = new StringBuilder("<div class=\"obs\">");
            if (lead.Length > 0) html.Append("<p class=\"obs-lead\">").Append(lead).Append("</p>");
            html.Append("<ul class=\"obs-list\">");
            foreach (var item in items) html.Append("<li>").Append(item).Append("</li>");
            return html.Append("</ul></div>").ToString();
        }

        static List<string> Split(string s) => s.Split(new[] { " ; " }, StringSplitOptions.None).Select(x => x.Trim()).Where(x => x.Length > 0).ToList();

        public static string Write(TriageReportInput input, string path)
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            TextFile.Write(path, Render(input));
            return path;
        }

        public static string Render(TriageReportInput r)
        {
            var d = r.Data;
            var os = d["os_info"];
            var host = IsTrue(os) ? Str(Get(os, "Hostname")) : "";
            if (host.Length == 0) host = "(unknown host)";
            var cov = d["collection_coverage"];
            bool elevated = IsTrue(cov) && Get(cov, "Elevated") != null && IsTrue(Get(cov, "Elevated"));
            var collected = r.CollectedUtc.HasValue ? FotonTime.Format(r.CollectedUtc.Value) : "(not recorded)";
            var findings = Order(r.Findings);
            int Count(string sev) => findings.Count(f => f.Severity == sev);
            const string notSupplied = "(not supplied)";

            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.AppendLine("<title>Foton Triage Report - " + Html.Encode(host) + "</title>");
            sb.AppendLine(ReportChrome.TriageCss + ReportChrome.NavCss);
            sb.AppendLine("</head><body><div class=\"wrap\" id=\"top\">");
            sb.AppendLine("<header class=\"hero\">");
            sb.AppendLine("<div class=\"brand\">");
            sb.AppendLine(ReportChrome.MarkSvg);
            sb.AppendLine("<div class=\"brand-text\">");
            sb.AppendLine("<h1>Foton</h1>");
            sb.AppendLine("<div class=\"tagline\">Windows DFIR triage report - Opening a window...closes a door</div>");
            sb.AppendLine("<div class=\"credits\">v" + Html.Encode(r.Version) + "</div>");
            sb.AppendLine("</div></div>");
            sb.AppendLine("<div class=\"meta\">");
            sb.AppendLine("<div><b>Hostname</b>" + Html.Encode(host) + "</div>");
            if (IsTrue(os))
            {
                sb.AppendLine("<div><b>Operating System</b>" + Html.Encode(F("{0} (build {1})", Get(os, "Caption"), Get(os, "BuildNumber"))) + "</div>");
                sb.AppendLine("<div><b>Domain</b>" + E(Get(os, "Domain")) + "</div>");
                sb.AppendLine("<div><b>Last Boot (UTC)</b>" + E(Get(os, "LastBootUtc")) + " &middot; up " + E(Get(os, "UptimeDays")) + "d</div>");
            }
            sb.AppendLine("<div><b>Case</b>" + notSupplied + "</div>");
            sb.AppendLine("<div><b>Examiner</b>" + notSupplied + "</div>");
            sb.AppendLine("<div><b>Collected (UTC)</b>" + Html.Encode(collected) + "</div>");
            sb.AppendLine($"<div><b>Event Window</b>Last {r.EventLogDays} days (analysis default if not stored in package)</div>");
            sb.AppendLine("<div><b>Privilege</b>" + (elevated ? "Elevated (Administrator)" : "Standard user - reduced coverage") + "</div>");
            sb.AppendLine("</div>");
            sb.AppendLine("<div class=\"notice\"><b>Read this first.</b> Every item below is an automated observation produced by pattern matching, not a conclusion. Nothing here establishes that this host is compromised. Each finding cites the artifact file it came from - verify against that artifact, and against the host owner's expectations, before it goes anywhere near a report or a remediation decision.</div>");
            sb.AppendLine("</header>");
            sb.AppendLine(ReportChrome.NavBarHtml);

            sb.AppendLine("<h2 id=\"sec-summary\">Triage Summary</h2>");
            sb.AppendLine("<div class=\"cards\">");
            sb.AppendLine($"<div class=\"card c-high\"><div class=\"n\">{Count("High")}</div><div class=\"l\">High attention</div></div>");
            sb.AppendLine($"<div class=\"card c-med\"><div class=\"n\">{Count("Medium")}</div><div class=\"l\">Medium</div></div>");
            sb.AppendLine($"<div class=\"card c-low\"><div class=\"n\">{Count("Low")}</div><div class=\"l\">Low</div></div>");
            sb.AppendLine($"<div class=\"card c-info\"><div class=\"n\">{Count("Info")}</div><div class=\"l\">Informational</div></div>");
            int Rows(string name) => IsTrue(d[name]) ? Items(d[name]).Count : 0;
            sb.AppendLine("</div>");
            sb.AppendLine("<div class=\"cards\">");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{Rows("running_processes")}</div><div class=\"l\">Processes</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{Rows("services")}</div><div class=\"l\">Services</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{Rows("scheduled_tasks")}</div><div class=\"l\">Scheduled tasks</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{Rows("active_connections")}</div><div class=\"l\">Connections</div></div>");
            sb.AppendLine("</div>");

            sb.AppendLine("<h2 id=\"sec-observations\">Observations<small>click any row to expand</small></h2>");
            sb.AppendLine("<div class=\"controls\">");
            sb.AppendLine("<button class=\"btn on\" data-sev=\"all\">All</button><button class=\"btn\" data-sev=\"High\">High</button><button class=\"btn\" data-sev=\"Medium\">Medium</button><button class=\"btn\" data-sev=\"Low\">Low</button><button class=\"btn\" data-sev=\"Info\">Info</button>");
            sb.AppendLine("</div>");
            foreach (var f in findings)
            {
                string cls = "f-info", chip = "chip-info";
                switch (f.Severity)
                {
                    case "High": cls = "f-high"; chip = "chip-high"; break;
                    case "Medium": cls = "f-med"; chip = "chip-med"; break;
                    case "Low": cls = "f-low"; chip = "chip-low"; break;
                }
                sb.AppendLine($"<div class=\"finding {cls}\" data-sev=\"{Html.Encode(f.Severity)}\">");
                sb.AppendLine("<div class=\"f-head\">");
                sb.AppendLine($"<span class=\"chip {chip}\">{Html.Encode(f.Severity)}</span>");
                sb.AppendLine("<span class=\"chip chip-cat\">" + Html.Encode(f.Category) + "</span>");
                sb.AppendLine("<span class=\"f-title\">" + Html.Encode(f.Title) + "</span>");
                sb.AppendLine($"<span class=\"chip chip-tier\">Tier {f.Tier}</span>");
                sb.AppendLine("</div><div class=\"f-body\">");
                sb.AppendLine("<div class=\"obs-block\"><span class=\"lbl\">What was observed</span>");
                sb.AppendLine(ObservationHtml(f.Observation));
                sb.AppendLine("</div>");
                if (f.WhyItMatters.Length > 0) sb.AppendLine("<p><span class=\"lbl\">Why it matters</span>" + Html.Encode(f.WhyItMatters) + "</p>");
                if (f.NextStep.Length > 0) sb.AppendLine("<p><span class=\"lbl\">Suggested next step</span>" + Html.Encode(f.NextStep) + "</p>");
                if (f.Artifact.Length > 0) sb.AppendLine("<p><span class=\"lbl\">Source artifact</span>" + Link(f.Artifact, f.Artifact) + "</p>");
                sb.AppendLine("</div></div>");
            }
            sb.AppendLine("<div id=\"nores\" style=\"display:none;color:#7f93a8;padding:14px\">No observations match the current filter.</div>");

            var admins = IsTrue(d["local_group_membership"])
                ? Items(d["local_group_membership"]).Where(a => Eq(Get(a, "Group"), "Administrators") && Ne(Get(a, "Member"), "(none)")).ToList() : new List<object?>();
            if (admins.Count > 0)
            {
                sb.AppendLine("<h2 id=\"sec-admins\">Local Administrators<small>compare against the expected baseline</small></h2><table><tr><th>Member</th><th>Type</th><th>Source</th><th>SID</th></tr>");
                foreach (var a in admins)
                    sb.AppendLine($"<tr><td>{E(Get(a, "Member"))}</td><td>{E(Get(a, "ObjectClass"))}</td><td>{E(Get(a, "PrincipalSource"))}</td><td class=\"dim\">{E(Get(a, "SID"))}</td></tr>");
                sb.AppendLine("</table>");
            }

            var ext = IsTrue(d["active_connections"])
                ? Items(d["active_connections"]).Where(x => Eq(Get(x, "RemoteIsExternal"), true)).Take(40).ToList() : new List<object?>();
            if (ext.Count > 0)
            {
                sb.AppendLine("<h2 id=\"sec-connections\">External Network Connections<small>point-in-time snapshot at collection</small></h2><table><tr><th>Process</th><th>PID</th><th>Remote</th><th>State</th><th>Path</th></tr>");
                foreach (var x in ext)
                {
                    var pathClass = Eq(Get(x, "UserWritablePath"), true) ? "warn" : "dim";
                    sb.AppendLine($"<tr><td>{E(Get(x, "ProcessName"))}</td><td>{E(Get(x, "OwningPID"))}</td><td>{Html.Encode(F("{0}:{1}", Get(x, "RemoteAddress"), Get(x, "RemotePort")))}</td><td>{E(Get(x, "State"))}</td><td class=\"{pathClass}\">{E(Get(x, "ProcessPath"))}</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            if (IsTrue(d["hardening_registry_settings"]))
            {
                var mismatch = Items(d["hardening_registry_settings"]).Where(h => Eq(Get(h, "MatchesRecommended"), false) && Ne(Get(h, "RecommendedValue"), "")).ToList();
                if (mismatch.Count > 0)
                {
                    sb.AppendLine("<h2 id=\"sec-hardening\">Hardening Settings Not At Recommended Value<small>configuration review, not compromise indicators</small></h2><table><tr><th>Setting</th><th>Current</th><th>Recommended</th><th>Meaning</th></tr>");
                    foreach (var m in mismatch)
                        sb.AppendLine($"<tr><td>{E(Get(m, "Setting"))}</td><td class=\"warn\">{E(Get(m, "Value"))}</td><td class=\"dim\">{E(Get(m, "RecommendedValue"))}</td><td>{E(Get(m, "Meaning"))}</td></tr>");
                    sb.AppendLine("</table>");
                }
            }

            string V(Dictionary<string, string?> row, string k) => row.TryGetValue(k, out var v) ? v ?? "" : "";
            sb.AppendLine("<h2 id=\"sec-manifest\">Collection Manifest<small>every artifact in this package</small></h2><table><tr><th>Category</th><th>Artifact</th><th>What it contains</th><th>Records</th><th>Status</th></tr>");
            foreach (var m in r.Manifest)
            {
                var status = V(m, "Status");
                var statusClass = Eq(status, "NoData") ? "dim" : Ne(status, "Success") ? "bad" : "ok";
                var file = V(m, "File");
                var leaf = file.Split('\\', '/').Last();
                sb.AppendLine($"<tr><td class=\"dim\">{Html.Encode(V(m, "Category"))}</td><td>{Link(file.Replace('\\', '/'), leaf)}</td><td>{Html.Encode(V(m, "Description"))}</td><td>{Html.Encode(V(m, "Records"))}</td><td class=\"{statusClass}\">{Html.Encode(status)}</td></tr>");
            }
            sb.AppendLine("</table>");

            // Methodology disclosure: which third-party engines touched this package, and the hash of their output.
            var inv = r.CaseRoot != null ? Path.Combine(r.CaseRoot, "analysis", "external", "external_parse_inventory.csv") : null;
            if (inv != null && File.Exists(inv))
            {
                List<Dictionary<string, string?>> rows;
                try { rows = Csv.Read(inv); } catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { rows = new List<Dictionary<string, string?>>(); }
                if (rows.Count > 0)
                {
                    int ran = rows.Count(x => Eq(V(x, "Status"), "Copied"));
                    sb.AppendLine("<h2 id=\"sec-external\">External Tool Passes<small>who parsed what, and the hash of their output</small></h2>");
                    sb.AppendLine($"<p class=\"dim\">Third-party engines run on <b>copied</b> package files only. Their rule hits are that engine's inferences, named to the tool in the findings above - not a Foton verdict. Tools shown as NotOnPath are a coverage gap on this workstation, not a parse failure: {ran} of {rows.Count} inventory row(s) produced output.</p>");
                    sb.AppendLine("<table><tr><th>Tool</th><th>Version</th><th>Rules</th><th>Status</th><th>Output</th><th>SHA-256</th><th>Note</th></tr>");
                    foreach (var row in rows)
                    {
                        var st = V(row, "Status");
                        var cls = Eq(st, "Copied") ? "ok" : Eq(st, "ToolError") ? "bad" : Eq(st, "NoInput") || Eq(st, "NoOutput") ? "warn" : "dim";
                        var hash = V(row, "SHA256");
                        if (hash.Length > 16) hash = hash.Substring(0, 16) + "...";
                        var dest = V(row, "DestRelative");
                        var outCell = dest.Length > 0 ? Link(dest.Replace('\\', '/'), dest) : "<span class=\"dim\">-</span>";
                        var ver = V(row, "Version");
                        var rules = V(row, "RulesVersion");
                        sb.AppendLine($"<tr><td>{Html.Encode(V(row, "Tool"))}</td><td class=\"dim\">{Html.Encode(ver.Length > 0 ? ver : "-")}</td><td class=\"dim\">{Html.Encode(rules.Length > 0 ? rules : "-")}</td><td class=\"{cls}\">{Html.Encode(st)}</td><td>{outCell}</td><td class=\"dim\">{Html.Encode(hash)}</td><td>{Html.Encode(V(row, "Note"))}</td></tr>");
                    }
                    sb.AppendLine("</table>");
                }
            }

            if (r.Errors.Count > 0)
            {
                sb.AppendLine("<h2 id=\"sec-errors\">Collection Errors<small>gaps to disclose in any report built from this data</small></h2><table><tr><th>Task</th><th>Error</th></tr>");
                foreach (var e in r.Errors)
                    sb.AppendLine($"<tr><td>{Html.Encode(V(e, "Task"))}</td><td class=\"warn\">{Html.Encode(V(e, "Error"))}</td></tr>");
                sb.AppendLine("</table>");
            }

            sb.AppendLine("<h2 id=\"sec-method\">Methodology, Tiers, and Limitations</h2>");
            sb.AppendLine(ReportChrome.TriageTiers);
            sb.AppendLine(ReportChrome.TriageLimits);
            if (r.FromZip)
                sb.AppendLine("<li><b>Rendered from a ZIP.</b> This report sits beside the source ZIP, not inside the case folder, so relative artifact links such as 06_Security_Posture/defender_status.json do not resolve from here. Extract the ZIP and re-run analyze against the folder if you need those links.</li>");
            sb.AppendLine(ReportChrome.TriageLimitsEnd);
            sb.AppendLine($"<footer>Foton v{Html.Encode(r.Version)} &middot; collected {Html.Encode(collected)} UTC on {Html.Encode(host)} by {notSupplied} &middot; verify artifact hashes in 00_Collection/hashes.csv before analysis</footer>");
            sb.AppendLine("</div>");
            sb.AppendLine(ReportChrome.TriageScript);
            sb.AppendLine(ReportChrome.NavScript);
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }
    }
}
