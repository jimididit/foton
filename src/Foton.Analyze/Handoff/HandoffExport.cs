using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Package;
using Foton.Report;

namespace Foton.Analyze.Handoff
{
    /// <summary>What foton handoff wrote.</summary>
    public sealed class HandoffRun
    {
        public string Folder { get; internal set; } = "";
        /// <summary>Every file in the handoff, relative to its folder, in the order SHA256SUMS.txt lists them.</summary>
        public List<string> Files { get; } = new List<string>();
        /// <summary>The package check at export time, in words.</summary>
        public string Verification { get; internal set; } = "";
        /// <summary>Every file listed in hashes.csv matched at export time.</summary>
        public bool Verified { get; internal set; }
        public NotesReview Review { get; internal set; } = new NotesReview();
    }

    /// <summary>
    /// foton handoff and the console's Export handoff: the review of one package in a folder another examiner can read
    /// and check. Foton's findings and the examiner's notes are written side by side and labelled apart (observations
    /// versus examiner input). The package itself is not copied: the handoff names it by its hashes.csv SHA-256 (and
    /// the ZIP's, when opened from one) and records whether it verified at export time. Every file is in SHA256SUMS.txt.
    /// </summary>
    public static class HandoffExport
    {
        public const string HtmlName = "Foton_Handoff.html", ReadmeName = "HANDOFF.txt", SumsName = "SHA256SUMS.txt", NotesCsvName = "examiner_notes.csv";

        /// <param name="outputParent">The folder to create the handoff in; C:\Foton\Handoffs when null.</param>
        /// <param name="builtReport">Foton_Report.html to include: only one this workstation built and has checked unchanged (the console passes it; foton handoff does not).</param>
        public static HandoffRun Run(string packagePath, StatusLog log, string? outputParent = null, string? builtReport = null, DateTime? utcNow = null)
        {
            var now = utcNow ?? DateTime.UtcNow;
            var pkg = FotonPackage.Open(packagePath);
            var root = pkg.CaseRoot;
            log.Write("Checking the package before the handoff", StatusLevel.Step);
            var code = PackageCheck.Report(log, pkg);
            var hashes = Path.Combine(root, CaseTree.CollectionFolder, "hashes.csv");
            var run = new HandoffRun
            {
                Verified = code == 0,
                Verification = code == 0 ? $"Every file listed in hashes.csv matched at {FotonTime.Format(now)} UTC."
                    : File.Exists(hashes) ? $"The package DID NOT VERIFY at {FotonTime.Format(now)} UTC: a file listed in hashes.csv changed or is missing (run foton package on it)."
                    : "No hashes.csv: the package's integrity could not be checked.",
            };
            // Refuses (InvalidDataException) when the notes cannot be read: a handoff without them would misstate the review.
            run.Review = ExaminerNotes.Review(root);

            var caseName = Path.GetFileName(root.TrimEnd('\\', '/'));
            var label = caseName.StartsWith("Foton_", StringComparison.OrdinalIgnoreCase) ? caseName.Substring(6) : caseName;
            var parent = Path.GetFullPath(outputParent ?? CaseTree.DefaultOutput("Handoffs"));
            var folder = Path.Combine(parent, $"Foton_Handoff_{SafeName(label)}_{FotonTime.Stamp(now)}Z");
            if (Directory.Exists(folder) || File.Exists(folder)) throw new IOException("Already exists: " + folder);
            Directory.CreateDirectory(folder);
            run.Folder = folder;
            log.Write("Writing the handoff to " + folder, StatusLevel.Step);

            void Add(string relative) { run.Files.Add(relative); }
            void Copy(string source, string relative)
            {
                var dest = Path.Combine(folder, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
                File.Copy(source, dest);
                Add(relative);
            }

            var findings = run.Review.FindingsSource;
            if (findings.Length > 0 && Plain(root, findings)) Copy(Path.Combine(root, findings), "findings.csv");
            var notesRel = Path.Combine("analysis", ExaminerNotes.FileName);
            if (File.Exists(Path.Combine(root, notesRel)) && Plain(root, notesRel)) Copy(Path.Combine(root, notesRel), ExaminerNotes.FileName);
            WriteNotesCsv(Path.Combine(folder, NotesCsvName), run.Review);
            Add(NotesCsvName);
            var custody = Path.Combine(CaseTree.CollectionFolder, "chain_of_custody.txt");
            foreach (var rel in new[] { custody, Path.Combine(CaseTree.CollectionFolder, "hashes.csv") })
                if (File.Exists(Path.Combine(root, rel)) && Plain(root, rel)) Copy(Path.Combine(root, rel), Path.Combine("package", Path.GetFileName(rel)));
            if (builtReport != null && File.Exists(builtReport)) Copy(builtReport, CaseTree.ReportFileName);

            var header = ChainOfCustody.ReadHeader(root);
            var hashesSha = File.Exists(hashes) && Plain(root, Path.Combine(CaseTree.CollectionFolder, "hashes.csv")) ? Hashing.Sha256Hex(hashes).ToLowerInvariant() : "";
            var facts = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("Case folder", caseName),
                new KeyValuePair<string, string>("Case number", header.CaseNumber ?? "(not recorded)"),
                new KeyValuePair<string, string>("Collection examiner", header.Examiner ?? "(not recorded)"),
                new KeyValuePair<string, string>("Package hashes.csv SHA-256", hashesSha.Length > 0 ? hashesSha : "(no hashes.csv)"),
            };
            if (pkg.ZipSha256 != null) facts.Add(new KeyValuePair<string, string>("Package ZIP", Path.GetFileName(pkg.SourcePath) + " SHA-256 " + pkg.ZipSha256.ToLowerInvariant()));
            facts.Add(new KeyValuePair<string, string>("Package check", run.Verification));
            facts.Add(new KeyValuePair<string, string>("Findings", findings.Length > 0 ? findings : "(none: analyze has not run)"));
            facts.Add(new KeyValuePair<string, string>("Handoff created (UTC)", FotonTime.Format(now)));
            facts.Add(new KeyValuePair<string, string>("Foton", FotonVersion.Product));

            File.WriteAllText(Path.Combine(folder, HtmlName), Page(run.Review, facts, builtReport != null && run.Files.Contains(CaseTree.ReportFileName)), new UTF8Encoding(false));
            Add(HtmlName);
            TextFile.WriteLines(Path.Combine(folder, ReadmeName), Readme(run, facts));
            Add(ReadmeName);
            TextFile.WriteLines(Path.Combine(folder, SumsName),
                run.Files.Select(f => Hashing.Sha256Hex(Path.Combine(folder, f)).ToLowerInvariant() + " *" + f.Replace('\\', '/')));
            log.Write($"Handoff: {run.Files.Count} files and {SumsName} in {folder}", StatusLevel.Good);
            if (code != 0) log.Write(run.Verification, StatusLevel.Warn);
            return run;
        }

        static bool Plain(string root, string relative) => CaseIndex.IsPlain(root, relative);

        static string SafeName(string name)
        {
            var safe = Regex.Replace(name ?? "", @"[^A-Za-z0-9._-]+", "_").Trim('_', '.');
            if (safe.Length > 60) safe = safe.Substring(0, 60).TrimEnd('_', '.');
            return safe.Length == 0 ? "case" : safe;
        }

        static int Count(NotesReview r, string status) => r.Findings.Count(f => f.Status == status);

        static IEnumerable<string> Readme(HandoffRun run, List<KeyValuePair<string, string>> facts)
        {
            var r = run.Review;
            yield return "Foton handoff";
            yield return "";
            foreach (var f in facts) yield return f.Key + ": " + TextFile.OneLine(f.Value);
            yield return "";
            yield return $"Findings: {r.Findings.Count} ({Count(r, NoteStatus.Relevant)} relevant, {Count(r, NoteStatus.FollowUp)} follow up, {Count(r, NoteStatus.NotRelevant)} not relevant, " +
                $"{Count(r, NoteStatus.Reviewed)} reviewed, {Count(r, NoteStatus.NotReviewed)} not reviewed)";
            yield return $"Notes on findings the latest analyze no longer produces: {r.NotInLatestFindings.Count}";
            yield return $"Row notes: {r.Rows.Count}";
            yield return "";
            yield return "Findings are Foton's automated observations (Tier 1 fact, Tier 2 inference, Tier 3 hypothesis), not conclusions.";
            yield return "Statuses and notes are examiner input. Neither asserts compromise, attribution, or intent.";
            yield return "";
            yield return "Files (SHA-256 in " + SumsName + "; check with Get-FileHash):";
            foreach (var f in run.Files) yield return "  " + f;
            yield return "";
            yield return "The package itself is not in this folder. Check it against the hashes above, or run foton package on it.";
        }

        static void WriteNotesCsv(string path, NotesReview r)
        {
            var rows = new List<Dictionary<string, object?>>();
            Dictionary<string, object?> Row(string kind, string status, string severity, string what, string artifact, object? row, string check, string text, string examiner, string updated, string key) =>
                new Dictionary<string, object?>
                {
                    ["Kind"] = kind, ["Status"] = NoteStatus.Label(status), ["Severity"] = severity, ["What"] = what, ["Artifact"] = artifact, ["Row"] = row,
                    ["RowCheck"] = check, ["Note"] = text, ["Examiner"] = examiner, ["UpdatedUtc"] = updated, ["Key"] = key,
                };
            foreach (var f in r.Findings) rows.Add(Row("Finding", f.Status, f.Severity, f.Title, f.Artifact, null, "", f.Text, f.Examiner, f.UpdatedUtc, f.Key));
            foreach (var n in r.NotInLatestFindings) rows.Add(Row("Finding not in the latest analyze", n.Status, "", n.Label, n.Artifact, null, "", n.Text, n.Examiner, n.UpdatedUtc, n.Key));
            foreach (var x in r.Rows) rows.Add(Row("Row", x.Note.Status, "", x.Note.Label, x.Note.Artifact, x.Note.Row, x.State, x.Note.Text, x.Note.Examiner, x.Note.UpdatedUtc, x.Note.Key));
            if (rows.Count > 0) Csv.Write(path, rows);
            else TextFile.Write(path, "\"Kind\",\"Status\",\"Severity\",\"What\",\"Artifact\",\"Row\",\"RowCheck\",\"Note\",\"Examiner\",\"UpdatedUtc\",\"Key\"");
        }

        static string E(string? s) => Foton.Report.Html.Encode(s);
        static string Para(string? s) => E(s).Replace("\r\n", "<br>").Replace("\n", "<br>");

        static string Page(NotesReview r, List<KeyValuePair<string, string>> facts, bool withReport)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
            sb.AppendLine("<title>Foton Handoff - " + E(facts[0].Value) + "</title>");
            sb.AppendLine(ReportChrome.BaselineCss + ReportChrome.NavCss);
            sb.AppendLine("</head><body><div class=\"wrap\" id=\"top\">");
            sb.AppendLine("<header class=\"hero\"><div class=\"brand\">" + ReportChrome.MarkSvg + "<div class=\"brand-text\"><h1>Foton</h1>");
            sb.AppendLine("<div class=\"tagline\">Handoff - Foton's findings and the examiner's review of one package.</div></div></div>");
            sb.AppendLine("<div class=\"meta\">");
            foreach (var f in facts) sb.AppendLine("<div><b>" + E(f.Key) + "</b>" + E(f.Value) + "</div>");
            sb.AppendLine("</div>");
            sb.AppendLine("<div class=\"notice\"><b>Read this first.</b> Findings are Foton's automated observations (Tier 1 fact, Tier 2 inference, Tier 3 hypothesis), not conclusions. "
                + "Statuses and notes are examiner input, shown apart from them. Neither asserts compromise, attribution, or intent. "
                + (withReport ? "Foton_Report.html in this folder is the full automated report. " : "")
                + "Every file in this folder is listed in SHA256SUMS.txt.</div>");
            sb.AppendLine("</header>");
            sb.AppendLine(ReportChrome.NavBarHtml);

            sb.AppendLine("<h2 id=\"sec-summary\">Review summary</h2><div class=\"cards\">");
            foreach (var s in new[] { NoteStatus.Relevant, NoteStatus.FollowUp, NoteStatus.NotRelevant, NoteStatus.Reviewed, NoteStatus.NotReviewed })
                sb.AppendLine($"<div class=\"card\"><div class=\"n\">{Count(r, s)}</div><div class=\"l\">{E(NoteStatus.Label(s))}</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{r.NotInLatestFindings.Count}</div><div class=\"l\">Notes on findings no longer produced</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"n\">{r.Rows.Count}</div><div class=\"l\">Row notes</div></div>");
            sb.AppendLine("</div>");

            sb.AppendLine("<h2 id=\"sec-findings\">Findings and examiner status</h2>");
            if (r.Findings.Count == 0) sb.AppendLine("<p class=\"dim\">No findings: analyze has not run on this package.</p>");
            else
            {
                sb.AppendLine("<table><thead><tr><th>Severity</th><th>Tier</th><th>Finding (Foton)</th><th>Observation (Foton)</th><th>Artifact</th><th>Status (examiner)</th><th>Note (examiner)</th></tr></thead><tbody>");
                foreach (var f in r.Findings)
                    sb.AppendLine($"<tr><td>{E(f.Severity)}</td><td>{E(f.Tier)}</td><td>{E(f.Title)}</td><td>{E(f.Observation)}</td><td>{E(f.Artifact)}</td><td>{E(NoteStatus.Label(f.Status))}</td><td>{Para(f.Text)}{Who(f.Examiner, f.UpdatedUtc)}</td></tr>");
                sb.AppendLine("</tbody></table>");
            }

            sb.AppendLine("<h2 id=\"sec-not-in-latest\">Notes on findings the latest analyze no longer produces</h2>");
            if (r.NotInLatestFindings.Count == 0) sb.AppendLine("<p class=\"dim\">None.</p>");
            else
            {
                sb.AppendLine("<p class=\"dim\">The finding these notes were written on reads differently now, or is no longer raised (new data, or a rule that words it differently). The notes are kept as written.</p>");
                sb.AppendLine("<table><thead><tr><th>Finding (as noted)</th><th>Artifact</th><th>Status (examiner)</th><th>Note (examiner)</th></tr></thead><tbody>");
                foreach (var n in r.NotInLatestFindings)
                    sb.AppendLine($"<tr><td>{E(n.Label)}</td><td>{E(n.Artifact)}</td><td>{E(NoteStatus.Label(n.Status))}</td><td>{Para(n.Text)}{Who(n.Examiner, n.UpdatedUtc)}</td></tr>");
                sb.AppendLine("</tbody></table>");
            }

            sb.AppendLine("<h2 id=\"sec-rows\">Row notes</h2>");
            if (r.Rows.Count == 0) sb.AppendLine("<p class=\"dim\">None.</p>");
            else
            {
                sb.AppendLine("<p class=\"dim\">Notes on rows of package files. Row check says whether the row still reads as it did when it was noted.</p>");
                sb.AppendLine("<table><thead><tr><th>Artifact</th><th>Row</th><th>Row (as noted)</th><th>Row check</th><th>Status (examiner)</th><th>Note (examiner)</th></tr></thead><tbody>");
                foreach (var x in r.Rows)
                    sb.AppendLine($"<tr><td>{E(x.Note.Artifact)}</td><td>{x.Note.Row}</td><td>{E(x.Note.Label)}</td><td>{E(x.State)}</td><td>{E(NoteStatus.Label(x.Note.Status))}</td><td>{Para(x.Note.Text)}{Who(x.Note.Examiner, x.Note.UpdatedUtc)}</td></tr>");
                sb.AppendLine("</tbody></table>");
            }

            sb.AppendLine($"<footer>Foton handoff v{E(FotonVersion.Product)} &middot; findings schema {E(FotonVersion.FindingsSchema)} &middot; notes schema {E(FotonVersion.NotesSchema)} &middot; check the files against SHA256SUMS.txt</footer>");
            sb.AppendLine("</div>");
            sb.AppendLine(ReportChrome.NavScript);
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }

        static string Who(string examiner, string updated) =>
            updated.Length == 0 ? "" : "<div class=\"dim\">" + E((examiner.Trim().Length > 0 ? examiner.Trim() + ", " : "") + updated + " UTC") + "</div>";
    }
}
