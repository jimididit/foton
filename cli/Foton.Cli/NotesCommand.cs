using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Core;
using Foton.Package;

namespace Foton.Cli
{
    /// <summary>
    /// foton notes: lists the review status and notes of a package's findings and rows (examiner input, kept in
    /// analysis\examiner_notes.json), or sets one. The console's note editor writes the same file.
    /// </summary>
    static class NotesCommand
    {
        public static int Run(string[] args)
        {
            string? key = null, artifact = null, status = null, text = null, examiner = null;
            int row = 0;
            bool json = false;
            for (int i = 2; i < args.Length; i++)
            {
                var a = args[i];
                if (string.Equals(a, "-Json", StringComparison.OrdinalIgnoreCase)) { json = true; continue; }
                var known = new[] { "-Key", "-Artifact", "-Row", "-Status", "-Text", "-Examiner" }.FirstOrDefault(k => string.Equals(k, a, StringComparison.OrdinalIgnoreCase));
                if (known == null) return Fail("Unknown argument: " + a);
                // A switch without its value stops here, so a set request never falls through to a listing.
                if (i + 1 >= args.Length) return Fail(known + " needs a value.");
                var value = args[++i];
                switch (known)
                {
                    case "-Key": key = value; break;
                    case "-Artifact": artifact = value; break;
                    case "-Row": if (!int.TryParse(value, out row) || row < 1) return Fail("-Row needs a data row number (1 is the first row after the header)."); break;
                    case "-Status": status = value; break;
                    case "-Text": text = value; break;
                    default: examiner = value; break;
                }
            }
            FotonPackage pkg;
            try { pkg = FotonPackage.Open(args[1]); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is InvalidDataException || ex is ArgumentException || ex is NotSupportedException)
            {
                return Fail("Cannot open the package: " + ex.Message);
            }
            bool setting = key != null || artifact != null || status != null || text != null || examiner != null || row > 0;
            try
            {
                if (!setting) return List(pkg.CaseRoot, json);
                if (json) return Fail("-Json lists notes; it does not go with -Key, -Artifact, -Status, or -Text.");
                return Set(pkg.CaseRoot, key, artifact, row, status, text, examiner);
            }
            catch (InvalidDataException ex) { return Fail("Notes not read: " + ex.Message); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException) { return Fail("Note not saved: " + ex.Message); }
        }

        static int Fail(string message)
        {
            Console.Error.WriteLine(TextFile.OneLine(message));
            return 1;
        }

        static int List(string caseRoot, bool json)
        {
            var review = ExaminerNotes.Review(caseRoot);
            if (json) { Console.WriteLine(Json.Indented(review)); return 0; }
            var log = new StatusLog();
            Banner.Write(log, Banner.Kind.Workstation);
            log.WriteConsole("Examiner notes (" + ExaminerNotes.About + ")");
            log.WriteConsole("  " + Path.Combine("analysis", ExaminerNotes.FileName));
            log.WriteConsole("");
            var reviewed = review.Findings.Count(f => f.Status != NoteStatus.NotReviewed);
            log.WriteConsole(review.FindingsSource.Length == 0
                ? "Findings: none in this package yet (run foton analyze)."
                : $"Findings ({review.FindingsSource}): {review.Findings.Count}, {reviewed} with a status");
            foreach (var f in review.Findings)
            {
                log.WriteConsole($"  {f.Severity,-7} {NoteStatus.Label(f.Status),-13} {f.Key.Substring(0, 12)}  {TextFile.OneLine(f.Title)}");
                if (f.Text.Length > 0) log.WriteConsole($"          note ({Who(f.Examiner, f.UpdatedUtc)}): {TextFile.OneLine(f.Text)}");
            }
            if (review.NotInLatestFindings.Count > 0)
            {
                log.WriteConsole("");
                log.WriteConsole($"Notes on findings the latest analyze does not produce: {review.NotInLatestFindings.Count}");
                foreach (var n in review.NotInLatestFindings) WriteNote(log, n, n.Key.Substring(0, Math.Min(12, n.Key.Length)) + "  ");
            }
            if (review.Rows.Count > 0)
            {
                log.WriteConsole("");
                log.WriteConsole($"Row notes (set with -Artifact and -Row): {review.Rows.Count}");
                foreach (var r in review.Rows) WriteNote(log, r.Note, $"{r.Note.Artifact} row {r.Note.Row} ({r.State})  ");
            }
            return 0;
        }

        static void WriteNote(StatusLog log, ExaminerNote n, string where)
        {
            log.WriteConsole($"  {NoteStatus.Label(n.Status),-13} {where}{TextFile.OneLine(n.Label)}");
            if (n.Text.Length > 0) log.WriteConsole($"          note ({Who(n.Examiner, n.UpdatedUtc)}): {TextFile.OneLine(n.Text)}");
        }

        static string Who(string examiner, string updatedUtc) =>
            (examiner.Trim().Length > 0 ? TextFile.OneLine(examiner) + ", " : "") + updatedUtc + " UTC";

        static int Set(string caseRoot, string? key, string? artifact, int row, string? statusText, string? text, string? examiner)
        {
            if ((key == null) == (artifact == null)) return Fail("Give either -Key (a finding or note key from foton notes) or -Artifact with -Row.");
            if (artifact != null && row < 1) return Fail("-Artifact needs -Row.");
            if (statusText == null && text == null) return Fail("Give -Status, -Text, or both.");
            string status = "";
            if (statusText != null && !NoteStatus.TryParse(statusText, out status))
                return Fail("-Status must be one of: " + string.Join(", ", NoteStatus.All.Select(NoteStatus.Label)) + ".");
            var notes = ExaminerNotes.Load(caseRoot);
            ExaminerNote note;
            if (key != null)
            {
                var found = Resolve(caseRoot, notes, key, out var problem);
                if (found == null) return Fail(problem);
                note = found;
            }
            else
            {
                var cells = ExaminerNotes.ReadRow(caseRoot, artifact!, row);
                if (cells == null) return Fail($"{artifact} has no data row {row} in this package (or is not a plain file inside it).");
                var rowKey = ExaminerNotes.RowKey(artifact!, row);
                var existing = notes.Notes.FirstOrDefault(n => n.Kind == ExaminerNote.RowKind && string.Equals(n.Key, rowKey, StringComparison.OrdinalIgnoreCase));
                note = existing ?? new ExaminerNote { Kind = ExaminerNote.RowKind, Key = rowKey, Artifact = artifact!, Row = row };
                note.RowSha256 = ExaminerNotes.RowSha256(cells);
                note.Label = ExaminerNotes.RowLabel(cells);
            }
            if (statusText != null) note.Status = status;
            else if (note.Status.Length == 0) note.Status = NoteStatus.NotReviewed;
            if (text != null) note.Text = text;
            note.Examiner = examiner ?? (note.Examiner.Length > 0 ? note.Examiner : ChainOfCustody.ReadHeader(caseRoot).Examiner ?? "");
            var stored = ExaminerNotes.Set(caseRoot, note);
            Console.WriteLine(stored == null
                ? "Note removed (Not reviewed, no text)."
                : $"Saved: {NoteStatus.Label(stored.Status)}  {TextFile.OneLine(stored.Label)}");
            // For a ZIP this is the -extracted folder beside it, where every verb writes its outputs.
            Console.WriteLine("Notes file: " + ExaminerNotes.PathOf(caseRoot));
            return 0;
        }

        /// <summary>A note for a key or unique key prefix (at least 8 characters): a current finding, or an existing note.</summary>
        static ExaminerNote? Resolve(string caseRoot, ExaminerNotesFile notes, string key, out string problem)
        {
            problem = "";
            if (key.Length < 8) { problem = "-Key needs at least 8 characters of a key that foton notes lists."; return null; }
            var current = ExaminerNotes.LatestFindings(caseRoot).Rows
                .Select(r => new { Key = ExaminerNotes.FindingKey(r), Row = r })
                .Where(f => f.Key.StartsWith(key, StringComparison.OrdinalIgnoreCase))
                .GroupBy(f => f.Key, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
            var noted = notes.Notes.Where(n => n.Key.StartsWith(key, StringComparison.OrdinalIgnoreCase)).ToList();
            var keys = new HashSet<string>(current.Select(c => c.Key).Concat(noted.Select(n => n.Key)), StringComparer.OrdinalIgnoreCase);
            if (keys.Count == 0) { problem = "No finding or note has a key starting " + key + "."; return null; }
            if (keys.Count > 1) { problem = $"{keys.Count} keys start with {key}; give more of it."; return null; }
            var existing = noted.FirstOrDefault();
            if (existing != null) return existing;
            var f = current[0].Row;
            string V(string k) => f.TryGetValue(k, out var v) ? v ?? "" : "";
            return new ExaminerNote { Kind = ExaminerNote.FindingKind, Key = current[0].Key, Label = V("Title"), Artifact = V("Artifact") };
        }
    }
}
