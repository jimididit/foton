using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Foton.Core;

namespace Foton.Package
{
    /// <summary>An examiner's review status for a finding or an artifact row.</summary>
    public static class NoteStatus
    {
        public const string NotReviewed = "NotReviewed", Reviewed = "Reviewed", Relevant = "Relevant", NotRelevant = "NotRelevant", FollowUp = "FollowUp";
        public static readonly string[] All = { NotReviewed, Reviewed, Relevant, NotRelevant, FollowUp };

        public static string Label(string status) =>
            status == NotReviewed ? "Not reviewed" : status == NotRelevant ? "Not relevant" : status == FollowUp ? "Follow up" : status;

        /// <summary>A status from its name or label, ignoring case and spaces ("follow up", "FollowUp").</summary>
        public static bool TryParse(string? text, out string status)
        {
            var t = (text ?? "").Replace(" ", "");
            status = All.FirstOrDefault(s => string.Equals(s, t, StringComparison.OrdinalIgnoreCase)) ?? "";
            return status.Length > 0;
        }
    }

    /// <summary>One examiner note: on a finding (by its content) or on a row of a package CSV (by artifact and row).</summary>
    public sealed class ExaminerNote
    {
        public const string FindingKind = "Finding", RowKind = "Row";
        /// <summary>Finding or Row.</summary>
        public string Kind { get; set; } = FindingKind;
        /// <summary>Finding: SHA-256 of its content (ExaminerNotes.FindingKey). Row: artifact#row (ExaminerNotes.RowKey).</summary>
        public string Key { get; set; } = "";
        /// <summary>The finding's title, or a short summary of the row, as it read when the note was written.</summary>
        public string Label { get; set; } = "";
        /// <summary>The artifact relative to the case root (the finding's cited artifact, or the row's file).</summary>
        public string Artifact { get; set; } = "";
        /// <summary>Row notes: the data row (1 is the first after the header).</summary>
        public int Row { get; set; }
        /// <summary>Row notes: SHA-256 of the row's cells when noted, so a row that later reads differently is flagged.</summary>
        public string RowSha256 { get; set; } = "";
        public string Status { get; set; } = NoteStatus.NotReviewed;
        public string Text { get; set; } = "";
        public string Examiner { get; set; } = "";
        public string UpdatedUtc { get; set; } = "";
    }

    public sealed class ExaminerNotesFile
    {
        public string NotesSchemaVersion { get; set; } = FotonVersion.NotesSchema;
        public string About { get; set; } = ExaminerNotes.About;
        public List<ExaminerNote> Notes { get; } = new List<ExaminerNote>();
    }

    /// <summary>The findings a package currently has: the workstation analyze, else the collector's.</summary>
    public sealed class CurrentFindings
    {
        /// <summary>The findings.csv read, relative to the case root, or empty when there is none.</summary>
        public string Source { get; set; } = "";
        public List<Dictionary<string, string?>> Rows { get; } = new List<Dictionary<string, string?>>();
    }

    /// <summary>A current finding with its review status (Not reviewed when it has no note).</summary>
    public sealed class ReviewedFinding
    {
        public string Key { get; set; } = "";
        public string Severity { get; set; } = "";
        public string Category { get; set; } = "";
        public string Title { get; set; } = "";
        public string Artifact { get; set; } = "";
        public string Status { get; set; } = NoteStatus.NotReviewed;
        public string Text { get; set; } = "";
        public string Examiner { get; set; } = "";
        public string UpdatedUtc { get; set; } = "";
    }

    /// <summary>A row note and whether its row still reads as it did when noted.</summary>
    public sealed class ReviewedRow
    {
        public ExaminerNote Note { get; set; } = new ExaminerNote();
        /// <summary>unchanged, changed since noted, row not found, or unreadable: ...</summary>
        public string State { get; set; } = "";
    }

    /// <summary>Every current finding with its status, the notes on findings no longer produced, and the row notes.</summary>
    public sealed class NotesReview
    {
        public string About { get; set; } = ExaminerNotes.About;
        public string FindingsSource { get; set; } = "";
        public List<ReviewedFinding> Findings { get; } = new List<ReviewedFinding>();
        /// <summary>Notes on findings the latest analyze does not produce (kept, never dropped).</summary>
        public List<ExaminerNote> NotInLatestFindings { get; } = new List<ExaminerNote>();
        public List<ReviewedRow> Rows { get; } = new List<ReviewedRow>();
    }

    /// <summary>
    /// analysis\examiner_notes.json: review status and notes an examiner records about findings and artifact rows. It is
    /// examiner input, kept apart from findings.csv and the automated report and labelled as such wherever it is shown.
    /// Notes are never dropped: a note whose finding a later analyze no longer produces stays, listed as such. Reads
    /// refuse a damaged file rather than overwrite it, so an examiner's work is never silently replaced.
    /// </summary>
    public static class ExaminerNotes
    {
        public const string FileName = "examiner_notes.json";
        public const string About = "Examiner input: review status and notes recorded by an examiner. Not produced by Foton's analysis and not findings.";
        const long MaxFileBytes = 16L * 1024 * 1024;
        public const int MaxText = 20000, MaxLabel = 300, MaxExaminer = 200;
        // The Viewer's caps (ArtifactReader.ReadCsv), so a row hashes the same however it was read.
        const int MaxFieldChars = 32768, MaxFields = 2000;

        public static string PathOf(string caseRoot) => Path.Combine(caseRoot, "analysis", FileName);

        /// <summary>The notes of a case; an empty set when there is no file. Throws InvalidDataException for a file that cannot be read as notes.</summary>
        public static ExaminerNotesFile Load(string caseRoot)
        {
            var file = new ExaminerNotesFile();
            var path = PathOf(caseRoot);
            if (!File.Exists(path)) return file;
            if (!CaseIndex.Plain(caseRoot, Path.Combine("analysis", FileName))) throw new InvalidDataException("examiner_notes.json or analysis is a link or junction; not read");
            if (new FileInfo(path).Length > MaxFileBytes) throw new InvalidDataException("examiner_notes.json is larger than " + MaxFileBytes + " bytes");
            object? root;
            try { root = Json.Parse(File.ReadAllText(path, Encoding.UTF8).TrimStart('\uFEFF')); }
            catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException) { throw new InvalidDataException("examiner_notes.json is not valid JSON: " + ex.Message); }
            if (!(root is IDictionary<string, object> map)) throw new InvalidDataException("examiner_notes.json is not a notes file");
            var schema = Str(map, "NotesSchemaVersion");
            if (schema.Split('.')[0] != FotonVersion.NotesSchema.Split('.')[0]) throw new InvalidDataException("examiner_notes.json has notes schema " + schema + "; this Foton reads " + FotonVersion.NotesSchema);
            file.NotesSchemaVersion = FotonVersion.NotesSchema;
            if (map.TryGetValue("Notes", out var list) && list != null)
            {
                if (!(list is IEnumerable items) || list is string) throw new InvalidDataException("examiner_notes.json: Notes is not a list");
                int i = 0;
                foreach (var item in items)
                {
                    i++;
                    if (!(item is IDictionary<string, object> n)) throw new InvalidDataException($"examiner_notes.json: note {i} is not an object");
                    var note = new ExaminerNote
                    {
                        Kind = Str(n, "Kind"), Key = Str(n, "Key"), Label = Str(n, "Label"), Artifact = Str(n, "Artifact"),
                        Row = n.TryGetValue("Row", out var r) && r is int row ? row : 0, RowSha256 = Str(n, "RowSha256"),
                        Status = Str(n, "Status"), Text = Str(n, "Text"), Examiner = Str(n, "Examiner"), UpdatedUtc = Str(n, "UpdatedUtc"),
                    };
                    var problem = Problem(note);
                    if (problem != null) throw new InvalidDataException($"examiner_notes.json: note {i}: {problem}");
                    file.Notes.Add(note);
                }
            }
            return file;
        }

        static string Str(IDictionary<string, object> map, string key) =>
            map.TryGetValue(key, out var v) && v != null ? Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" : "";

        /// <summary>Why a note cannot be stored, or null.</summary>
        static string? Problem(ExaminerNote n)
        {
            if (n.Kind != ExaminerNote.FindingKind && n.Kind != ExaminerNote.RowKind) return "Kind must be Finding or Row";
            if (n.Key.Length == 0) return "no Key";
            if (!NoteStatus.All.Contains(n.Status)) return "unknown Status " + TextFile.OneLine(n.Status);
            if (n.Kind == ExaminerNote.RowKind && (n.Row < 1 || n.Artifact.Length == 0)) return "a row note needs Artifact and Row";
            if (n.Text.Length > MaxText) return "Text is longer than " + MaxText + " characters";
            return null;
        }

        /// <summary>
        /// Adds or replaces the note with the same Kind and Key (re-reading the file first, so a note saved meanwhile by
        /// another window or foton notes is kept) and stamps it with the current UTC time. A note set back to Not
        /// reviewed with no text is removed. Returns the stored note, or null when removed.
        /// </summary>
        public static ExaminerNote? Set(string caseRoot, ExaminerNote note)
        {
            note.Label = Cut(TextFile.OneLine(note.Label).Trim(), MaxLabel);
            note.Examiner = Cut(TextFile.OneLine(note.Examiner).Trim(), MaxExaminer);
            note.Artifact = TextFile.OneLine(note.Artifact).Trim().Replace('/', '\\');
            note.Text = (note.Text ?? "").Replace("\r\n", "\n").Replace("\n", "\r\n").Trim();
            note.UpdatedUtc = FotonTime.Format(DateTime.UtcNow);
            var problem = Problem(note);
            if (problem != null) throw new ArgumentException(problem);
            var file = Load(caseRoot);
            file.Notes.RemoveAll(n => n.Kind == note.Kind && string.Equals(n.Key, note.Key, StringComparison.OrdinalIgnoreCase));
            var removed = note.Status == NoteStatus.NotReviewed && note.Text.Length == 0;
            if (!removed) file.Notes.Add(note);
            Save(caseRoot, file);
            return removed ? null : note;
        }

        static string Cut(string s, int max) => s.Length > max ? s.Substring(0, max) : s;

        /// <summary>Writes the notes sorted (Kind, then Key) through a temporary file, so a failed write never leaves half a file.</summary>
        public static void Save(string caseRoot, ExaminerNotesFile file)
        {
            if (!CaseIndex.Plain(caseRoot, Path.Combine("analysis", FileName))) throw new IOException("analysis or examiner_notes.json is a link or junction; notes not written");
            var dir = Path.Combine(caseRoot, "analysis");
            Directory.CreateDirectory(dir);
            var sorted = new ExaminerNotesFile();
            sorted.Notes.AddRange(file.Notes.OrderBy(n => n.Kind, StringComparer.Ordinal).ThenBy(n => n.Key, StringComparer.OrdinalIgnoreCase));
            var path = PathOf(caseRoot);
            var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllText(temp, Json.Indented(sorted) + "\r\n", TextFile.Utf8NoBom);
                if (File.Exists(path)) File.Replace(temp, path, null);
                else File.Move(temp, path);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
        }

        /// <summary>A finding's note key: SHA-256 of its category, title, artifact, and observation, so a re-analyze that produces the same finding finds its note.</summary>
        public static string FindingKey(string? category, string? title, string? artifact, string? observation) =>
            Sha256(new[] { category, title, artifact, observation });

        public static string FindingKey(IReadOnlyDictionary<string, string?> row)
        {
            string V(string k) => row.TryGetValue(k, out var v) ? v ?? "" : "";
            return FindingKey(V("Category"), V("Title"), V("Artifact"), V("Observation"));
        }

        /// <summary>A row note's key: the artifact (backslashes) and its data row.</summary>
        public static string RowKey(string artifact, int row) => artifact.Replace('/', '\\') + "#" + row.ToString(CultureInfo.InvariantCulture);

        /// <summary>SHA-256 of a row's cells (length-prefixed, so cell boundaries count).</summary>
        public static string RowSha256(IReadOnlyList<string> cells) => Sha256(cells);

        static string Sha256(IEnumerable<string?> parts)
        {
            var sb = new StringBuilder();
            foreach (var p in parts) sb.Append((p ?? "").Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(p ?? "").Append('|');
            using (var sha = SHA256.Create())
                return string.Concat(sha.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString())).Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
        }

        /// <summary>A short label for a row: its first non-empty cells.</summary>
        public static string RowLabel(IReadOnlyList<string> cells) =>
            Cut(TextFile.OneLine(string.Join("  ", cells.Where(c => !string.IsNullOrWhiteSpace(c)).Take(4).Select(c => c.Trim()))), 160);

        /// <summary>
        /// Data row <paramref name="row"/> (1-based) of a package CSV, with the Viewer's caps; null when the artifact path
        /// is not a plain file inside the case (outside it, through a link) or the file has fewer rows.
        /// </summary>
        public static List<string>? ReadRow(string caseRoot, string artifact, int row)
        {
            var rel = artifact.Replace('/', '\\');
            if (row < 1 || rel.Length == 0 || Path.IsPathRooted(rel) || rel.Contains(':') || rel.Split('\\').Any(p => p == "..")) return null;
            if (!CaseIndex.Plain(caseRoot, rel)) return null;
            var path = Path.Combine(caseRoot, rel);
            if (!File.Exists(path)) return null;
            int n = -1;
            foreach (var cells in Csv.StreamRecords(path, MaxFieldChars, MaxFields))
                if (++n == row) return cells;
            return null;
        }

        /// <summary>Whether a row note's row still reads as it did: "unchanged", "changed since noted", or "row not found".</summary>
        public static string RowState(string caseRoot, ExaminerNote note)
        {
            if (note.Kind != ExaminerNote.RowKind) return "";
            try
            {
                var cells = ReadRow(caseRoot, note.Artifact, note.Row);
                if (cells == null) return "row not found";
                return string.Equals(RowSha256(cells), note.RowSha256, StringComparison.OrdinalIgnoreCase) ? "unchanged" : "changed since noted";
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException)
            {
                return "unreadable: " + TextFile.OneLine(ex.Message);
            }
        }

        static readonly string[] SeverityOrder = { "High", "Medium", "Low", "Info" };

        /// <summary>The review of a case: current findings (most severe first) with their notes, then the other notes.</summary>
        public static NotesReview Review(string caseRoot)
        {
            var notes = Load(caseRoot);
            var current = LatestFindings(caseRoot);
            var review = new NotesReview { FindingsSource = current.Source };
            var byKey = notes.Notes.Where(n => n.Kind == ExaminerNote.FindingKind).GroupBy(n => n.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string V(Dictionary<string, string?> r, string k) => r.TryGetValue(k, out var v) ? v ?? "" : "";
            int Rank(string severity) { var i = Array.IndexOf(SeverityOrder, severity); return i < 0 ? SeverityOrder.Length : i; }
            foreach (var r in current.Rows.Select((row, i) => new { row, i }).OrderBy(x => Rank(V(x.row, "Severity"))).ThenBy(x => x.i).Select(x => x.row))
            {
                var key = FindingKey(r);
                seen.Add(key);
                var f = new ReviewedFinding { Key = key, Severity = V(r, "Severity"), Category = V(r, "Category"), Title = V(r, "Title"), Artifact = V(r, "Artifact") };
                if (byKey.TryGetValue(key, out var n)) { f.Status = n.Status; f.Text = n.Text; f.Examiner = n.Examiner; f.UpdatedUtc = n.UpdatedUtc; }
                review.Findings.Add(f);
            }
            review.NotInLatestFindings.AddRange(byKey.Values.Where(n => !seen.Contains(n.Key)));
            foreach (var n in notes.Notes.Where(n => n.Kind == ExaminerNote.RowKind))
                review.Rows.Add(new ReviewedRow { Note = n, State = RowState(caseRoot, n) });
            return review;
        }

        /// <summary>The latest findings: analysis\findings.csv (workstation analyze), else the collector's 00_Collection\findings.csv.</summary>
        public static CurrentFindings LatestFindings(string caseRoot)
        {
            var current = new CurrentFindings();
            foreach (var rel in new[] { Path.Combine("analysis", "findings.csv"), Path.Combine(CaseTree.CollectionFolder, "findings.csv") })
            {
                var path = Path.Combine(caseRoot, rel);
                if (!File.Exists(path)) continue;
                current.Source = rel;
                current.Rows.AddRange(Csv.Read(path));
                break;
            }
            return current;
        }
    }
}
