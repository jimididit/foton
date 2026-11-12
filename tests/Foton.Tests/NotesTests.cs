using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Core;
using Foton.Package;
using Xunit;

namespace Foton.Tests
{
    public class NotesTests
    {
        static string Case(TempDir t)
        {
            var c = t.File("Foton_HOST_20261110-120000Z");
            Directory.CreateDirectory(Path.Combine(c, "analysis"));
            Directory.CreateDirectory(Path.Combine(c, CaseTree.CollectionFolder));
            Csv.Write(Path.Combine(c, "analysis", "findings.csv"), new List<Finding>
            {
                new Finding { Severity = "Info", Category = "Coverage", Title = "Info one", Observation = "o1", Artifact = "a.csv" },
                new Finding { Severity = "High", Category = "Persistence", Title = "High one", Observation = "o2", Artifact = @"05_Persistence\scheduled_tasks.csv" },
            });
            File.WriteAllText(Path.Combine(c, "data.csv"), "Name,Value\r\nalpha,1\r\nbeta,2\r\n");
            return c;
        }

        static ExaminerNote FindingNote(string key, string status, string text = "") =>
            new ExaminerNote { Kind = ExaminerNote.FindingKind, Key = key, Label = "High one", Status = status, Text = text, Examiner = "Examiner A" };

        [Fact]
        public void Notes_round_trip_sorted_and_a_note_back_to_not_reviewed_with_no_text_is_removed()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                Assert.Empty(ExaminerNotes.Load(c).Notes);
                var high = ExaminerNotes.FindingKey("Persistence", "High one", @"05_Persistence\scheduled_tasks.csv", "o2");
                ExaminerNotes.Set(c, FindingNote(high, NoteStatus.Relevant, "line one\nline two"));
                var cells = ExaminerNotes.ReadRow(c, "data.csv", 2)!;
                Assert.Equal(new[] { "beta", "2" }, cells);
                ExaminerNotes.Set(c, new ExaminerNote
                {
                    Kind = ExaminerNote.RowKind, Key = ExaminerNotes.RowKey("data.csv", 2), Artifact = "data.csv", Row = 2,
                    RowSha256 = ExaminerNotes.RowSha256(cells), Label = ExaminerNotes.RowLabel(cells), Status = NoteStatus.FollowUp,
                });
                var loaded = ExaminerNotes.Load(c);
                Assert.Equal(new[] { ExaminerNote.FindingKind, ExaminerNote.RowKind }, loaded.Notes.Select(n => n.Kind));
                Assert.Equal("line one\r\nline two", loaded.Notes[0].Text);
                Assert.Equal("beta  2", loaded.Notes[1].Label);
                Assert.Matches(@"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", loaded.Notes[0].UpdatedUtc);
                Assert.Contains("Examiner input", File.ReadAllText(ExaminerNotes.PathOf(c)));

                Assert.Null(ExaminerNotes.Set(c, FindingNote(high, NoteStatus.NotReviewed)));
                Assert.Single(ExaminerNotes.Load(c).Notes);
                Assert.Empty(Directory.GetFiles(Path.Combine(c, "analysis"), "*.tmp"));
            }
        }

        [Fact]
        public void The_review_keeps_notes_on_findings_a_later_analyze_no_longer_produces()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                var high = ExaminerNotes.FindingKey("Persistence", "High one", @"05_Persistence\scheduled_tasks.csv", "o2");
                ExaminerNotes.Set(c, FindingNote(high, NoteStatus.FollowUp, "check the task"));
                var review = ExaminerNotes.Review(c);
                Assert.Equal(@"analysis\findings.csv", review.FindingsSource);
                Assert.Equal(new[] { "High one", "Info one" }, review.Findings.Select(f => f.Title));
                Assert.Equal(NoteStatus.FollowUp, review.Findings[0].Status);
                Assert.Equal(NoteStatus.NotReviewed, review.Findings[1].Status);
                Assert.Empty(review.NotInLatestFindings);

                // A re-analyze that words the observation differently is another finding; the note stays, listed apart.
                Csv.Write(Path.Combine(c, "analysis", "findings.csv"), new List<Finding>
                {
                    new Finding { Severity = "High", Category = "Persistence", Title = "High one", Observation = "o2, reworded", Artifact = @"05_Persistence\scheduled_tasks.csv" },
                });
                review = ExaminerNotes.Review(c);
                Assert.Equal(NoteStatus.NotReviewed, review.Findings.Single().Status);
                Assert.Equal("check the task", review.NotInLatestFindings.Single().Text);
            }
        }

        [Fact]
        public void A_damaged_or_newer_notes_file_is_refused_and_never_overwritten()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                var path = ExaminerNotes.PathOf(c);
                File.WriteAllText(path, "{ not json");
                Assert.Throws<InvalidDataException>(() => ExaminerNotes.Load(c));
                Assert.Throws<InvalidDataException>(() => ExaminerNotes.Set(c, FindingNote("ABCDEF0123", NoteStatus.Reviewed)));
                Assert.Equal("{ not json", File.ReadAllText(path));

                File.WriteAllText(path, "{\"NotesSchemaVersion\":\"2.0.0\",\"Notes\":[]}");
                Assert.Contains("notes schema 2.0.0", Assert.Throws<InvalidDataException>(() => ExaminerNotes.Load(c)).Message);
                File.WriteAllText(path, "{\"NotesSchemaVersion\":\"1.0.0\",\"Notes\":[{\"Kind\":\"Finding\",\"Key\":\"K\",\"Status\":\"Maybe\"}]}");
                Assert.Contains("unknown Status", Assert.Throws<InvalidDataException>(() => ExaminerNotes.Load(c)).Message);
            }
        }

        [Fact]
        public void A_row_note_says_when_its_row_reads_differently_and_paths_outside_the_case_are_not_read()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                var cells = ExaminerNotes.ReadRow(c, "data.csv", 1)!;
                var note = new ExaminerNote { Kind = ExaminerNote.RowKind, Key = ExaminerNotes.RowKey("data.csv", 1), Artifact = "data.csv", Row = 1, RowSha256 = ExaminerNotes.RowSha256(cells) };
                Assert.Equal("unchanged", ExaminerNotes.RowState(c, note));
                File.WriteAllText(Path.Combine(c, "data.csv"), "Name,Value\r\nalpha,9\r\n");
                Assert.Equal("changed since noted", ExaminerNotes.RowState(c, note));
                note.Row = 5;
                Assert.Equal("row not found", ExaminerNotes.RowState(c, note));

                File.WriteAllText(t.File("outside.csv"), "A\r\nsecret\r\n");
                Assert.Null(ExaminerNotes.ReadRow(c, @"..\outside.csv", 1));
                Assert.Null(ExaminerNotes.ReadRow(c, t.File("outside.csv"), 1));
                Assert.Null(ExaminerNotes.ReadRow(c, "data.csv", 0));
            }
        }

        [Fact]
        public void Keys_keep_field_boundaries_and_statuses_read_by_name_or_label()
        {
            Assert.NotEqual(ExaminerNotes.FindingKey("a|b", "c", "", ""), ExaminerNotes.FindingKey("a", "b|c", "", ""));
            Assert.Equal(ExaminerNotes.FindingKey("a", "b", "c", "d"), ExaminerNotes.FindingKey(new Dictionary<string, string?> { ["Category"] = "a", ["Title"] = "b", ["Artifact"] = "c", ["Observation"] = "d" }));
            Assert.NotEqual(ExaminerNotes.RowSha256(new[] { "ab", "c" }), ExaminerNotes.RowSha256(new[] { "a", "bc" }));
            Assert.Equal(@"x\y.csv#3", ExaminerNotes.RowKey("x/y.csv", 3));
            Assert.True(NoteStatus.TryParse("follow up", out var s));
            Assert.Equal(NoteStatus.FollowUp, s);
            Assert.False(NoteStatus.TryParse("maybe", out _));
            Assert.Equal("Not relevant", NoteStatus.Label(NoteStatus.NotRelevant));
        }
    }
}
