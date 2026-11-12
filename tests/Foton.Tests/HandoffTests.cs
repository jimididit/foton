using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Analyze.Handoff;
using Foton.Core;
using Foton.Package;
using Xunit;

namespace Foton.Tests
{
    public class HandoffTests
    {
        static readonly DateTime At = new DateTime(2026, 11, 12, 12, 0, 0, DateTimeKind.Utc);

        /// <summary>A hashed case with two findings (one with markup in its title), custody, and a finding note.</summary>
        static string Case(TempDir t)
        {
            var c = t.File("Foton_HOST_20261110-120000Z");
            var col = Path.Combine(c, CaseTree.CollectionFolder);
            Directory.CreateDirectory(col);
            Directory.CreateDirectory(Path.Combine(c, "01_System"));
            var os = Path.Combine(c, "01_System", "os.json");
            File.WriteAllText(os, "{\"Caption\":\"Windows\"}");
            File.WriteAllText(Path.Combine(col, "chain_of_custody.txt"), "Case Number : CASE-0001\r\nExaminer : Examiner A\r\nParameters Used:\r\n");
            Csv.Write(Path.Combine(col, "hashes.csv"), new[] { new HashRow { RelativePath = @"01_System\os.json", SizeBytes = new FileInfo(os).Length, SHA256 = Hashing.Sha256Hex(os) } });
            Directory.CreateDirectory(Path.Combine(c, "analysis"));
            Csv.Write(Path.Combine(c, "analysis", "findings.csv"), new List<Finding>
            {
                new Finding { Severity = "High", Category = "Persistence", Title = "Task <script>alert(1)</script>", Observation = "o", Artifact = "a.csv", Tier = 1 },
                new Finding { Severity = "Info", Category = "Coverage", Title = "Standard user", Observation = "o2" },
            });
            var key = ExaminerNotes.FindingKey("Persistence", "Task <script>alert(1)</script>", "a.csv", "o");
            ExaminerNotes.Set(c, new ExaminerNote { Kind = ExaminerNote.FindingKind, Key = key, Label = "Task", Status = NoteStatus.Relevant, Text = "Owner confirmed <b>no</b>", Examiner = "Examiner B" });
            return c;
        }

        [Fact]
        public void A_handoff_holds_findings_notes_custody_and_a_page_every_file_hashed()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                var run = HandoffExport.Run(c, new StatusLog(new StringWriter()), t.File("out"), null, At);
                Assert.True(run.Verified);
                Assert.Equal(Path.Combine(t.File("out"), "Foton_Handoff_HOST_20261110-120000Z_20261112-120000Z"), run.Folder);
                Assert.Equal(new[] { "findings.csv", ExaminerNotes.FileName, HandoffExport.NotesCsvName, @"package\chain_of_custody.txt", @"package\hashes.csv", HandoffExport.HtmlName, HandoffExport.ReadmeName }, run.Files);

                // Every listed file matches SHA256SUMS.txt, and nothing else is in the folder.
                var sums = File.ReadAllLines(Path.Combine(run.Folder, HandoffExport.SumsName));
                Assert.Equal(run.Files.Count, sums.Length);
                foreach (var line in sums)
                {
                    var parts = line.Split(new[] { " *" }, 2, StringSplitOptions.None);
                    Assert.Equal(parts[0], Hashing.Sha256Hex(Path.Combine(run.Folder, parts[1].Replace('/', '\\'))).ToLowerInvariant());
                }
                Assert.Equal(run.Files.Count + 1, Directory.GetFiles(run.Folder, "*", SearchOption.AllDirectories).Length);

                var html = File.ReadAllText(Path.Combine(run.Folder, HandoffExport.HtmlName));
                Assert.DoesNotContain("<script>alert", html);
                Assert.Contains("Task &lt;script&gt;alert(1)&lt;/script&gt;", html);
                Assert.Contains("Owner confirmed &lt;b&gt;no&lt;/b&gt;", html);
                Assert.Contains("examiner input", html);
                var readme = File.ReadAllText(Path.Combine(run.Folder, HandoffExport.ReadmeName));
                Assert.Contains("Package hashes.csv SHA-256: " + Hashing.Sha256Hex(Path.Combine(c, CaseTree.CollectionFolder, "hashes.csv")).ToLowerInvariant(), readme);
                Assert.Contains("Case number: CASE-0001", readme);
                Assert.Contains("1 relevant", readme);
                var csv = Csv.Read(Path.Combine(run.Folder, HandoffExport.NotesCsvName));
                Assert.Equal(new[] { "Relevant", "Not reviewed" }, csv.Select(r => r["Status"]));

                Assert.Throws<IOException>(() => HandoffExport.Run(c, new StatusLog(new StringWriter()), t.File("out"), null, At));
            }
        }

        [Fact]
        public void A_package_that_does_not_verify_is_said_so_and_unreadable_notes_stop_the_handoff()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                File.WriteAllText(Path.Combine(c, "01_System", "os.json"), "{\"Caption\":\"changed\"}");
                var run = HandoffExport.Run(c, new StatusLog(new StringWriter()), t.File("out"), null, At);
                Assert.False(run.Verified);
                Assert.Contains("DID NOT VERIFY", File.ReadAllText(Path.Combine(run.Folder, HandoffExport.ReadmeName)));

                File.WriteAllText(ExaminerNotes.PathOf(c), "{ damaged");
                Assert.Throws<InvalidDataException>(() => HandoffExport.Run(c, new StatusLog(new StringWriter()), t.File("out2"), null, At));
                Assert.False(Directory.Exists(t.File("out2")));
            }
        }

        [Fact]
        public void A_report_built_here_is_included_when_given()
        {
            using (var t = new TempDir())
            {
                var c = Case(t);
                var report = Path.Combine(c, CaseTree.ReportFileName);
                File.WriteAllText(report, "<html>built here</html>");
                var run = HandoffExport.Run(c, new StatusLog(new StringWriter()), t.File("out"), report, At);
                Assert.Contains(CaseTree.ReportFileName, run.Files);
                Assert.Equal("<html>built here</html>", File.ReadAllText(Path.Combine(run.Folder, CaseTree.ReportFileName)));
            }
        }
    }
}
