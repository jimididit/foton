using System.IO;
using System.Linq;
using Foton.Core;
using Xunit;

namespace Foton.Tests
{
    /// <summary>Bytes on disk match what 1.38.x wrote (golden files from tests\golden\Update-Golden.ps1).</summary>
    public class WriterParityTests
    {
        public sealed class GoldenRow
        {
            public string Name { get; set; } = "";
            public string Quote { get; set; } = "";
            public string Comma { get; set; } = "";
            public string Newline { get; set; } = "";
            public string Empty { get; set; } = "";
            public string? Null { get; set; }
            public bool Flag { get; set; }
            public int Count { get; set; }
            public string Unicode { get; set; } = "";
        }

        static GoldenRow[] Rows() => new[]
        {
            new GoldenRow { Name = "plain", Quote = "say \"hi\"", Comma = "a,b", Newline = "line1\r\nline2", Empty = "", Null = null, Flag = true, Count = 42, Unicode = "ünï ✓" },
            new GoldenRow { Name = "second", Quote = "'", Comma = ",", Newline = "\n", Empty = "", Null = null, Flag = false, Count = -1, Unicode = "" },
        };

        [Fact]
        public void Csv_write_matches_Export_Csv_byte_for_byte()
        {
            using (var t = new TempDir())
            {
                var path = t.File("export.csv");
                Csv.Write(path, Rows());
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden("export.csv")), File.ReadAllBytes(path));
            }
        }

        [Fact]
        public void Csv_read_round_trips_an_Export_Csv_file()
        {
            var rows = Csv.Read(TestPaths.Golden("export.csv"));
            Assert.Equal(2, rows.Count);
            Assert.Equal("say \"hi\"", rows[0]["Quote"]);
            Assert.Equal("a,b", rows[0]["Comma"]);
            Assert.Equal("line1\r\nline2", rows[0]["Newline"]);
            Assert.Equal("", rows[0]["Null"]);
            Assert.Equal("True", rows[0]["Flag"]);
            Assert.Equal("ünï ✓", rows[0]["Unicode"]);
            Assert.Equal("\n", rows[1]["Newline"]);
            Assert.Equal("-1", rows[1]["count"]); // column names are case-insensitive, as in PowerShell
        }

        [Fact]
        public void Csv_read_skips_a_TYPE_line_and_pads_short_rows()
        {
            using (var t = new TempDir())
            {
                var p = t.File("t.csv");
                File.WriteAllText(p, "#TYPE System.Management.Automation.PSCustomObject\r\n\"A\",\"B\",\"C\"\r\n\"1\",\"2\"\r\n\r\n");
                var rows = Csv.Read(p);
                Assert.Single(rows);
                Assert.Equal("2", rows[0]["B"]);
                Assert.Null(rows[0]["C"]);
            }
        }

        [Fact]
        public void Text_files_match_Out_File_UTF8()
        {
            using (var t = new TempDir())
            {
                var lines = t.File("lines.txt");
                TextFile.WriteLines(lines, new[] { "first line", "second line" });
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden("outfile-lines.txt")), File.ReadAllBytes(lines));

                var single = t.File("single.txt");
                TextFile.Write(single, "single string");
                TextFile.AppendLine(single, "appended");
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden("outfile-single.txt")), File.ReadAllBytes(single));
            }
        }

        public sealed class Copy : ICopyRow
        {
            public string SourcePath { get; set; } = "";
            public string Status { get; set; } = "";
            public string Note { get; set; } = "";
        }

        public sealed class DataRow
        {
            public string Status { get; set; } = "";
            public string Name { get; set; } = "";
        }

        [Fact]
        public void Copy_task_status_matches_1_38()
        {
            var cases = new System.Collections.Generic.Dictionary<string, object>
            {
                ["none"] = new Copy[0],
                ["data"] = new[] { new DataRow { Status = "Error", Name = "pnp device" } },
                ["ok"] = new[] { new Copy { SourcePath = "a", Status = "Copied" }, new Copy { SourcePath = "b", Status = "Missing" } },
                ["partial"] = new[] { new Copy { SourcePath = "a", Status = "Copied" }, new Copy { SourcePath = @"C:\x", Status = "CopyError", Note = "in use" } },
                ["failed"] = new[] { new Copy { SourcePath = @"C:\h", Status = "SaveError", Note = "denied" }, new Copy { SourcePath = "b", Status = "CappedSkip" } },
            };
            foreach (var line in TestPaths.GoldenText("copystatus.tsv").Split('\n'))
            {
                var parts = line.Split('\t');
                var r = CopyTaskStatus.Evaluate(cases[parts[0]]);
                Assert.Equal(parts[1], r.Status);
                Assert.Equal(parts[2], r.Message);
            }
        }
    }
}
