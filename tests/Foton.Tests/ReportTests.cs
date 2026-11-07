using System.Collections.Generic;
using System.IO;
using Foton.Baseline.Compare;
using Foton.Core;
using Foton.Report;
using Xunit;

namespace Foton.Tests
{
    /// <summary>Report chrome and escaping are identical to 1.38.x (golden files).</summary>
    public class ReportTests
    {
        [Fact]
        public void Chrome_is_byte_identical_to_the_PowerShell_here_strings()
        {
            Assert.Equal(TestPaths.GoldenText("nav.css"), ReportChrome.NavCss);
            Assert.Equal(TestPaths.GoldenText("navbar.html"), ReportChrome.NavBarHtml);
            Assert.Equal(TestPaths.GoldenText("nav.js"), ReportChrome.NavScript);
            Assert.Equal(TestPaths.GoldenText("mark.svg"), ReportChrome.MarkSvg);
        }

        [Fact]
        public void Encode_matches_ConvertTo_FotonSafeHtml()
        {
            foreach (var line in TestPaths.GoldenText("safehtml.tsv").Split('\n'))
            {
                var parts = line.Split('\t');
                Assert.Equal(parts[1], Html.Encode(parts[0]));
            }
            Assert.Equal("", Html.Encode(null));
        }

        [Theory]
        [InlineData("baseline-snapshot.html", 200)]
        [InlineData("baseline-snapshot-cap1.html", 1)]
        public void Baseline_snapshot_html_is_byte_identical_to_1_38(string golden, int maxRows)
        {
            using (var t = new TempDir())
            {
                File.Copy(TestPaths.Golden("baseline-dif.json"), t.File("dif.json"));
                var html = BaselineSnapshotReport.Write(t.File("dif.json"), t.File("out.html"), maxRows);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden(golden)), File.ReadAllBytes(html));
            }
        }

        [Theory]
        [InlineData("baseline-dif.json", "compare-temporal.html", 400)]
        [InlineData("baseline-dif-fleet.json", "compare-fleet.html", 400)]
        [InlineData("baseline-dif.json", "compare-temporal-cap2.html", 2)]
        public void Baseline_compare_html_is_byte_identical_to_1_38(string difGolden, string golden, int maxRows)
        {
            using (var t = new TempDir())
            {
                File.Copy(TestPaths.Golden("baseline-ref.json"), t.File("ref.json"));
                File.Copy(TestPaths.Golden(difGolden), t.File("dif.json"));
                var r = BaselineComparer.Run(t.File("ref.json"), t.File("dif.json"), new StatusLog(new StringWriter()), writeCsv: false);
                var html = BaselineCompareReport.Write(r, t.File("out.html"), maxRows);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden(golden)), File.ReadAllBytes(html));
            }
        }

        [Fact]
        public void Report_cells_from_a_baseline_are_escaped()
        {
            var doc = new BaselineDocument { Header = new BaselineHeader { Hostname = "<script>x</script>" } };
            doc.Providers.Add(new ProviderMeta { RecordType = "Service", IdentityFields = new[] { "Name" }, FalsePositives = "a & b" });
            doc.Records["Service"] = new List<Dictionary<string, object?>> { new Dictionary<string, object?> { ["Name"] = "\"><img src=x onerror=alert(1)>" } };
            var html = BaselineSnapshotReport.Render(doc);
            Assert.DoesNotContain("<script>x", html);
            Assert.DoesNotContain("<img", html);
            Assert.Contains("&lt;img src=x onerror=alert(1)&gt;", html);
            Assert.Contains("a &amp; b", html);
        }

        [Fact]
        public void SectionId_matches_Get_FotonReportSectionId()
        {
            foreach (var line in TestPaths.GoldenText("sectionid.tsv").Split('\n'))
            {
                var parts = line.Split('\t');
                Assert.Equal(parts[1], Html.SectionId(parts[0]));
            }
        }
    }
}
