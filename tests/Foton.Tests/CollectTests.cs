using System;
using System.IO;
using System.Linq;
using Foton.Analyze;
using Foton.Collect;
using Foton.Core;
using Xunit;

namespace Foton.Tests
{
    /// <summary>The collect orchestrator on this host (no categories are needed to exercise the package lifecycle).</summary>
    public class CollectTests
    {
        static StatusLog Quiet() => new StatusLog(new StringWriter());

        [Fact]
        public void A_run_writes_a_hashed_case_package_whose_findings_a_workstation_reproduces()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, Examiner = "examiner", CaseNumber = "CASE-0001" }, Quiet());
                var r = CollectRun.Run(s, only: new string[0]);

                var col = Path.Combine(r.CaseRoot, "00_Collection");
                foreach (var f in new[] { "chain_of_custody.txt", "collection_coverage.json", "collection_manifest.csv", "collection.log", "findings.csv", "hashes.csv", "hashes.txt" })
                    Assert.True(File.Exists(Path.Combine(col, f)), f);
                Assert.True(File.Exists(r.ReportPath));
                Assert.Contains("CASE-0001", File.ReadAllText(Path.Combine(col, "chain_of_custody.txt")));
                if (Categories.InOrder.Count < CaseCategories.All.Count - 1)
                {
                    Assert.Contains("does not collect yet", File.ReadAllText(Path.Combine(col, "collection.log")));
                    Assert.NotEmpty(r.NotCollected);
                }
                Assert.Contains(Csv.Read(Path.Combine(col, "hashes.csv")), h => h["RelativePath"] == "Foton_Report.html");
                Assert.Equal(r.ZipPath, r.CaseRoot + ".zip");
                Assert.True(File.Exists(r.CaseRoot + "_PACKAGE_HASH.txt"));
                Assert.Equal(Hashing.Sha256Hex(r.ZipPath!), r.ZipSha256);

                // Endpoint analysis reads the written case, so the workstation (given the same empty pattern list) agrees.
                Assert.Contains(s.Findings, f => f.Title == "Suspicious-command pattern matching did not run");
                var again = Analyzer.RunPackage(r.CaseRoot, Quiet(), new string[0]);
                Assert.Equal(File.ReadAllBytes(Path.Combine(col, "findings.csv")), File.ReadAllBytes(again.FindingsPath!));
            }
        }

        [Fact]
        public void NoZip_leaves_only_the_case_folder()
        {
            using (var t = new TempDir())
            {
                var s = CollectRun.NewSession(new SessionOptions { OutputPath = t.Path, NoZip = true }, Quiet());
                var r = CollectRun.Run(s, only: new string[0]);
                Assert.Null(r.ZipPath);
                Assert.Single(Directory.GetFileSystemEntries(t.Path));
            }
        }
    }
}
