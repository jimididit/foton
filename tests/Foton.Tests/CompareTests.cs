using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Baseline.Compare;
using Foton.Core;
using Xunit;

namespace Foton.Tests
{
    /// <summary>Compare matches 1.38.x Compare-FotonBaseline output on the same inputs (golden files).</summary>
    public class CompareTests
    {
        static CompareResult RunGolden(TempDir t, string difGolden)
        {
            File.Copy(TestPaths.Golden("baseline-ref.json"), t.File("ref.json"));
            File.Copy(TestPaths.Golden(difGolden), t.File("dif.json"));
            return BaselineComparer.Run(t.File("ref.json"), t.File("dif.json"), new StatusLog(new StringWriter()));
        }

        [Theory]
        [InlineData("baseline-dif.json", "temporal", "Temporal")]
        [InlineData("baseline-dif-fleet.json", "fleet", "Fleet")]
        public void Changes_and_findings_match_1_38_byte_for_byte(string difGolden, string tag, string mode)
        {
            using (var t = new TempDir())
            {
                var r = RunGolden(t, difGolden);
                Assert.Equal(mode, r.Mode);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden($"compare-{tag}-diff.csv")), File.ReadAllBytes(t.File("baseline_diff.csv")));
                Csv.Write(t.File("findings.csv"), r.Findings);
                Assert.Equal(File.ReadAllBytes(TestPaths.Golden($"compare-{tag}-findings.csv")), File.ReadAllBytes(t.File("findings.csv")));
            }
        }

        [Fact]
        public void Payload_hash_matches_ConvertTo_Json_Compress_for_hard_values()
        {
            using (var t = new TempDir())
            {
                // Wrap the golden records in a document and let the loader parse them as it would a real baseline.
                var records = File.ReadAllText(TestPaths.Golden("payload-records.json"), System.Text.Encoding.UTF8).TrimStart('\uFEFF');
                File.WriteAllText(t.File("b.json"), "{\"Header\":{\"PayloadSha256\":\"" + TestPaths.GoldenText("payload-sha256.txt") + "\"},\"Records\":" + records + "}");
                var doc = BaselineDocument.Load(t.File("b.json"));
                Assert.Equal(TestPaths.GoldenText("payload-sha256.txt"), doc.ComputePayloadSha256());
                Assert.True(doc.PayloadMatches());
                Assert.Empty(doc.Records["Empty"]);
                Assert.Equal(false, doc.Records["LocalAccount"][0]["Enabled"]);
            }
        }

        [Fact]
        public void Placeholder_or_edited_payloads_are_reported_not_trusted()
        {
            using (var t = new TempDir())
            {
                var r = RunGolden(t, "baseline-dif.json");
                Assert.False(r.ReferencePayloadIntact); // the fixtures carry "00"
                var doc = BaselineDocument.Load(t.File("ref.json"));
                doc.Header.PayloadSha256 = doc.ComputePayloadSha256();
                Assert.True(doc.PayloadMatches());
                doc.Records["Service"][0]["PathName"] = @"C:\other.exe";
                Assert.False(doc.PayloadMatches());
            }
        }

        [Fact]
        public void Schema_mismatch_is_refused_except_the_1_14_to_1_15_value_only_change()
        {
            var a = new BaselineDocument { Header = { BaselineSchemaVersion = "1.13.0" } };
            var b = new BaselineDocument { Header = { BaselineSchemaVersion = "1.14.0" } };
            var c = new BaselineDocument { Header = { BaselineSchemaVersion = "1.15.0" } };
            Assert.Throws<InvalidDataException>(() => BaselineComparer.Compare(a, b, "x.json"));
            var r = BaselineComparer.Compare(b, c, "x.json");
            Assert.Contains("(not reported)", r.SchemaNote);
            Assert.Null(BaselineComparer.Compare(b, b, "x.json").SchemaNote);
        }

        [Fact]
        public void Identities_are_case_insensitive_and_removed_records_are_listed_after_added()
        {
            var meta = new ProviderMeta { RecordType = "Service", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "PathName" } };
            Dictionary<string, object?> Svc(string name, string path) => new Dictionary<string, object?> { ["Name"] = name, ["PathName"] = path };
            var reference = new BaselineDocument { Header = { BaselineSchemaVersion = "1.14.0", Hostname = "H" }, Providers = { meta } };
            reference.Records["Service"] = new List<Dictionary<string, object?>> { Svc("Spooler", "a"), Svc("Gone", "x") };
            var difference = new BaselineDocument { Header = { BaselineSchemaVersion = "1.14.0", Hostname = "h" }, Providers = { meta } };
            difference.Records["Service"] = new List<Dictionary<string, object?>> { Svc("SPOOLER", "A"), Svc("New", "y") };
            var r = BaselineComparer.Compare(reference, difference, "dif.json");
            Assert.Equal("Temporal", r.Mode);
            Assert.Equal(new[] { "Added New", "Modified SPOOLER PathName a->A", "Removed Gone" },
                r.Changes.Select(c => (c.ChangeType + " " + c.Identity + (c.Field.Length > 0 ? $" {c.Field} {c.OldValue}->{c.NewValue}" : ""))));
        }

        [Fact]
        public void Zero_changes_replace_a_stale_diff_with_a_header_only_file()
        {
            using (var t = new TempDir())
            {
                File.Copy(TestPaths.Golden("baseline-ref.json"), t.File("ref.json"));
                File.Copy(TestPaths.Golden("baseline-ref.json"), t.File("same.json"));
                File.WriteAllText(t.File("baseline_diff.csv"), "stale");
                var r = BaselineComparer.Run(t.File("ref.json"), t.File("same.json"), new StatusLog(new StringWriter()));
                Assert.Empty(r.Changes);
                Assert.Empty(Csv.Read(t.File("baseline_diff.csv")));
                Assert.StartsWith("\"RecordType\"", TextFile.ReadLines(t.File("baseline_diff.csv"))[0]);
            }
        }

        [Theory]
        [InlineData("ActiveSetup", "Modified", "Version", "", "Info")]
        [InlineData("ActiveSetup", "Modified", "StubPath", "", "High")]
        [InlineData("TimeProvider", "Modified", "Enabled", "", "Medium")]
        [InlineData("ProxyConfig", "Modified", "Value", "Machine|AutoConfigURL", "Medium")]
        [InlineData("ProxyConfig", "Modified", "Value", "Machine|ProxyServer", "High")]
        [InlineData("LocalGroupMember", "Added", "", "administrators|S-1-5-21-1", "High")]
        [InlineData("LocalGroupMember", "Added", "", "Users|S-1-5-21-1", "Medium")]
        [InlineData("Listener", "Added", "", "TCP|0.0.0.0|8080", "Low")]
        [InlineData("InstalledSoftware", "Modified", "DisplayVersion", "", "Info")]
        [InlineData("Certificate", "Added", "", @"Cert:\LocalMachine\Root|AB", "High")]
        public void Severity_follows_the_1_38_rules(string type, string change, string field, string identity, string expected)
        {
            Assert.Equal(expected, ChangeSeverity.Of(new BaselineChange { RecordType = type, ChangeType = change, Field = field, Identity = identity }));
        }
    }
}
