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

                // Seal a copy with its true hash, then tamper with one record in the file.
                var json = File.ReadAllText(t.File("ref.json"));
                var sealedHash = BaselineDocument.Load(t.File("ref.json")).ComputePayloadSha256();
                File.WriteAllText(t.File("sealed.json"), json.Replace("\"00\"", "\"" + sealedHash + "\""));
                Assert.True(BaselineDocument.Load(t.File("sealed.json")).PayloadMatches());
                File.WriteAllText(t.File("tampered.json"), File.ReadAllText(t.File("sealed.json")).Replace("spoolsv.exe", "spoolsv2.exe"));
                Assert.False(BaselineDocument.Load(t.File("tampered.json")).PayloadMatches());
            }
        }

        [Fact]
        public void Payload_hash_verifies_the_file_whatever_shape_a_type_was_stored_in()
        {
            using (var t = new TempDir())
            {
                const string records = "{\"Service\":{\"Name\":\"Solo\",\"PathName\":\"x\"},\"Missing\":null,\"Listed\":[{\"Name\":\"a\"}]}";
                var sha = Hashing.Sha256Hex(System.Text.Encoding.UTF8.GetBytes(records));
                File.WriteAllText(t.File("b.json"), "{\"Header\":{\"PayloadSha256\":\"" + sha + "\"},\"Records\":" + records + "}");
                var doc = BaselineDocument.Load(t.File("b.json"));
                Assert.True(doc.PayloadMatches());
                Assert.Single(doc.Records["Service"]);
                Assert.Empty(doc.Records["Missing"]);
            }
        }

        [Fact]
        public void A_type_only_the_difference_knows_uses_its_contract_and_type_names_are_case_insensitive()
        {
            var keyed = new ProviderMeta { RecordType = "KnownDll", IdentityFields = new[] { "Key" }, ComparedFields = new[] { "MappedFile" } };
            var reference = new BaselineDocument { Header = { BaselineSchemaVersion = "1.14.0", Hostname = "H" } };
            reference.Records["service"] = new List<Dictionary<string, object?>> { new Dictionary<string, object?> { ["Name"] = "Spooler" } };
            var difference = new BaselineDocument { Header = { BaselineSchemaVersion = "1.14.0", Hostname = "H" }, Providers = { keyed } };
            difference.Records["Service"] = new List<Dictionary<string, object?>> { new Dictionary<string, object?> { ["Name"] = "Spooler" } };
            difference.Records["KnownDll"] = new List<Dictionary<string, object?>>
            {
                new Dictionary<string, object?> { ["Key"] = "kernel32", ["MappedFile"] = "kernel32.dll" },
                new Dictionary<string, object?> { ["Key"] = "user32", ["MappedFile"] = "user32.dll" },
            };
            var r = BaselineComparer.Compare(reference, difference, "dif.json");
            // Two Added rows keyed by Key (1.38.x keyed by the absent Name and collapsed them into one);
            // "service" and "Service" are the same type, so no Removed/Added pair for Spooler.
            Assert.Equal(new[] { "Added KnownDll kernel32", "Added KnownDll user32" }, r.Changes.Select(c => $"{c.ChangeType} {c.RecordType} {c.Identity}"));
        }

        [Fact]
        public void Identity_values_containing_the_separator_do_not_collide()
        {
            var meta = new ProviderMeta { RecordType = "Autorun", IdentityFields = new[] { "Key", "ValueName" }, ComparedFields = new[] { "Command" } };
            Dictionary<string, object?> Run(string key, string name, string cmd) => new Dictionary<string, object?> { ["Key"] = key, ["ValueName"] = name, ["Command"] = cmd };
            var reference = new BaselineDocument { Header = { BaselineSchemaVersion = "1.14.0", Hostname = "H" }, Providers = { meta } };
            reference.Records["Autorun"] = new List<Dictionary<string, object?>> { Run("a|b", "c", "one") };
            var difference = new BaselineDocument { Header = { BaselineSchemaVersion = "1.14.0", Hostname = "H" }, Providers = { meta } };
            difference.Records["Autorun"] = new List<Dictionary<string, object?>> { Run("a", "b|c", "two") };
            var r = BaselineComparer.Compare(reference, difference, "dif.json");
            // Both display as "a|b|c", but they are different records: one Added, one Removed (1.38.x reported a Modified Command).
            Assert.Equal(new[] { "Added a|b|c", "Removed a|b|c" }, r.Changes.Select(c => c.ChangeType + " " + c.Identity));
        }

        [Fact]
        public void A_loaded_baseline_verifies_its_file_while_capture_hashes_its_records()
        {
            using (var t = new TempDir())
            {
                const string records = "{\"Service\":[{\"Name\":\"a\"}]}";
                File.WriteAllText(t.File("b.json"), "{\"Header\":{\"PayloadSha256\":\"" + Hashing.Sha256Hex(System.Text.Encoding.UTF8.GetBytes(records)) + "\"},\"Records\":" + records + "}");
                var doc = BaselineDocument.Load(t.File("b.json"));
                Assert.True(doc.PayloadMatches());
                doc.Records["Service"][0]["Name"] = "edited";
                Assert.True(doc.PayloadMatches()); // the file is what is verified
                Assert.NotEqual(doc.Header.PayloadSha256, doc.ComputePayloadSha256()); // records are what capture hashes
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
