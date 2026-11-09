using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Foton.Baseline.Capture;
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
        public void ServiceDll_is_compared_from_1_17_and_skipped_against_older_baselines()
        {
            var meta = new ProviderMeta { RecordType = "Service", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "PathName", "ServiceDll" } };
            BaselineDocument Doc(string schema, string? dll)
            {
                var d = new BaselineDocument { Header = { BaselineSchemaVersion = schema, Hostname = "H" }, Providers = { meta } };
                var row = new Dictionary<string, object?> { ["Name"] = "Schedule", ["PathName"] = @"C:\Windows\system32\svchost.exe -k netsvcs" };
                if (dll != null) row["ServiceDll"] = dll;
                d.Records["Service"] = new List<Dictionary<string, object?>> { row };
                return d;
            }
            var swapped = BaselineComparer.Compare(Doc("1.17.0", @"C:\Windows\system32\schedsvc.dll"), Doc("1.17.0", @"C:\Users\x\evil.dll"), "dif.json");
            var change = swapped.Changes.Single();
            Assert.Equal("ServiceDll", change.Field);
            Assert.Equal("High", ChangeSeverity.Of(change));

            // A 1.16.0 side never captured ServiceDll: no Modified row in either direction, and the note says why.
            foreach (var r in new[] { BaselineComparer.Compare(Doc("1.16.0", null), Doc("1.17.0", @"C:\Windows\system32\schedsvc.dll"), "dif.json"),
                                      BaselineComparer.Compare(Doc("1.17.0", @"C:\Windows\system32\schedsvc.dll"), Doc("1.16.0", null), "dif.json") })
            {
                Assert.Empty(r.Changes);
                Assert.Contains("ServiceDll", r.SchemaNote);
            }
            Assert.Empty(BaselineSchema.FieldsNotComparable("1.17.0", "1.17.0", "Service"));
            Assert.Empty(BaselineSchema.FieldsNotComparable("1.14.0", "1.17.0", "Driver"));
        }

        [Fact]
        public void Schema_1_18_is_comparable_and_explains_the_pwsh_row()
        {
            Assert.True(BaselineSchema.CanCompare("1.14.0", "1.18.0"));
            Assert.True(BaselineSchema.CanCompare("1.18.0", "1.17.0"));
            Assert.Contains("pwsh.exe", BaselineSchema.CrossVersionNote("1.17.0", "1.18.0"));
            Assert.DoesNotContain("pwsh.exe", BaselineSchema.CrossVersionNote("1.16.0", "1.17.0"));
            Assert.Empty(BaselineSchema.FieldsNotComparable("1.17.0", "1.18.0", "SystemBinary"));
        }

        [Fact]
        public void System_binaries_are_looked_for_where_they_install()
        {
            var paths = OtherProviders.SystemBinaryPaths(@"C:\Windows", @"C:\Program Files").ToList();
            Assert.Contains(@"C:\Program Files\PowerShell\7\pwsh.exe", paths);
            Assert.Contains(@"C:\Windows\explorer.exe", paths);
            Assert.Contains(@"C:\Windows\System32\lsass.exe", paths);
            Assert.DoesNotContain(@"C:\Windows\System32\pwsh.exe", paths);
            Assert.Equal(paths.Count, paths.Select(System.IO.Path.GetFileName).Distinct(StringComparer.OrdinalIgnoreCase).Count());   // Name stays a unique identity
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
        public void LoadUserHives_header_round_trips_and_older_baselines_read_as_off()
        {
            using (var t = new TempDir())
            {
                var doc = new BaselineDocument { Header = { BaselineSchemaVersion = "1.18.0", LoadUserHives = true, UserHivesMounted = 2 } };
                File.WriteAllText(t.File("new.json"), doc.ToJson());
                var reloaded = BaselineDocument.Load(t.File("new.json"));
                Assert.True(reloaded.Header.LoadUserHives);
                Assert.Equal(2, reloaded.Header.UserHivesMounted);

                File.WriteAllText(t.File("old.json"), "{\"Header\":{\"BaselineSchemaVersion\":\"1.18.0\",\"Elevated\":true},\"Records\":{}}");
                var old = BaselineDocument.Load(t.File("old.json"));
                Assert.False(old.Header.LoadUserHives);
                Assert.Equal(0, old.Header.UserHivesMounted);

                // Any number shape the parser can box (int, long, decimal) or a string reads as the count; a fraction,
                // negative, out-of-range value, boolean, or text reads as 0.
                foreach (var c in new[] { "3:3", "3.0:3", "\"3\":3", "2147483647:2147483647", "4294967296:0", "2.5:0", "-1:0", "true:0", "\"x\":0", "null:0" })
                {
                    var i = c.LastIndexOf(':');
                    File.WriteAllText(t.File("n.json"), "{\"Header\":{\"UserHivesMounted\":" + c.Substring(0, i) + "},\"Records\":{}}");
                    Assert.Equal(int.Parse(c.Substring(i + 1)), BaselineDocument.Load(t.File("n.json")).Header.UserHivesMounted);
                }
            }
        }

        [Fact]
        public void Comparing_with_and_without_LoadUserHives_explains_per_user_rows()
        {
            BaselineDocument Doc(bool mounted) => new BaselineDocument { Header = { BaselineSchemaVersion = "1.18.0", Hostname = "H", LoadUserHives = mounted } };
            var added = BaselineComparer.Compare(Doc(false), Doc(true), "x.json").UserHivesNote!;
            Assert.Contains("Only the difference baseline", added);
            Assert.Contains("can show as Added", added);
            var removed = BaselineComparer.Compare(Doc(true), Doc(false), "x.json").UserHivesNote!;
            Assert.Contains("Only the reference baseline", removed);
            Assert.Contains("can show as Removed", removed);
            Assert.Null(BaselineComparer.Compare(Doc(true), Doc(true), "x.json").UserHivesNote);
            Assert.Null(BaselineComparer.Compare(Doc(false), Doc(false), "x.json").UserHivesNote);
        }

        [Fact]
        public void Schema_mismatch_is_refused_except_the_value_only_changes_since_1_14()
        {
            var a = new BaselineDocument { Header = { BaselineSchemaVersion = "1.13.0" } };
            var b = new BaselineDocument { Header = { BaselineSchemaVersion = "1.14.0" } };
            var c = new BaselineDocument { Header = { BaselineSchemaVersion = "1.15.0" } };
            var d = new BaselineDocument { Header = { BaselineSchemaVersion = "1.16.0" } };
            var e = new BaselineDocument { Header = { BaselineSchemaVersion = "1.17.0" } };
            var de = BaselineComparer.Compare(d, e, "x.json").SchemaNote!;
            Assert.Contains("ServiceDll", de);
            Assert.DoesNotContain("Namespace64", de);
            Assert.Throws<InvalidDataException>(() => BaselineComparer.Compare(a, b, "x.json"));
            Assert.Throws<InvalidDataException>(() => BaselineComparer.Compare(a, d, "x.json"));
            var bc = BaselineComparer.Compare(b, c, "x.json").SchemaNote!;
            Assert.Contains("(not reported)", bc);
            Assert.DoesNotContain("Namespace64", bc);
            var cd = BaselineComparer.Compare(c, d, "x.json").SchemaNote!;
            Assert.Contains("Namespace64", cd);
            Assert.DoesNotContain("(not reported)", cd);
            var db = BaselineComparer.Compare(d, b, "x.json").SchemaNote!;
            Assert.Contains("(not reported)", db);
            Assert.Contains("Namespace64", db);
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
