using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Foton.Baseline.Capture;
using Foton.Core;
using Foton.Win;
using Xunit;

namespace Foton.Tests
{
    public class BaselineCaptureTests
    {
        static string LegacyProviders => Path.Combine(TestPaths.Root, "legacy", "powershell", "src", "Private", "Baseline", "Providers");

        static string[] QuotedList(string s) =>
            Regex.Matches(s, "'((?:[^']|'')*)'").Cast<Match>().Select(m => m.Groups[1].Value.Replace("''", "'")).ToArray();

        public static IEnumerable<object[]> LegacyFiles() =>
            Directory.GetFiles(Path.Combine(TestPaths.Root, "legacy", "powershell", "src", "Private", "Baseline", "Providers"), "*.ps1")
                .Select(f => new object[] { Path.GetFileNameWithoutExtension(f) });

        [Fact]
        public void Every_1_38_provider_is_ported_in_the_same_order()
        {
            var legacy = Directory.GetFiles(LegacyProviders, "*.ps1").Select(Path.GetFileNameWithoutExtension).ToList();
            var ported = Providers.All.Select(p => p.RecordType).ToList();
            Assert.Equal(legacy.OrderBy(n => n, StringComparer.OrdinalIgnoreCase), ported);
        }

        /// <summary>
        /// Identity, compared fields, false-positive text and Sort-Object keys are the provider contract a 1.14.0
        /// baseline was written against. Drift here silently changes what Compare reports.
        /// </summary>
        [Theory]
        [MemberData(nameof(LegacyFiles))]
        public void Provider_contract_matches_1_38(string recordType)
        {
            var text = File.ReadAllText(Path.Combine(LegacyProviders, recordType + ".ps1"));
            var p = Providers.All.Single(x => x.RecordType == recordType);
            Assert.Equal(QuotedList(Regex.Match(text, @"-IdentityFields\s+@\(([^)]*)\)").Groups[1].Value), p.IdentityFields);
            Assert.Equal(QuotedList(Regex.Match(text, @"-ComparedFields\s+@\(([^)]*)\)").Groups[1].Value), p.ComparedFields);
            Assert.Equal(QuotedList(Regex.Match(text, @"-FalsePositives\s+('(?:[^']|'')*')").Groups[1].Value).Single(), p.FalsePositives);

            var sortSource = text;
            if (recordType == "StartupApproved")
                sortSource = File.ReadAllText(Path.Combine(TestPaths.Root, "legacy", "powershell", "src", "Private", "Core", "Get-FotonStartupApprovedRows.ps1"));
            var sort = Regex.Match(sortSource, @"\$rows\)?\s*\|\s*Sort-Object\s+([\w, ]+)");
            Assert.True(sort.Success, "No Sort-Object over $rows in the 1.38.x provider.");
            Assert.Equal(sort.Groups[1].Value.Split(',').Select(k => k.Trim()).Where(k => k.Length > 0), p.SortKeys);
        }

        [Fact]
        public void Rows_tied_on_every_sort_key_get_one_order_whatever_the_read_order()
        {
            Dictionary<string, object?> Row(string version) => new Dictionary<string, object?>
            {
                ["DisplayName"] = "Runtime", ["Publisher"] = "Microsoft Corporation", ["DisplayVersion"] = version, ["InstallLocation"] = "",
            };
            List<string> Run(params string[] versions)
            {
                var p = new Provider { RecordType = "InstalledSoftware", SortKeys = new[] { "DisplayName", "Publisher" }, Collect = _ => versions.Select(Row) };
                return p.Run(new CaptureContext(false)).Select(r => (string)r["DisplayVersion"]!).ToList();
            }
            Assert.Equal(Run("6.0.36.34217", "48.144.23186", "10.0"), Run("48.144.23186", "10.0", "6.0.36.34217"));
        }

        [Fact]
        public void Tie_break_is_symmetric_when_rows_carry_different_fields()
        {
            var x = new Dictionary<string, object?> { ["Name"] = "n", ["B"] = "2" };
            var y = new Dictionary<string, object?> { ["Name"] = "n", ["A"] = "1" };
            List<Dictionary<string, object?>> Run(params Dictionary<string, object?>[] rows) =>
                new Provider { RecordType = "T", SortKeys = new[] { "Name" }, Collect = _ => rows }.Run(new CaptureContext(false));
            Assert.Equal(Run(x, y), Run(y, x));
        }

        [Fact]
        public void Safe_catches_errors_raised_while_a_lazy_query_enumerates()
        {
            IEnumerable<Dictionary<string, object?>> Throws()
            {
                yield return new Dictionary<string, object?> { ["Name"] = "first" };
                throw new InvalidOperationException("enumeration failed");
            }
            var p = new Provider { RecordType = "T", SortKeys = new[] { "Name" }, Collect = _ => R.Safe(() => Throws().Select(r => r)) };
            Assert.Empty(p.Run(new CaptureContext(false)));
        }

        [Fact]
        public void Sort_keys_use_PowerShell_culture_order_not_ordinal()
        {
            var p = new Provider
            {
                RecordType = "Service", SortKeys = new[] { "Name" },
                Collect = _ => new[] { "b", "A", "a_x", "B" }.Select(n => new Dictionary<string, object?> { ["Name"] = n }),
            };
            var names = p.Run(new CaptureContext(false)).Select(r => (string)r["Name"]!).ToList();
            Assert.Equal(new[] { "A", "a_x", "B", "b" }, names, StringComparer.OrdinalIgnoreCase);
            Assert.Equal("a_x", names[1]);
        }

        [Fact]
        public void Netapi32_structs_match_the_native_layout()
        {
            int ptr = IntPtr.Size;
            // LOCALGROUP_INFO_0 { LPWSTR }; LOCALGROUP_MEMBERS_INFO_2 { PSID; SID_NAME_USE; LPWSTR } (padded on x64).
            Assert.Equal(new[] { ptr, ptr == 8 ? 24 : 12 }, LocalGroups.StructSizes());
        }

        [Fact]
        public void Package_has_the_1_38_layout_and_every_file_is_hashed()
        {
            using (var t = new TempDir())
            {
                var log = new StatusLog(new StringWriter()) { UtcNow = () => Sessions.Start };
                var s = new FotonSession(new SessionOptions(), Sessions.Start, "HOST", @"DOMAIN\user", false, log);
                var root = BaselineLayout.Create(s, t.Path);
                Assert.Equal(Path.Combine(t.Path, "FotonBaseline_HOST_20260115-120000Z"), root);

                var r = new CaptureResult();
                r.Document.Providers.Add(new ProviderMeta { RecordType = "Service", IdentityFields = new[] { "Name" }, ComparedFields = new[] { "StartMode" }, FalsePositives = "x" });
                r.Document.Records["Service"] = new List<Dictionary<string, object?>> { new Dictionary<string, object?> { ["Name"] = "svc", ["StartMode"] = "Auto" } };
                r.Coverage.Add(new ProviderCoverage { RecordType = "Service", Status = "Success", Count = 1 });
                r.Document.Header = new BaselineHeader
                {
                    BaselineSchemaVersion = FotonVersion.BaselineSchema, ToolVersion = "2.0.0", Hostname = "HOST",
                    CapturedUtc = FotonTime.Format(Sessions.Start), PayloadSha256 = r.Document.ComputePayloadSha256(), Note = BaselineDocument.HeaderNote,
                };

                var pkg = BaselineCapture.WritePackage(s, r, zip: true);
                foreach (var f in new[] { "baseline.json", "coverage.json", "baseline.log", "hashes.csv" })
                    Assert.True(File.Exists(Path.Combine(root, f)), f);
                Assert.True(File.Exists(root + ".zip"));
                Assert.Contains("Foton baseline package integrity record", File.ReadAllText(root + "_PACKAGE_HASH.txt"));
                Assert.Equal(Hashing.Sha256Hex(root + ".zip"), pkg.ZipSha256);

                var hashed = Csv.Read(Path.Combine(root, "hashes.csv")).ToDictionary(h => h["RelativePath"] ?? "", h => h["SHA256"] ?? "", StringComparer.OrdinalIgnoreCase);
                foreach (var f in new[] { "baseline.json", "coverage.json", "baseline.log" })
                    Assert.Equal(Hashing.Sha256Hex(Path.Combine(root, f)), hashed.Single(h => h.Key.EndsWith(f, StringComparison.OrdinalIgnoreCase)).Value);

                var reloaded = BaselineDocument.Load(pkg.JsonPath);
                Assert.True(reloaded.PayloadMatches());
                Assert.Contains("\"Status\"", File.ReadAllText(Path.Combine(root, "coverage.json")));
            }
        }

        /// <summary>Live read of this host: every provider runs, and the header hash survives a save and reload.</summary>
        [Fact]
        public void Live_capture_covers_every_provider_and_its_payload_hash_verifies()
        {
            using (var t = new TempDir())
            {
                var log = new StatusLog(new StringWriter());
                var s = new FotonSession(new SessionOptions(), DateTime.UtcNow, Environment.MachineName, HostInfo.Account(), HostInfo.IsElevated(), log);
                var r = BaselineCapture.Capture(s);
                Assert.Equal(Providers.All.Select(p => p.RecordType), r.Coverage.Select(c => c.RecordType));
                Assert.All(r.Coverage, c => Assert.Equal("Success", c.Status));
                Assert.Equal("1.15.0", r.Document.Header.BaselineSchemaVersion);
                var json = BaselineCapture.WriteJson(r, t.File("snap.json"));
                var reloaded = BaselineDocument.Load(json);
                Assert.True(reloaded.PayloadMatches());
                Assert.Equal(r.Document.Header.PayloadSha256, reloaded.Header.PayloadSha256);
            }
        }
    }
}
