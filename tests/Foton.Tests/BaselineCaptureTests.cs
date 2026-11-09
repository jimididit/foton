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
        /// <summary>
        /// testdata/baseline/provider-contract.json: identity fields, compared fields, sort keys, and false-positive text
        /// per record type, captured from the 1.38.x providers when they were checked equal. Older baselines were written
        /// against this contract; changing it changes what Compare reports, so a change here needs a baseline schema
        /// decision (BaselineSchema) and an updated snapshot in the same PR.
        /// </summary>
        static List<Dictionary<string, object>> Contract() =>
            ((System.Collections.IEnumerable)Json.Parse(File.ReadAllText(Path.Combine(TestPaths.Root, "testdata", "baseline", "provider-contract.json")))!)
                .Cast<Dictionary<string, object>>().ToList();

        static string Str(object? v) => v as string ?? "";

        static string[] Strings(object? v) => ((System.Collections.IEnumerable)v!).Cast<object?>().Select(Str).ToArray();

        public static IEnumerable<object[]> ContractTypes() => Contract().Select(c => new object[] { Str(c["RecordType"]) });

        [Fact]
        public void Providers_match_the_contract_snapshot_in_order()
        {
            Assert.Equal(Contract().Select(c => Str(c["RecordType"])), Providers.All.Select(p => p.RecordType));
        }

        [Theory]
        [MemberData(nameof(ContractTypes))]
        public void Provider_contract_is_unchanged(string recordType)
        {
            var c = Contract().Single(x => Str(x["RecordType"]) == recordType);
            var p = Providers.All.Single(x => x.RecordType == recordType);
            Assert.Equal(Strings(c["IdentityFields"]), p.IdentityFields);
            Assert.Equal(Strings(c["ComparedFields"]), p.ComparedFields);
            Assert.Equal(Strings(c["SortKeys"]), p.SortKeys);
            Assert.Equal(Str(c["FalsePositives"]), p.FalsePositives);
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
            var ctx = new CaptureContext(false);
            var p = new Provider { RecordType = "T", SortKeys = new[] { "Name" }, Collect = c => c.Safe(() => Throws().Select(r => r)) };
            Assert.Empty(p.Run(ctx));
            Assert.Equal(new[] { "InvalidOperationException: enumeration failed" }, ctx.TakeGaps());
            Assert.Empty(ctx.TakeGaps());
        }

        [Fact]
        public void Sort_order_does_not_depend_on_the_machine_locale()
        {
            var p = new Provider
            {
                RecordType = "Service", SortKeys = new[] { "Name" },
                Collect = _ => new[] { "zeta", "öst", "alpha" }.Select(n => new Dictionary<string, object?> { ["Name"] = n }),
            };
            var saved = System.Threading.Thread.CurrentThread.CurrentCulture;
            try
            {
                // Swedish sorts ö after z; invariant culture keeps it beside o.
                System.Threading.Thread.CurrentThread.CurrentCulture = new System.Globalization.CultureInfo("sv-SE");
                var names = p.Run(new CaptureContext(false)).Select(r => (string)r["Name"]!).ToList();
                Assert.Equal(new[] { "alpha", "öst", "zeta" }, names);
            }
            finally { System.Threading.Thread.CurrentThread.CurrentCulture = saved; }
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
            // USER_INFO_0 { LPWSTR }; USER_INFO_4 (29 fields: 15 pointers, 14 DWORDs, padded on x64);
            // USER_INFO_24 { BOOL; DWORD; LPWSTR; LPWSTR; PSID }; USER_MODALS_INFO_0 (5 DWORDs).
            Assert.Equal(new[] { ptr, ptr == 8 ? 192 : 116, ptr == 8 ? 32 : 20, 20 }, LocalUsers.StructSizes());
            // SIGNATURE_INFO: five DWORDs, then three (LPWSTR, DWORD) pairs, a hash pointer, cbHash, and fOSBinary.
            Assert.Equal(ptr == 8 ? 88 : 56, Authenticode.StructSize());
            // SID_AND_ATTRIBUTES { PSID; DWORD } (padded on x64).
            Assert.Equal(ptr == 8 ? 16 : 8, ProcessOwner.StructSize());
            // BG_JOB_TIMES: three FILETIMEs.
            Assert.Equal(24, Bits.StructSize());
            Assert.Equal(600, FileStreams.StructSize());
            // USN_JOURNAL_DATA_V0: seven 64-bit fields; READ_USN_JOURNAL_DATA_V0: USN, two DWORDs, three 64-bit fields.
            Assert.Equal(new[] { 56, 40 }, UsnJournal.StructSizes());
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
                // Partial is legitimate on a standard-user CI runner; an escaped exception is not.
                Assert.All(r.Coverage, c => Assert.NotEqual("Error", c.Status));
                Assert.All(r.Coverage.Where(c => c.Status == "Partial"), c => Assert.NotEqual("", c.Error));
                Assert.Equal(FotonVersion.BaselineSchema, r.Document.Header.BaselineSchemaVersion);
                var json = BaselineCapture.WriteJson(r, t.File("snap.json"));
                var reloaded = BaselineDocument.Load(json);
                Assert.True(reloaded.PayloadMatches());
                Assert.Equal(r.Document.Header.PayloadSha256, reloaded.Header.PayloadSha256);
            }
        }
    }
}
