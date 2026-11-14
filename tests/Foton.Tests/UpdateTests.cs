using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Foton.Core;
using Foton.Tools.Update;
using Xunit;

namespace Foton.Tests
{
    /// <summary>
    /// The updater, offline: a throwaway key signs fixture statements (the product pins the owner's keys), a fake source
    /// stands in for GitHub, and staging runs against ZIPs built from a real Foton assembly. No test touches the network.
    /// </summary>
    public class UpdateTests
    {
        static readonly DateTime Now = new DateTime(2026, 12, 1, 12, 0, 0, DateTimeKind.Utc);
        const string Download = "https://github.com/jimididit/foton/releases/download/";

        sealed class TestKey : IDisposable
        {
            readonly ECDsaCng _ecdsa = new ECDsaCng(256);
            public ReleaseKey Key { get; }
            public TestKey(string role = "test")
            {
                var blob = _ecdsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);
                Key = new ReleaseKey(role, Convert.ToBase64String(blob), Hashing.Sha256Hex(blob).ToLowerInvariant());
            }
            public byte[] Sign(byte[] statement) => Encoding.ASCII.GetBytes(Convert.ToBase64String(_ecdsa.SignData(statement, HashAlgorithmName.SHA256)) + "\n");
            public void Dispose() => _ecdsa.Dispose();
        }

        sealed class FakeSource : IUpdateSource
        {
            public readonly Dictionary<string, byte[]> Bodies = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            public void Fetch(string url, Stream output, long maxBytes)
            {
                if (!Bodies.TryGetValue(url, out var body)) throw new IOException("GitHub answered 404 Not Found for " + url);
                if (body.Length > maxBytes) throw new IOException(url + " is over the " + maxBytes + "-byte limit.");
                output.Write(body, 0, body.Length);
            }
        }

        static readonly string[] Exes = ReleaseStatement.RequiredFiles.ToArray();

        /// <summary>The statement exactly as release-v2.yml writes it: fixed key order, LF, no BOM.</summary>
        static byte[] Statement(string version, string released = "2026-11-20", string? zipSha = null, IDictionary<string, string>? files = null,
            string product = "Foton", string? zipName = null)
        {
            files = files ?? Exes.ToDictionary(e => e, e => new string('b', 64));
            var lines = new List<string>
            {
                "{",
                $"  \"product\": \"{product}\",",
                $"  \"version\": \"{version}\",",
                $"  \"released\": \"{released}\",",
                $"  \"zip\": {{ \"name\": \"{zipName ?? "Foton-" + version + "-windows.zip"}\", \"sha256\": \"{zipSha ?? new string('a', 64)}\" }},",
                "  \"files\": {",
                string.Join(",\n", files.OrderBy(f => f.Key, StringComparer.Ordinal).Select(f => $"    \"{f.Key}\": \"{f.Value}\"")),
                "  }",
                "}",
            };
            return new UTF8Encoding(false).GetBytes(string.Join("\n", lines));
        }

        static Dictionary<string, object?> Release(string tag, bool draft = false, bool prerelease = false, params string[] assets) =>
            new Dictionary<string, object?>
            {
                ["tag_name"] = tag,
                ["draft"] = draft,
                ["prerelease"] = prerelease,
                ["html_url"] = "https://github.com/jimididit/foton/releases/tag/" + tag,
                ["assets"] = assets.Select(a => new Dictionary<string, object?> { ["name"] = a, ["browser_download_url"] = Download + tag + "/" + a }).ToList(),
            };

        static void List(FakeSource src, params Dictionary<string, object?>[] releases) =>
            src.Bodies[UpdateCheck.ReleasesApi] = Encoding.UTF8.GetBytes(Json.Indented(releases.ToList()));

        /// <summary>Publishes a release's statement and signature (as GitHub would serve them) and returns the list entry.</summary>
        static Dictionary<string, object?> Signed(FakeSource src, TestKey key, string version, byte[]? statement = null)
        {
            statement = statement ?? Statement(version);
            var tag = "v" + version;
            src.Bodies[Download + tag + "/foton-release.json"] = statement;
            src.Bodies[Download + tag + "/foton-release.json.sig"] = key.Sign(statement);
            return Release(tag, false, false, "foton-release.json", "foton-release.json.sig", "Foton-" + version + "-windows.zip", "foton.exe");
        }

        [Fact]
        public void The_pinned_keys_are_two_P256_keys_whose_fingerprints_match_their_blobs()
        {
            Assert.Equal(new[] { "primary", "backup" }, ReleaseKeys.All.Select(k => k.Role));
            foreach (var key in ReleaseKeys.All)
            {
                Assert.Equal(72, key.Blob.Length);
                Assert.Equal(Hashing.Sha256Hex(key.Blob).ToLowerInvariant(), key.Fingerprint);
                using (var cng = CngKey.Import(key.Blob, CngKeyBlobFormat.EccPublicBlob))
                using (var ecdsa = new ECDsaCng(cng))
                    Assert.Equal(256, ecdsa.KeySize);
            }
            Assert.NotEqual(ReleaseKeys.All[0].Fingerprint, ReleaseKeys.All[1].Fingerprint);
        }

        [Fact]
        public void A_signature_verifies_only_for_the_exact_bytes_and_the_key_that_made_it()
        {
            using (var key = new TestKey())
            using (var other = new TestKey("other"))
            {
                var statement = Statement("3.4.0");
                var sig = key.Sign(statement);
                Assert.Same(key.Key, ReleaseSignature.Verify(statement, sig, new[] { other.Key, key.Key }));
                Assert.Null(ReleaseSignature.Verify(statement, sig, new[] { other.Key }));
                Assert.Null(ReleaseSignature.Verify(statement, sig, ReleaseKeys.All));
                var tampered = (byte[])statement.Clone();
                tampered[20] ^= 1;
                Assert.Null(ReleaseSignature.Verify(tampered, sig, new[] { key.Key }));
                var raw = Convert.FromBase64String(Encoding.ASCII.GetString(sig).Trim());
                Assert.Null(ReleaseSignature.Verify(statement, Encoding.ASCII.GetBytes(Convert.ToBase64String(raw.Take(63).ToArray())), new[] { key.Key }));
                Assert.Null(ReleaseSignature.Verify(statement, Encoding.ASCII.GetBytes("not base64!"), new[] { key.Key }));
                Assert.Null(ReleaseSignature.Verify(statement, new byte[0], new[] { key.Key }));
                Assert.Null(ReleaseSignature.Verify(statement, new byte[ReleaseSignature.MaxSignatureFileBytes + 1], new[] { key.Key }));
            }
        }

        [Fact]
        public void A_statement_parses_with_its_version_date_zip_and_files()
        {
            var s = ReleaseStatement.Parse(Statement("3.4.0"));
            Assert.Equal("3.4.0", s.Version);
            Assert.Equal("2026-11-20", s.ReleasedText);
            Assert.Equal("Foton-3.4.0-windows.zip", s.ZipName);
            Assert.Equal(new string('a', 64), s.ZipSha256);
            Assert.Equal(Exes.OrderBy(e => e, StringComparer.Ordinal), s.Files.Keys.OrderBy(e => e, StringComparer.Ordinal));
        }

        public static IEnumerable<object[]> BadStatements()
        {
            var good = Exes.ToDictionary(e => e, e => new string('b', 64));
            yield return new object[] { "product", Statement("3.4.0", product: "FOTON") };
            yield return new object[] { "version", Statement("3.4") };
            yield return new object[] { "released", Statement("3.4.0", released: "20 Nov 2026") };
            yield return new object[] { "the ZIP is not named", Statement("3.4.0", zipName: "../evil.zip") };
            // A JSON-escaped backslash: the parsed name is ..\evil.zip.
            yield return new object[] { "the ZIP is not named", Statement("3.4.0", zipName: "..\\\\evil.zip") };
            yield return new object[] { "the ZIP is not named", Statement("3.4.0", zipName: "foton-3.4.0-WINDOWS.zip") };
            yield return new object[] { "the ZIP's SHA-256", Statement("3.4.0", zipSha: new string('A', 64)) };
            yield return new object[] { "unexpected file name", Statement("3.4.0", files: new Dictionary<string, string>(good) { ["../evil.exe"] = new string('b', 64) }) };
            yield return new object[] { "unexpected file name", Statement("3.4.0", files: new Dictionary<string, string>(good) { ["..\\\\evil.exe"] = new string('b', 64) }) };
            yield return new object[] { "unexpected file name", Statement("3.4.0", files: new Dictionary<string, string>(good) { ["FOTON.exe"] = new string('b', 64) }) };
            yield return new object[] { "SHA-256 of foton.exe", Statement("3.4.0", files: new Dictionary<string, string>(good) { ["foton.exe"] = "zz" }) };
            yield return new object[] { "does not list foton-console.exe", Statement("3.4.0", files: good.Where(p => p.Key != "foton-console.exe").ToDictionary(p => p.Key, p => p.Value)) };
            // A trailing newline (a JSON \n escape) must not slip past an anchored pattern.
            yield return new object[] { "version", Statement("3.4.0\\n") };
            yield return new object[] { "unexpected file name", Statement("3.4.0", files: new Dictionary<string, string>(good) { ["foton.exe\\n"] = new string('b', 64) }) };
            yield return new object[] { "SHA-256 of foton.exe", Statement("3.4.0", files: new Dictionary<string, string>(good) { ["foton.exe"] = new string('b', 64) + "\\n" }) };
            yield return new object[] { "not JSON", Encoding.UTF8.GetBytes("{ nope") };
            yield return new object[] { "not UTF-8", new byte[] { 0x7B, 0xFF, 0xFE, 0x7D } };
            yield return new object[] { "size", new byte[ReleaseStatement.MaxBytes + 1] };
        }

        [Theory]
        [MemberData(nameof(BadStatements))]
        public void A_statement_that_breaks_the_schema_is_refused_with_the_reason(string reason, byte[] bytes)
        {
            var ex = Assert.Throws<InvalidDataException>(() => ReleaseStatement.Parse(bytes));
            Assert.Contains(reason, ex.Message);
        }

        [Theory]
        [InlineData("3.3.0", "3.2.2", true)]
        [InlineData("3.2.10", "3.2.9", true)]
        [InlineData("3.3.0", "3.3.0-beta.1", true)]
        [InlineData("3.3.0", "3.3.0", false)]
        [InlineData("3.2.9", "3.3.0", false)]
        [InlineData("3.3.0", "unknown", true)]
        [InlineData("not.a.version", "3.3.0", false)]
        public void Only_a_later_version_counts_as_newer(string candidate, string current, bool newer) =>
            Assert.Equal(newer, UpdateCheck.IsNewer(candidate, current));

        [Fact]
        public void Up_to_date_when_no_stable_release_is_newer_and_drafts_and_prereleases_are_ignored()
        {
            using (var key = new TestKey())
            {
                var src = new FakeSource();
                var draft = Signed(src, key, "3.5.0");
                draft["draft"] = true;
                var pre = Signed(src, key, "3.6.0");
                pre["prerelease"] = true;
                List(src, draft, pre, Release("v3.7.0-beta.1"), Signed(src, key, "3.3.0"), Release("v3.2.2"));
                var r = UpdateCheck.Run(src, "3.3.0", Now, new[] { key.Key });
                Assert.Equal(UpdateState.UpToDate, r.State);
                Assert.Contains("No release newer than Foton 3.3.0", r.Message);
            }
        }

        [Fact]
        public void The_newest_signed_release_is_available_and_a_newer_unsigned_one_is_named_as_pending()
        {
            using (var key = new TestKey())
            {
                var src = new FakeSource();
                List(src, Release("v3.5.0", false, false, "foton-release.json", "Foton-3.5.0-windows.zip"), Signed(src, key, "3.4.0"), Release("v3.2.2"));
                var r = UpdateCheck.Run(src, "3.3.0", Now, new[] { key.Key });
                Assert.Equal(UpdateState.Available, r.State);
                Assert.Equal("3.4.0", r.Statement!.Version);
                Assert.Same(key.Key, r.SignedBy);
                Assert.Equal(Download + "v3.4.0/Foton-3.4.0-windows.zip", r.ZipUrl);
                Assert.Equal("https://github.com/jimididit/foton/releases/tag/v3.4.0", r.ReleaseUrl);
                Assert.Equal("3.5.0", r.PendingVersion);
                Assert.Contains("fingerprint " + key.Key.Fingerprint, r.Message);
            }
        }

        [Fact]
        public void A_newer_release_without_a_signature_is_published_but_not_installable()
        {
            var src = new FakeSource();
            List(src, Release("v3.4.0", false, false, "foton-release.json", "Foton-3.4.0-windows.zip"));
            var r = UpdateCheck.Run(src, "3.3.0", Now, ReleaseKeys.All);
            Assert.Equal(UpdateState.NotYetSigned, r.State);
            Assert.Equal("3.4.0", r.PendingVersion);
            Assert.Contains("not signed yet", r.Message);
        }

        [Fact]
        public void An_asset_outside_this_repository_and_tag_does_not_count()
        {
            using (var key = new TestKey())
            {
                var src = new FakeSource();
                var release = Signed(src, key, "3.4.0");
                foreach (var a in (List<Dictionary<string, object?>>)release["assets"]!)
                    a["browser_download_url"] = ((string)a["browser_download_url"]!).Replace("jimididit/foton", "someone/foton");
                List(src, release);
                Assert.Equal(UpdateState.NotYetSigned, UpdateCheck.Run(src, "3.3.0", Now, new[] { key.Key }).State);
            }
        }

        [Fact]
        public void A_signature_from_an_unpinned_key_fails_the_check_and_never_falls_back()
        {
            using (var key = new TestKey())
            using (var stranger = new TestKey("stranger"))
            {
                var src = new FakeSource();
                List(src, Signed(src, stranger, "3.5.0"), Signed(src, key, "3.4.0"));
                var r = UpdateCheck.Run(src, "3.3.0", Now, new[] { key.Key });
                Assert.Equal(UpdateState.Failed, r.State);
                Assert.Contains("3.5.0 is not trusted", r.Message);
                Assert.Null(r.Statement);
            }
        }

        [Fact]
        public void A_signed_statement_for_another_version_or_a_future_date_fails_the_check()
        {
            using (var key = new TestKey())
            {
                var src = new FakeSource();
                List(src, Signed(src, key, "3.5.0", Statement("3.4.0")));
                var r = UpdateCheck.Run(src, "3.3.0", Now, new[] { key.Key });
                Assert.Equal(UpdateState.Failed, r.State);
                Assert.Contains("for version 3.4.0", r.Message);

                List(src, Signed(src, key, "3.5.0", Statement("3.5.0", released: "2027-01-01")));
                r = UpdateCheck.Run(src, "3.3.0", Now, new[] { key.Key });
                Assert.Equal(UpdateState.Failed, r.State);
                Assert.Contains("in the future", r.Message);
            }
        }

        [Fact]
        public void An_unreachable_or_unreadable_release_list_fails_the_check()
        {
            var src = new FakeSource();
            Assert.Equal(UpdateState.Failed, UpdateCheck.Run(src, "3.3.0", Now, ReleaseKeys.All).State);
            src.Bodies[UpdateCheck.ReleasesApi] = Encoding.UTF8.GetBytes("<html>rate limited</html>");
            var r = UpdateCheck.Run(src, "3.3.0", Now, ReleaseKeys.All);
            Assert.Equal(UpdateState.Failed, r.State);
            Assert.Contains("not JSON", r.Message);
        }

        [Fact]
        public void A_body_over_its_cap_is_refused_before_it_lands_whole()
        {
            var output = new MemoryStream();
            HttpUpdateSource.CopyCapped(new MemoryStream(new byte[100]), output, 100, "body");
            Assert.Equal(100, output.Length);
            Assert.Throws<IOException>(() => HttpUpdateSource.CopyCapped(new MemoryStream(new byte[101]), new MemoryStream(), 100, "body"));
        }

        /// <summary>A release ZIP of real version-stamped files (a Foton assembly under each executable's name) and its statement.</summary>
        sealed class Built
        {
            public string Version = "";
            public string Zip = "";
            public ReleaseStatement Statement = null!;
            public byte[] StatementBytes = null!;
        }

        static string AssemblyVersion()
        {
            var info = FileVersionInfo.GetVersionInfo(typeof(FotonVersion).Assembly.Location);
            return $"{info.FileMajorPart}.{info.FileMinorPart}.{info.FileBuildPart}";
        }

        static Built BuildRelease(string dir, string? version = null, Action<ZipArchive>? extra = null, string[]? omit = null, IDictionary<string, string>? hashOverride = null)
        {
            version = version ?? AssemblyVersion();
            var payload = File.ReadAllBytes(typeof(FotonVersion).Assembly.Location);
            var zip = Path.Combine(dir, "Foton-" + version + "-windows.zip");
            using (var archive = ZipFile.Open(zip, ZipArchiveMode.Create))
            {
                foreach (var exe in Exes.Where(e => omit == null || !omit.Contains(e)))
                    using (var s = archive.CreateEntry(exe).Open()) s.Write(payload, 0, payload.Length);
                foreach (var companion in UpdateStage.CompanionFiles)
                    using (var w = new StreamWriter(archive.CreateEntry(companion).Open())) w.Write(companion);
                extra?.Invoke(archive);
            }
            var exeSha = Hashing.Sha256Hex(payload).ToLowerInvariant();
            var files = Exes.ToDictionary(e => e, e => hashOverride != null && hashOverride.TryGetValue(e, out var h) ? h : exeSha);
            var bytes = Statement(version, zipSha: Hashing.Sha256Hex(zip).ToLowerInvariant(), files: files);
            return new Built { Version = version, Zip = zip, StatementBytes = bytes, Statement = ReleaseStatement.Parse(bytes) };
        }

        static StatusLog Quiet() => new StatusLog(new StringWriter());

        [Fact]
        public void A_verified_release_stages_every_file_and_deletes_the_download()
        {
            using (var tmp = new TempDir())
            {
                var b = BuildRelease(tmp.Path);
                var staged = UpdateStage.Verify(b.Statement, b.Zip, tmp.File("staged"), Quiet());
                Assert.False(File.Exists(b.Zip));
                Assert.Equal(Exes.Concat(UpdateStage.CompanionFiles).OrderBy(n => n, StringComparer.Ordinal),
                    Directory.GetFiles(staged).Select(Path.GetFileName).OrderBy(n => n, StringComparer.Ordinal));
            }
        }

        [Fact]
        public void Release_files_are_extracted_only_into_a_new_folder()
        {
            using (var tmp = new TempDir())
            {
                var b = BuildRelease(tmp.Path);
                var existing = Directory.CreateDirectory(tmp.File("existing")).FullName;
                File.WriteAllText(Path.Combine(existing, "keep.txt"), "mine");
                Assert.Throws<IOException>(() => UpdateStage.Verify(b.Statement, b.Zip, existing, Quiet()));
                Assert.Equal(new[] { "keep.txt" }, Directory.GetFiles(existing).Select(Path.GetFileName));
            }
        }

        [Fact]
        public void Stage_downloads_from_the_source_and_removes_its_folder_when_a_check_fails()
        {
            using (var tmp = new TempDir())
            {
                var b = BuildRelease(tmp.Path);
                var url = Download + "v" + b.Version + "/" + b.Statement.ZipName;
                var src = new FakeSource();
                src.Bodies[url] = File.ReadAllBytes(b.Zip);
                var updates = tmp.File("updates");
                var staged = UpdateStage.Stage(b.Statement, url, src, updates, Quiet());
                Assert.True(File.Exists(Path.Combine(staged, "foton-console.exe")));

                src.Bodies[url] = new byte[] { 1, 2, 3 };
                var ex = Assert.Throws<InvalidDataException>(() => UpdateStage.Stage(b.Statement, url, src, updates, Quiet()));
                Assert.Contains("does not match the signed SHA-256", ex.Message);
                Assert.False(Directory.Exists(Path.Combine(updates, b.Version)));
            }
        }

        static Built BadZip(string reason, string dir)
        {
            switch (reason)
            {
                case "unexpected entry '../evil.txt'": return BuildRelease(dir, extra: a => a.CreateEntry("../evil.txt"));
                case "unexpected entry 'tools/foton.exe'": return BuildRelease(dir, extra: a => a.CreateEntry("tools/foton.exe"));
                case "unexpected entry 'extra.dll'": return BuildRelease(dir, extra: a => a.CreateEntry("extra.dll"));
                case "does not hold foton-collect.exe": return BuildRelease(dir, omit: new[] { "foton-collect.exe" });
                case "foton.exe does not match the signed SHA-256": return BuildRelease(dir, hashOverride: new Dictionary<string, string> { ["foton.exe"] = new string('c', 64) });
                default: return BuildRelease(dir, version: "9.9.9");
            }
        }

        [Theory]
        [InlineData("unexpected entry '../evil.txt'")]
        [InlineData("unexpected entry 'tools/foton.exe'")]
        [InlineData("unexpected entry 'extra.dll'")]
        [InlineData("does not hold foton-collect.exe")]
        [InlineData("foton.exe does not match the signed SHA-256")]
        [InlineData("not the signed 9.9.9")]
        public void A_release_ZIP_that_does_not_match_its_statement_is_refused_with_the_failed_check(string reason)
        {
            using (var tmp = new TempDir())
            {
                var b = BadZip(reason, tmp.Path);
                var ex = Assert.Throws<InvalidDataException>(() => UpdateStage.Verify(b.Statement, b.Zip, tmp.File("staged"), Quiet()));
                Assert.Contains(reason, ex.Message);
                Assert.False(File.Exists(Path.Combine(tmp.Path, "evil.txt")));
            }
        }

        [Fact]
        public void Install_puts_the_release_in_a_new_folder_beside_this_one_and_keeps_this_one()
        {
            using (var tmp = new TempDir())
            {
                var current = Directory.CreateDirectory(tmp.File("Foton-old")).FullName;
                File.WriteAllText(Path.Combine(current, "foton.exe"), "old");
                var b = BuildRelease(tmp.Path);
                var staged = UpdateStage.Verify(b.Statement, b.Zip, tmp.File("staged"), Quiet());
                var target = UpdateInstall.DefaultTarget(current, b.Version);
                Assert.Equal(tmp.File("Foton-" + b.Version), target);

                Assert.Equal(target, UpdateInstall.Install(staged, target, b.Statement, Quiet()));
                Assert.Equal("old", File.ReadAllText(Path.Combine(current, "foton.exe")));
                Assert.Equal(Exes.Length + UpdateStage.CompanionFiles.Count, Directory.GetFiles(target).Length);
                Assert.Empty(Directory.GetDirectories(tmp.Path, "*.partial-*"));

                // Installing the same release again reports it; another folder in the way is refused, not overwritten.
                Assert.Equal(target, UpdateInstall.Install(staged, target, b.Statement, Quiet()));
                var blocked = Directory.CreateDirectory(tmp.File("blocked")).FullName;
                File.WriteAllText(Path.Combine(blocked, "notes.txt"), "mine");
                Assert.Throws<IOException>(() => UpdateInstall.Install(staged, blocked, b.Statement, Quiet()));
                Assert.Equal("mine", File.ReadAllText(Path.Combine(blocked, "notes.txt")));

                // Clean deletes only updatesRoot\X.Y.Z; any other name is refused, and nothing is deleted.
                Assert.Throws<InvalidDataException>(() => UpdateStage.Clean(tmp.Path, "staged"));
                Assert.Throws<InvalidDataException>(() => UpdateStage.Clean(tmp.File("updates"), ".."));
                Assert.True(Directory.Exists(tmp.File("staged")));
                var work = Directory.CreateDirectory(Path.Combine(tmp.Path, "updates", b.Version)).FullName;
                UpdateStage.Clean(tmp.File("updates"), b.Version);
                Assert.False(Directory.Exists(work));
            }
        }

        [Theory]
        [InlineData(@"C:\Users\analyst\scoop\apps\foton\3.3.0", true)]
        [InlineData(@"C:\Users\analyst\scoop\apps\foton\current", true)]
        [InlineData(@"C:\Tools\Foton-3.3.0", false)]
        [InlineData(@"D:\scoopish\apps", false)]
        public void A_Scoop_install_is_recognised_by_its_folder(string exeDir, bool scoop) =>
            Assert.Equal(scoop, UpdateInstall.IsScoop(exeDir));
    }
}
