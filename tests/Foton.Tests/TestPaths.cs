using System;
using System.IO;
using System.Text;
using Foton.Core;

namespace Foton.Tests
{
    static class TestPaths
    {
        public static readonly string Root = FindRoot();
        public static string Golden(string name) => Path.Combine(Root, "testdata", "golden", name);
        public static string Fixture => Path.Combine(Root, "testdata", "packages", "WinFoton_FIXTURE_20260115-120000Z");

        static string FindRoot()
        {
            for (var d = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory); d != null; d = d.Parent)
                if (File.Exists(Path.Combine(d.FullName, "Foton.sln"))) return d.FullName;
            throw new InvalidOperationException("Foton.sln not found.");
        }

        /// <summary>Golden text exactly as stored (UTF-8, no BOM).</summary>
        public static string GoldenText(string name) => File.ReadAllText(Golden(name), new UTF8Encoding(false));
    }

    /// <summary>A scratch folder deleted after the test.</summary>
    sealed class TempDir : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "foton-test-" + Guid.NewGuid().ToString("N"));
        public TempDir() { Directory.CreateDirectory(Path); }
        public string File(string name) => System.IO.Path.Combine(Path, name);
        public void Dispose() { try { Directory.Delete(Path, true); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
    }

    static class Sessions
    {
        public static readonly DateTime Start = new DateTime(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc);

        /// <summary>Session with a case created under dir, quiet console, and a fixed clock.</summary>
        public static FotonSession New(string dir, bool elevated = false, SessionOptions? options = null)
        {
            var log = new StatusLog(new StringWriter()) { UtcNow = () => Start };
            var s = new FotonSession(options ?? new SessionOptions { Examiner = "examiner", CaseNumber = "CASE-0001" }, Start, "HOST", @"DOMAIN\user", elevated, log);
            CaseLayout.Create(s, dir);
            return s;
        }
    }
}
