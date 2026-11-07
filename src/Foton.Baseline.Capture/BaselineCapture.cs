using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Foton.Core;

namespace Foton.Baseline.Capture
{
    /// <summary>One coverage.json provider row.</summary>
    public sealed class ProviderCoverage
    {
        public string RecordType { get; set; } = "";
        public string Status { get; set; } = "";
        public int Count { get; set; }
        public string Error { get; set; } = "";
    }

    public sealed class CaptureResult
    {
        public BaselineDocument Document { get; internal set; } = new BaselineDocument();
        public List<ProviderCoverage> Coverage { get; } = new List<ProviderCoverage>();
    }

    /// <summary>
    /// Captures a normalized snapshot of stable configuration (New-FotonBaseline). Live reads only; volatile
    /// state (PIDs, connections, uptime, sessions) is excluded. A snapshot taken after an intrusion is a
    /// picture of that state: a later diff proves change between observations, never when or who.
    /// </summary>
    public static class BaselineCapture
    {
        public static CaptureResult Capture(FotonSession session)
        {
            var ctx = new CaptureContext(session.IsElevated);
            var result = new CaptureResult();
            var doc = result.Document;
            foreach (var p in Providers.All)
            {
                doc.Providers.Add(p.Meta);
                List<Dictionary<string, object?>> rows;
                string status = "Success", error = "";
                try { rows = p.Run(ctx); }
                catch (Exception ex)
                {
                    rows = new List<Dictionary<string, object?>>();
                    status = "Error";
                    error = ex.Message;
                    session.Status.Write($"Baseline provider {p.RecordType} failed: {error}", StatusLevel.Warn);
                }
                var gaps = ctx.TakeGaps();
                if (gaps.Count > 0 && status == "Success")
                {
                    // Some reads failed; the rows that were read are kept. Zero records here is not "nothing configured".
                    status = "Partial";
                    error = string.Join("; ", gaps);
                    session.Status.Write($"Baseline provider {p.RecordType} read partially: {error}", StatusLevel.Warn);
                }
                doc.Records[p.RecordType] = rows;
                result.Coverage.Add(new ProviderCoverage { RecordType = p.RecordType, Status = status, Count = rows.Count, Error = error });
            }
            doc.Header = new BaselineHeader
            {
                BaselineSchemaVersion = FotonVersion.BaselineSchema,
                ToolVersion = session.Version,
                Hostname = session.Hostname,
                CapturedUtc = FotonTime.Format(session.StartTimeUtc),
                Elevated = session.IsElevated,
                PayloadSha256 = doc.ComputePayloadSha256(),
                Note = BaselineDocument.HeaderNote,
            };
            return result;
        }

        /// <summary>A bare snapshot JSON (scripts and Compare inputs). Returns the full path.</summary>
        public static string WriteJson(CaptureResult r, string path)
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(path));
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            TextFile.Write(path, r.Document.ToJson());
            return Path.GetFullPath(path);
        }

        public sealed class PackageResult
        {
            public string Root { get; internal set; } = "";
            public string JsonPath { get; internal set; } = "";
            public string? ZipPath { get; internal set; }
            public string? ZipSha256 { get; internal set; }
        }

        /// <summary>
        /// Writes the package folder (baseline.json, coverage.json; the session must already own the folder via
        /// BaselineLayout.Create), hashes every file, then optionally ZIPs it with a package integrity record.
        /// </summary>
        public static PackageResult WritePackage(FotonSession session, CaptureResult r, bool zip, Action<string>? beforeHashing = null)
        {
            var root = session.CaseRoot ?? throw new InvalidOperationException("Call BaselineLayout.Create first.");
            var json = Path.Combine(root, "baseline.json");
            TextFile.Write(json, r.Document.ToJson());
            TextFile.Write(Path.Combine(root, "coverage.json"), Json.Indented(new Dictionary<string, object?>
            {
                ["Elevated"] = session.IsElevated,
                ["BaselineSchemaVersion"] = r.Document.Header.BaselineSchemaVersion,
                ["ToolVersion"] = r.Document.Header.ToolVersion,
                ["CapturedUtc"] = r.Document.Header.CapturedUtc,
                ["Providers"] = r.Coverage,
            }));
            beforeHashing?.Invoke(root);
            PackageFiles.WriteArtifactHashes(session);
            var result = new PackageResult { Root = root, JsonPath = json };
            if (!zip) return result;
            result.ZipPath = PackageFiles.CompressCase(session);
            if (result.ZipPath != null)
            {
                try { result.ZipSha256 = Hashing.Sha256Hex(result.ZipPath); } catch (Exception) { result.ZipSha256 = "HASH_ERROR"; }
                TextFile.WriteLines(root + "_PACKAGE_HASH.txt", new[]
                {
                    "Foton baseline package integrity record",
                    "Folder   : " + TextFile.OneLine(root),
                    "ZIP      : " + TextFile.OneLine(result.ZipPath),
                    "SHA-256  : " + result.ZipSha256,
                    "UTC      : " + FotonTime.Format(session.StartTimeUtc),
                });
                session.Status.WriteConsole("    [+] Package SHA-256: " + result.ZipSha256, ConsoleColor.Green);
            }
            return result;
        }
    }
}
