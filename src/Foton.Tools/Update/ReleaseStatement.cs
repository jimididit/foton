using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Tools.Update
{
    /// <summary>
    /// foton-release.json, the statement the owner signs offline: product, version, release date, and the SHA-256 of the
    /// release ZIP and of each executable. Parsed only after its signature verified; still strict, because its names
    /// become file names and its hashes are the only thing the downloaded files are trusted against.
    /// </summary>
    public sealed class ReleaseStatement
    {
        public const int MaxBytes = 64 * 1024;

        /// <summary>Every release carries these; a statement without one of them is refused.</summary>
        public static readonly IReadOnlyList<string> RequiredFiles = new[] { "foton-baseline.exe", "foton-collect.exe", "foton-console.exe", "foton.exe" };

        // \z, not $: in .NET, $ also matches before a final newline, which would let "foton.exe\n" through.
        static readonly Regex VersionPattern = new Regex(@"^\d{1,4}\.\d{1,4}\.\d{1,4}\z", RegexOptions.CultureInvariant);
        static readonly Regex HashPattern = new Regex(@"^[0-9a-f]{64}\z", RegexOptions.CultureInvariant);
        static readonly Regex ExeName = new Regex(@"^foton(-[a-z]+)?\.exe\z", RegexOptions.CultureInvariant);

        public string Version { get; private set; } = "";
        public DateTime Released { get; private set; }
        public string ReleasedText => Released.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        public string ZipName { get; private set; } = "";
        public string ZipSha256 { get; private set; } = "";
        /// <summary>Executable name to SHA-256 (lowercase hex), ordinal names.</summary>
        public IReadOnlyDictionary<string, string> Files { get; private set; } = new Dictionary<string, string>();

        /// <summary>Parses the signed bytes. Throws InvalidDataException naming the first thing that is wrong.</summary>
        public static ReleaseStatement Parse(byte[] bytes)
        {
            if (bytes.Length == 0 || bytes.Length > MaxBytes) throw Bad("its size is outside 1 byte to 64 KB");
            string text;
            try { text = new UTF8Encoding(false, true).GetString(bytes); }
            catch (DecoderFallbackException) { throw Bad("it is not UTF-8"); }
            object? parsed;
            try { parsed = Json.Parse(text); }
            catch (ArgumentException) { throw Bad("it is not JSON"); }
            catch (InvalidOperationException) { throw Bad("it is not JSON"); }
            if (!(parsed is IDictionary<string, object> root)) throw Bad("it is not a JSON object");

            if (Text(root, "product") != "Foton") throw Bad("product is not Foton");
            var version = Text(root, "version");
            if (!VersionPattern.IsMatch(version)) throw Bad("version is not X.Y.Z");
            if (!DateTime.TryParseExact(Text(root, "released"), "yyyy-MM-dd", CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var released))
                throw Bad("released is not yyyy-MM-dd");
            if (!(Field(root, "zip") is IDictionary<string, object> zip)) throw Bad("zip is missing");
            var zipName = Text(zip, "name");
            if (zipName != "Foton-" + version + "-windows.zip") throw Bad("the ZIP is not named Foton-" + version + "-windows.zip");
            var zipSha = Text(zip, "sha256");
            if (!HashPattern.IsMatch(zipSha)) throw Bad("the ZIP's SHA-256 is not 64 lowercase hex characters");
            if (!(Field(root, "files") is IDictionary<string, object> filesObj)) throw Bad("files is missing");
            var files = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var pair in filesObj)
            {
                if (!ExeName.IsMatch(pair.Key)) throw Bad("it lists an unexpected file name '" + TextFile.OneLine(pair.Key) + "'");
                if (!(pair.Value is string hash) || !HashPattern.IsMatch(hash)) throw Bad("the SHA-256 of " + pair.Key + " is not 64 lowercase hex characters");
                files[pair.Key] = hash;
            }
            var missing = RequiredFiles.FirstOrDefault(f => !files.ContainsKey(f));
            if (missing != null) throw Bad("it does not list " + missing);
            return new ReleaseStatement { Version = version, Released = released, ZipName = zipName, ZipSha256 = zipSha, Files = files };
        }

        static object? Field(IDictionary<string, object> obj, string name) => obj.TryGetValue(name, out var v) ? v : null;
        static string Text(IDictionary<string, object> obj, string name) => Field(obj, name) as string ?? "";
        static InvalidDataException Bad(string why) => new InvalidDataException("foton-release.json is not valid: " + why + ".");
    }
}
