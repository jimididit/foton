using System.Linq;
using System.Reflection;

namespace Foton.Core
{
    /// <summary>
    /// Product and schema versions, set once in Directory.Build.props. Replaces Get-FotonVersion.
    /// Read from assembly metadata so a version can never be a stale literal in code.
    /// </summary>
    public static class FotonVersion
    {
        static readonly Assembly Self = typeof(FotonVersion).Assembly;

        /// <summary>Semantic version including any prerelease tag, for example 2.0.0-alpha.0.</summary>
        public static string Product
        {
            get
            {
                var info = Self.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";
                int plus = info.IndexOf('+');
                return plus < 0 ? info : info.Substring(0, plus);
            }
        }

        /// <summary>Source commit the build came from (empty for local builds without git metadata).</summary>
        public static string Commit
        {
            get
            {
                var info = Self.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "";
                int plus = info.IndexOf('+');
                return plus < 0 ? "" : info.Substring(plus + 1);
            }
        }

        public static string CollectSchema => Metadata("FotonCollectSchemaVersion");
        public static string BaselineSchema => Metadata("FotonBaselineSchemaVersion");
        public static string FindingsSchema => Metadata("FotonFindingsSchemaVersion");
        public static string NotesSchema => Metadata("FotonNotesSchemaVersion");

        /// <summary>UTC date (yyyy-MM-dd) of the change that set the version; the banner's Updated line.</summary>
        public static string ReleaseDate => Metadata("FotonReleaseDate");

        /// <summary>The lines every executable prints for -Version, in the Get-FotonVersion order.</summary>
        public static string[] Describe(string executable) => new[]
        {
            executable + " " + Product + (Commit.Length > 0 ? " (" + Commit + ")" : ""),
            "Collect schema  " + CollectSchema,
            "Baseline schema " + BaselineSchema,
            "Findings schema " + FindingsSchema,
        };

        static string Metadata(string key) =>
            Self.GetCustomAttributes<AssemblyMetadataAttribute>().FirstOrDefault(a => a.Key == key)?.Value ?? "unknown";
    }
}
