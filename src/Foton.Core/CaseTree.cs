using System.IO;
using System.Linq;

namespace Foton.Core
{
    /// <summary>Locating a case root and the "package contains a copy of itself" duplicate.</summary>
    public static class CaseTree
    {
        public const string CollectionFolder = "00_Collection";

        /// <summary>The folder itself if it holds 00_Collection, else the first child that does; null if none.</summary>
        public static string? FindCaseRoot(string searchRoot)
        {
            if (!Directory.Exists(searchRoot)) return null;
            if (Directory.Exists(Path.Combine(searchRoot, CollectionFolder))) return searchRoot;
            return Directory.GetDirectories(searchRoot).OrderBy(d => d, System.StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault(d => Directory.Exists(Path.Combine(d, CollectionFolder)));
        }

        /// <summary>
        /// A well-formed package has one 00_Collection. Some arrive with the whole tree copied inside
        /// itself (extracted into the case folder, re-zipped in transit); the inner hashes.csv is
        /// byte-identical. Returns that inner copy so recursive walks skip it instead of counting
        /// every artifact twice.
        /// </summary>
        public static string? FindNestedDuplicate(string? caseRoot)
        {
            if (caseRoot == null || !Directory.Exists(caseRoot)) return null;
            return Directory.GetDirectories(caseRoot).OrderBy(d => d, System.StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault(d => Directory.Exists(Path.Combine(d, CollectionFolder)));
        }

        /// <summary>True when path is inside root. Both are normalized, so / and \ forms compare equal.</summary>
        public static bool IsUnder(string path, string? root)
        {
            if (root == null) return false;
            var r = Path.GetFullPath(root).TrimEnd('\\') + "\\";
            return Path.GetFullPath(path).StartsWith(r, System.StringComparison.OrdinalIgnoreCase);
        }
    }
}
