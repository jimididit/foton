using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Foton.Core
{
    /// <summary>Locating a case root, and case folders embedded inside a case.</summary>
    public static class CaseTree
    {
        public const string CollectionFolder = "00_Collection";

        /// <summary>The folder itself if it holds 00_Collection, else the first child that does; null if none.</summary>
        public static string? FindCaseRoot(string searchRoot)
        {
            if (!Directory.Exists(searchRoot)) return null;
            if (Directory.Exists(Path.Combine(searchRoot, CollectionFolder))) return searchRoot;
            return ChildCases(searchRoot).FirstOrDefault();
        }

        /// <summary>Child folders that hold their own 00_Collection, in ordinal order.</summary>
        public static IReadOnlyList<string> ChildCases(string? caseRoot)
        {
            if (caseRoot == null || !Directory.Exists(caseRoot)) return new string[0];
            return Directory.GetDirectories(caseRoot).OrderBy(d => d, System.StringComparer.OrdinalIgnoreCase)
                .Where(d => Directory.Exists(Path.Combine(d, CollectionFolder))).ToList();
        }

        /// <summary>
        /// The "package contains a copy of itself" duplicate: a child case folder with the same name as the
        /// case, or whose hashes.csv is byte-identical (extracted into the case and re-zipped in transit).
        /// Recursive walks skip it so artifacts are not counted twice. Any other embedded case folder is not
        /// a duplicate (see OtherChildCases): it is reported, never silently treated as a copy.
        /// </summary>
        public static string? FindNestedDuplicate(string? caseRoot) =>
            ChildCases(caseRoot).FirstOrDefault(c => IsDuplicateOf(c, caseRoot!));

        /// <summary>Embedded case folders that are not a verified copy of this case.</summary>
        public static IReadOnlyList<string> OtherChildCases(string? caseRoot) =>
            ChildCases(caseRoot).Where(c => !IsDuplicateOf(c, caseRoot!)).ToList();

        static bool IsDuplicateOf(string child, string root)
        {
            if (string.Equals(Path.GetFileName(child), Path.GetFileName(root.TrimEnd('\\', '/')), System.StringComparison.OrdinalIgnoreCase))
                return true;
            var a = Path.Combine(child, CollectionFolder, "hashes.csv");
            var b = Path.Combine(root, CollectionFolder, "hashes.csv");
            if (!File.Exists(a) || !File.Exists(b)) return false;
            try { return File.ReadAllBytes(a).SequenceEqual(File.ReadAllBytes(b)); }
            catch (IOException) { return false; }
            catch (System.UnauthorizedAccessException) { return false; }
        }

        /// <summary>True when path is inside root. Both are normalized, so / and \ forms compare equal.</summary>
        public static bool IsUnder(string path, string? root)
        {
            if (root == null) return false;
            var r = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return Path.GetFullPath(path).StartsWith(r, System.StringComparison.OrdinalIgnoreCase);
        }
    }
}
