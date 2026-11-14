using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// Published text uses hyphens, never en or em dashes (house style for docs, release notes, and code). Covers the
    /// public docs, brand notes, packaging, workflows, and all source and tests; local-only notes are not published.
    /// </summary>
    public class TextRules
    {
        static readonly string[] RootFiles = { "README.md", "CHANGELOG.md", "SECURITY.md" };
        static readonly string[] PublicDocs = { "USAGE.md", "GETTING-STARTED.md", "CONTRIBUTING.md", "CARVE.md", "README.md" };
        static readonly string[] Folders = { "src", "cli", "tests", "assets", "packaging", "bucket", ".github" };
        static readonly string[] Extensions = { ".md", ".txt", ".cs", ".csproj", ".targets", ".props", ".yml", ".yaml", ".json", ".svg", ".ps1", ".py", ".xml", ".html", ".css", ".js" };

        static IEnumerable<string> Published()
        {
            foreach (var f in RootFiles) yield return Path.Combine(Repo.Root, f);
            foreach (var f in PublicDocs) yield return Path.Combine(Repo.Root, "docs", f);
            foreach (var folder in Folders.Select(f => Path.Combine(Repo.Root, f)).Where(Directory.Exists))
                foreach (var f in Directory.GetFiles(folder, "*", SearchOption.AllDirectories))
                    if (Extensions.Contains(Path.GetExtension(f), StringComparer.OrdinalIgnoreCase)
                        && !f.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar)
                        && !f.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar))
                        yield return f;
        }

        [Fact]
        public void Published_text_uses_hyphens_not_en_or_em_dashes()
        {
            var offenders = new List<string>();
            var scanned = 0;
            foreach (var file in Published().Where(File.Exists))
            {
                scanned++;
                var lines = File.ReadAllLines(file);
                for (int i = 0; i < lines.Length; i++)
                    if (lines[i].IndexOf('\u2013') >= 0 || lines[i].IndexOf('\u2014') >= 0)
                        offenders.Add(file.Substring(Repo.Root.Length + 1) + ":" + (i + 1));
            }
            Assert.True(scanned > 50, "Only " + scanned + " files scanned; the rule would pass vacuously.");
            Assert.True(offenders.Count == 0, "En or em dash (use a hyphen, colon, or comma): " + string.Join(", ", offenders));
        }
    }
}
