using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// The Scoop manifest (bucket\foton.json) installs what a release ships: the four executables the solution builds,
    /// from the release's all-in-one ZIP, pinned by SHA-256. packaging\update-scoop.ps1 moves it to a new release.
    /// </summary>
    public class PackagingRules
    {
        static string Manifest => File.ReadAllText(Path.Combine(Repo.Root, "bucket", "foton.json"));

        [Fact]
        public void Scoop_installs_exactly_the_four_executables()
        {
            var bin = Regex.Match(Manifest, @"""bin"":\s*\[(?<list>[^\]]*)\]").Groups["list"].Value;
            var listed = Regex.Matches(bin, @"""([^""]+)""").Cast<Match>().Select(m => m.Groups[1].Value).OrderBy(n => n).ToList();
            var built = Repo.Projects.Values.Where(p => p.IsExe).Select(p => p.AssemblyName + ".exe").OrderBy(n => n).ToList();
            Assert.Equal(built, listed);
        }

        [Fact]
        public void Scoop_points_at_a_release_ZIP_pinned_by_SHA256()
        {
            var version = Regex.Match(Manifest, @"""version"":\s*""(\d+\.\d+\.\d+)""").Groups[1].Value;
            Assert.NotEqual("", version);
            Assert.Matches(@"""url"":\s*""https://github\.com/jimididit/foton/releases/download/v" + Regex.Escape(version) + "/Foton-" + Regex.Escape(version) + @"-windows\.zip""", Manifest);
            Assert.Matches(@"""hash"":\s*""[0-9a-f]{64}""", Manifest);
            Assert.Contains("/download/v$version/Foton-$version-windows.zip", Manifest);
            Assert.Contains("/download/v$version/SHA256SUMS.txt", Manifest);
        }
    }
}
