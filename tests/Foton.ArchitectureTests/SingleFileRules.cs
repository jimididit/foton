using System.IO;
using System.Linq;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>Each role ships as one executable: a Release build output holds the exe and no loose DLL.</summary>
    public class SingleFileRules
    {
        [Theory]
        [InlineData("Foton.Collect.Cli", "foton-collect.exe")]
        [InlineData("Foton.Baseline.Cli", "foton-baseline.exe")]
        [InlineData("Foton.Cli", "foton.exe")]
        public void Release_output_is_one_exe(string project, string exe)
        {
#if DEBUG
            // ILRepack merges in Release only; CI runs these tests with -c Release.
            return;
#else
            var output = Path.Combine(Repo.Root, "cli", project, "bin", "Release", "net462");
            Assert.True(File.Exists(Path.Combine(output, exe)), exe + " missing; build the solution with -c Release first.");
            var dlls = Directory.GetFiles(output, "*.dll").Select(Path.GetFileName).ToList();
            Assert.True(dlls.Count == 0, exe + " has loose DLLs (ILRepack did not merge): " + string.Join(", ", dlls));
            Assert.Single(Directory.GetFiles(output, "*.exe"));
#endif
        }
    }
}
