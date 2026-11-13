using System;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// foton.exe and foton-console.exe carry the endpoint collectors as data (cli\EmbedCollectors.targets) so the analyst
    /// program can build bundles. That is the one link from a workstation executable to a collector project, and it must
    /// stay build order only: no collector code is referenced or merged (LayerRules and BinaryRules still hold), and
    /// what is embedded is exactly what the release publishes.
    /// </summary>
    public class EmbeddedCollectorRules
    {
        static readonly string Targets = Path.Combine(Repo.Root, "cli", "EmbedCollectors.targets");

        [Fact]
        public void The_collector_link_is_build_order_only_and_only_the_workstation_executables_have_it()
        {
            var refs = XDocument.Load(Targets).Descendants("ProjectReference").ToList();
            Assert.Equal(new[] { "Foton.Baseline.Cli", "Foton.Collect.Cli" },
                refs.Select(r => Path.GetFileNameWithoutExtension((string)r.Attribute("Include")!.Value.Replace('\\', Path.DirectorySeparatorChar))).OrderBy(n => n, StringComparer.Ordinal));
            Assert.All(refs, r => Assert.Equal("false", (string?)r.Attribute("ReferenceOutputAssembly")));

            var importers = Repo.Projects.Values
                .Where(p => XDocument.Load(p.Path).Descendants("Import").Any(i => ((string?)i.Attribute("Project") ?? "").EndsWith("EmbedCollectors.targets", StringComparison.OrdinalIgnoreCase)))
                .Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal);
            Assert.Equal(new[] { "Foton.Cli", "Foton.Gui" }, importers);
        }

        [Theory]
        [InlineData("Foton.Cli", "foton-collect.exe", "Foton.Collect.Cli")]
        [InlineData("Foton.Cli", "foton-baseline.exe", "Foton.Baseline.Cli")]
        [InlineData("Foton.Gui", "foton-collect.exe", "Foton.Collect.Cli")]
        [InlineData("Foton.Gui", "foton-baseline.exe", "Foton.Baseline.Cli")]
        public void The_embedded_collector_is_byte_for_byte_the_published_one(string carrier, string collector, string collectorProject)
        {
            var host = Repo.LoadBuilt(Repo.Projects[carrier].OutputAssembly);
            Assert.True(host != null, carrier + " is not built (" + Repo.Configuration + ").");
            var published = File.ReadAllBytes(Repo.Projects[collectorProject].OutputAssembly);
            using (var stream = host!.GetManifestResourceStream("Foton.Collectors." + collector))
            {
                Assert.True(stream != null, Repo.Projects[carrier].AssemblyName + " does not carry " + collector + ".");
                var embedded = new byte[stream!.Length];
                int read = 0, n;
                while (read < embedded.Length && (n = stream.Read(embedded, read, embedded.Length - read)) > 0) read += n;
                Assert.Equal(published, embedded);
            }
        }
    }
}
