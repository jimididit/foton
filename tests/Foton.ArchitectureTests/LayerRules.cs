using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// The layer split as compile-time facts. Collect and Baseline capture touch a live host;
    /// everything else runs offline, and endpoint executables carry no workstation code.
    /// New projects with these names are covered as soon as they are added.
    /// </summary>
    public class LayerRules
    {
        // Must never read live state or hit the network: no Foton.Win, no WMI, no HTTP.
        static readonly string[] Offline =
        {
            "Foton.Core", "Foton.Report", "Foton.Package", "Foton.Baseline.Compare",
            "Foton.Analyze", "Foton.Patterns", "Foton.Parse", "Foton.Carve",
        };

        // Endpoint executables must not ship parsers, compose/install code, or the pattern list.
        static readonly string[] EndpointExes = { "Foton.Collect.Cli", "Foton.Baseline.Cli" };
        static readonly string[] WorkstationOnly = { "Foton.Parse", "Foton.Carve", "Foton.Tools", "Foton.Patterns" };

        [Fact]
        public void Projects_were_found()
        {
            Assert.Contains("Foton.Core", Repo.Projects.Keys);
            Assert.Contains("Foton.Cli", Repo.Projects.Keys);
        }

        [Fact]
        public void Offline_layers_never_reach_the_live_host_or_network()
        {
            foreach (var name in Offline.Where(Repo.Projects.ContainsKey))
            {
                var closure = Repo.Closure(name);
                Assert.False(closure.Contains("Foton.Win"), name + " must not reference Foton.Win (live-host access).");
                var fx = Repo.FrameworkRefsOf(closure).ToList();
                Assert.False(fx.Any(r => r.StartsWith("System.Management", StringComparison.OrdinalIgnoreCase)), name + " must not reference System.Management (WMI).");
                Assert.False(fx.Any(r => r.StartsWith("System.Net.Http", StringComparison.OrdinalIgnoreCase)), name + " must not reference System.Net.Http.");
            }
        }

        [Fact]
        public void Endpoint_executables_carry_no_workstation_code()
        {
            foreach (var exe in EndpointExes.Where(Repo.Projects.ContainsKey))
            {
                var closure = Repo.Closure(exe);
                foreach (var banned in WorkstationOnly)
                    Assert.False(closure.Contains(banned), exe + " must not reference " + banned + ".");
            }
        }

        [Fact]
        public void Only_Foton_Tools_uses_HTTP()
        {
            foreach (var p in Repo.Projects.Values.Where(p => p.Name != "Foton.Tools"))
                Assert.False(p.FrameworkRefs.Any(r => r.StartsWith("System.Net.Http", StringComparison.OrdinalIgnoreCase)),
                    p.Name + " references System.Net.Http; only Foton.Tools (pinned tool install) may.");
        }

        [Fact]
        public void PInvoke_lives_only_in_Foton_Win()
        {
            var win = Path.Combine(Repo.Root, "src", "Foton.Win") + Path.DirectorySeparatorChar;
            var offenders = Repo.SourceFiles()
                .Where(f => !f.StartsWith(win, StringComparison.OrdinalIgnoreCase))
                // Any extern method, or the attribute in any spelling (aliased, namespace-qualified, ...Attribute).
                .Where(f => Regex.IsMatch(File.ReadAllText(f),
                    @"\bstatic\s+extern\b|\bextern\s+static\b|\[\s*(?:[\w.]+\.)?(?:DllImport|LibraryImport)(?:Attribute)?\b"))
                .ToList();
            Assert.True(offenders.Count == 0, "P/Invoke outside Foton.Win: " + string.Join(", ", offenders));
        }

        [Fact]
        public void Nothing_loads_assemblies_from_memory()
        {
            // Assembly.Load(byte[]) is AMSI-scanned on .NET 4.8 and is the classic in-memory loader pattern.
            // Load by name (string literal) is allowed; AssemblyResolve hooks are the embedding pattern.
            var bad = new Regex(@"Assembly\s*\.\s*Load\s*\(\s*[^""\s)]|AssemblyResolve\s*\+=");
            var offenders = Repo.SourceFiles().Where(f => bad.IsMatch(File.ReadAllText(f))).ToList();
            Assert.True(offenders.Count == 0, "In-memory assembly loading: " + string.Join(", ", offenders));
        }

        [Fact]
        public void Every_project_targets_in_box_net462()
        {
            foreach (var p in Repo.Projects.Values)
            {
                var xml = File.ReadAllText(p.Path);
                Assert.False(Regex.IsMatch(xml, @"<TargetFrameworks?>(?!net462<)"), p.Name + " overrides TargetFramework; endpoints must run on in-box .NET Framework 4.6.2+.");
            }
        }
    }
}
