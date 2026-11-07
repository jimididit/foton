using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml.Linq;
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
                var fx = Repo.AssemblyRefsOf(closure).ToList();
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
        public void Analyze_takes_pattern_lists_as_input_so_the_endpoint_can_run_it()
        {
            // Collect runs analysis at the end of a triage; the suspicious-command list must never ride along.
            if (Repo.Projects.ContainsKey("Foton.Analyze"))
                Assert.False(Repo.Closure("Foton.Analyze").Contains("Foton.Patterns"), "Foton.Analyze must not reference Foton.Patterns; pass the lists in.");
        }

        [Fact]
        public void Only_Foton_Tools_uses_HTTP()
        {
            foreach (var p in Repo.Projects.Values.Where(p => p.Name != "Foton.Tools"))
                Assert.False(p.AssemblyRefs.Any(r => r.StartsWith("System.Net.Http", StringComparison.OrdinalIgnoreCase)),
                    p.Name + " references System.Net.Http; only Foton.Tools (pinned tool install) may.");
        }

        [Fact]
        public void Product_projects_have_no_package_references()
        {
            // Runtime dependencies must be in-box .NET Framework assemblies. Build-time packages
            // (reference assemblies, ILRepack) come from Directory.Build.props / cli\Directory.Build.targets.
            foreach (var p in Repo.Projects.Values)
                Assert.True(p.PackageRefs.Count == 0, p.Name + " has PackageReference " + string.Join(", ", p.PackageRefs) + "; executables ship no NuGet DLLs.");
        }

        [Fact]
        public void Product_projects_reference_framework_assemblies_by_name_only()
        {
            // A <Reference> with a HintPath is a third-party DLL that ILRepack would quietly merge into the exe.
            foreach (var p in Repo.Projects.Values)
            {
                var hinted = XDocument.Load(p.Path).Descendants("Reference")
                    .Where(r => r.Elements("HintPath").Any() || r.Attribute("HintPath") != null)
                    .Select(r => (string)r.Attribute("Include")!).ToList();
                Assert.True(hinted.Count == 0, p.Name + " references a DLL by path: " + string.Join(", ", hinted) + "; only in-box framework assemblies are allowed.");
            }
        }

        [Fact]
        public void Central_packages_are_build_or_test_time_only()
        {
            // Adding a package means editing this allowlist on purpose, in review.
            var allowed = new[]
            {
                "Microsoft.NETFramework.ReferenceAssemblies", "ILRepack.Lib.MSBuild.Task",
                "Microsoft.NET.Test.Sdk", "xunit", "xunit.runner.visualstudio",
            };
            var doc = XDocument.Load(Path.Combine(Repo.Root, "Directory.Packages.props"));
            var names = doc.Descendants("PackageVersion").Select(e => (string)e.Attribute("Include")!).ToList();
            var extra = names.Where(n => !allowed.Contains(n, StringComparer.OrdinalIgnoreCase)).ToList();
            Assert.True(extra.Count == 0, "Unreviewed central package(s): " + string.Join(", ", extra));
        }

        [Fact]
        public void PInvoke_and_COM_imports_are_written_only_in_Foton_Win()
        {
            // Fast source check. BinaryRules checks the compiled IL, which catches any spelling.
            var win = Path.Combine(Repo.Root, "src", "Foton.Win") + Path.DirectorySeparatorChar;
            var pattern = new Regex(
                @"\bextern\b(?!\s+alias\b)|\[\s*(?:[\w.]+\.)?(?:DllImport|LibraryImport|ComImport)(?:Attribute)?\b");
            var offenders = Repo.SourceFiles()
                .Where(f => !f.StartsWith(win, StringComparison.OrdinalIgnoreCase))
                .Where(f => pattern.IsMatch(File.ReadAllText(f)))
                .ToList();
            Assert.True(offenders.Count == 0, "P/Invoke or COM import outside Foton.Win: " + string.Join(", ", offenders));
        }

        [Fact]
        public void Nothing_is_written_to_load_assemblies_from_memory()
        {
            // Fast source check; BinaryRules scans the IL for the byte[] overloads.
            // Assembly/AppDomain Load or ReflectionOnlyLoad with anything but a string literal, or an
            // AssemblyResolve hook (the embed-and-load pattern).
            var bad = new Regex(
                @"\b(?:Assembly|AppDomain(?:\s*\.\s*CurrentDomain)?)\s*\.\s*(?:Load|ReflectionOnlyLoad)\s*\(\s*[^""\s)]|AssemblyResolve\s*\+=");
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
