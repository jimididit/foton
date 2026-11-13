using System;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// Foton.Win.Ui lets the console draw its title bar and scroll bars dark without referencing Foton.Win. These rules
    /// keep it to that: the two documented window-appearance calls, no other Foton project, and nothing that reads the
    /// host (registry, files, processes, WMI, network). Adding a call means editing the list here, in review.
    /// </summary>
    public class UiRules
    {
        const string Ui = "Foton.Win.Ui";

        static readonly string[] AllowedImports = { "dwmapi.dll!DwmSetWindowAttribute", "uxtheme.dll!SetWindowTheme" };

        // Namespaces whose calls would read or change the host.
        static readonly string[] HostNamespaces = { "Microsoft.Win32", "System.IO", "System.Net", "System.Management", "System.Diagnostics" };

        [Fact]
        public void Ui_references_no_Foton_project_and_only_System_Drawing()
        {
            Assert.True(Repo.Projects.ContainsKey(Ui), Ui + " project not found.");
            var p = Repo.Projects[Ui];
            Assert.True(p.ProjectRefs.Count == 0, Ui + " references " + string.Join(", ", p.ProjectRefs) + "; it must stand alone.");
            Assert.True(p.AssemblyRefs.All(r => r == "System.Drawing"), Ui + " references " + string.Join(", ", p.AssemblyRefs) + "; only System.Drawing is expected.");
        }

        [Fact]
        public void Only_the_console_uses_Ui()
        {
            var users = Repo.Projects.Values.Where(p => p.ProjectRefs.Contains(Ui, StringComparer.OrdinalIgnoreCase)).Select(p => p.Name).ToList();
            Assert.Equal(new[] { "Foton.Gui" }, users);
        }

        static Assembly Built()
        {
            var asm = Repo.LoadBuilt(Repo.Projects[Ui].IntermediateAssembly);
            Assert.True(asm != null, Ui + " not built (" + Repo.Configuration + ").");
            return asm!;
        }

        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;

        [Fact]
        public void Ui_imports_only_the_two_window_appearance_calls()
        {
            var imports = Built().GetTypes()
                .SelectMany(t => t.GetMethods(All))
                .Where(m => (m.Attributes & MethodAttributes.PinvokeImpl) != 0)
                .Select(m => m.GetCustomAttribute<DllImportAttribute>()!.Value.ToLowerInvariant() + "!" + m.Name)
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToList();
            Assert.Equal(AllowedImports.OrderBy(s => s, StringComparer.Ordinal), imports);
            Assert.DoesNotContain(Built().GetTypes(), t => t.IsImport);
        }

        [Fact]
        public void Ui_never_calls_into_the_registry_files_processes_WMI_or_network()
        {
            int scanned = 0;
            foreach (var t in Built().GetTypes())
                foreach (var m in t.GetMethods(All).Cast<MethodBase>().Concat(t.GetConstructors(All)))
                {
                    scanned++;
                    foreach (var callee in IlReader.Callees(m))
                    {
                        var ns = callee.DeclaringType?.Namespace ?? "";
                        Assert.False(HostNamespaces.Any(h => ns == h || ns.StartsWith(h + ".", StringComparison.Ordinal)),
                            Ui + ": " + t.FullName + "." + m.Name + " calls " + callee.DeclaringType + "." + callee.Name + ".");
                    }
                }
            Assert.True(scanned > 0, "No methods scanned; the rule would pass vacuously.");
        }
    }
}
