using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Xunit;

namespace Foton.ArchitectureTests
{
    /// <summary>
    /// Rules checked against compiled IL rather than source text, so they hold however the code is
    /// spelled. They need the solution built in the test's configuration (CI: -c Release).
    /// </summary>
    public class BinaryRules
    {
        // Strong-name keys of Microsoft framework assemblies (mscorlib/System*, Microsoft.*, System.Web.*, facades).
        static readonly string[] FrameworkKeys = { "b77a5c561934e089", "31bf3856ad364e35", "b03f5f7f11d50a3a", "cc7b13ffcd2ddd51" };

        static IEnumerable<(ProjectInfo Project, Assembly Assembly)> Built(Func<ProjectInfo, string> path)
        {
            foreach (var p in Repo.Projects.Values)
            {
                var asm = Repo.LoadBuilt(path(p));
                // Missing output fails in every configuration: these rules must never pass by not looking.
                Assert.True(asm != null, path(p) + " missing; build the solution (" + Repo.Configuration + ") first.");
                yield return (p, asm!);
            }
        }

        // Fail closed: a type that cannot load is a type these rules cannot inspect.
        static IEnumerable<Type> TypesOf(Assembly a)
        {
            try { return a.GetTypes(); }
            catch (ReflectionTypeLoadException e)
            {
                var why = string.Join("; ", e.LoaderExceptions.Select(x => x?.Message).Distinct());
                throw new InvalidOperationException(a.GetName().Name + ": types failed to load, so they cannot be checked: " + why, e);
            }
        }

        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;

        static string Token(AssemblyName n) =>
            string.Concat((n.GetPublicKeyToken() ?? new byte[0]).Select(b => b.ToString("x2")));

        [Fact]
        public void In_box_assembly_set_was_loaded()
        {
            // Guards the rule below against passing vacuously on a broken lookup.
            Assert.True(Repo.InBoxAssemblyNames.Count > 100, "Only " + Repo.InBoxAssemblyNames.Count + " net462 reference assemblies found.");
            Assert.Contains("System.Management", Repo.InBoxAssemblyNames);
            Assert.DoesNotContain("System.Memory", Repo.InBoxAssemblyNames);
        }

        [Fact]
        public void Shipped_executables_reference_only_in_box_framework_assemblies()
        {
            foreach (var (p, asm) in Built(p => p.OutputAssembly).Where(x => x.Project.IsExe))
            {
                foreach (var r in asm.GetReferencedAssemblies())
                {
                    Assert.False(r.Name.StartsWith("Foton", StringComparison.OrdinalIgnoreCase), p.AssemblyName + " still references " + r.Name + " (not merged).");
                    // Name must be in the net462 in-box set AND carry a Microsoft framework key: a Microsoft-signed
                    // NuGet package (System.Memory, System.Text.Json, ...) has the key but is not in-box.
                    Assert.True(Repo.InBoxAssemblyNames.Contains(r.Name) && FrameworkKeys.Contains(Token(r)),
                        p.AssemblyName + " references " + r.FullName + ", which is not an in-box .NET Framework 4.6.2 assembly.");
                }
                // Only the workstation executables carry Foton.Tools' pinned, hash-checked tool download; endpoints never do.
                if (p.Name != "Foton.Cli" && p.Name != "Foton.Gui")
                    Assert.DoesNotContain(asm.GetReferencedAssemblies(), r => r.Name.Equals("System.Net.Http", StringComparison.OrdinalIgnoreCase));
            }
        }

        [Fact]
        public void PInvoke_and_COM_imports_are_compiled_only_into_Foton_Win()
        {
            // Intermediate (pre-merge) assemblies, so a cli exe is judged on its own code only. Foton.Win.Ui's imports are
            // pinned one by one in UiRules.
            foreach (var (p, asm) in Built(p => p.IntermediateAssembly).Where(x => x.Project.Name != "Foton.Win" && x.Project.Name != "Foton.Win.Ui"))
            {
                foreach (var t in TypesOf(asm))
                {
                    Assert.False(t.IsImport, p.Name + ": COM import " + t.FullName + " belongs in Foton.Win.");
                    foreach (var m in t.GetMethods(All))
                        Assert.False((m.Attributes & MethodAttributes.PinvokeImpl) != 0, p.Name + ": P/Invoke " + t.FullName + "." + m.Name + " belongs in Foton.Win.");
                }
            }
        }

        /// <remarks>
        /// Static calls, virtual calls, and method groups (ldftn) are covered. A call made through
        /// reflection (GetMethod("Load").Invoke) is not visible in IL; code review covers that.
        /// </remarks>
        [Fact]
        public void No_code_loads_assemblies_from_bytes()
        {
            int scanned = 0;
            foreach (var (p, asm) in Built(p => p.IntermediateAssembly))
                foreach (var t in TypesOf(asm))
                    foreach (var m in t.GetMethods(All).Cast<MethodBase>().Concat(t.GetConstructors(All)).Concat(t.TypeInitializer == null ? new MethodBase[0] : new[] { t.TypeInitializer }).Distinct())
                    {
                        scanned++;
                        foreach (var callee in IlReader.Callees(m))
                            Assert.False(IsByteLoad(callee), p.Name + ": " + t.FullName + "." + m.Name + " calls " + callee.DeclaringType + "." + callee.Name + "(byte[])");
                    }
            Assert.True(scanned > 0, "No method bodies were scanned; the rule would pass vacuously.");
        }

        static bool IsByteLoad(MethodBase callee)
        {
            var type = callee.DeclaringType?.FullName;
            if (type != "System.Reflection.Assembly" && type != "System.AppDomain") return false;
            if (callee.Name != "Load" && callee.Name != "ReflectionOnlyLoad") return false;
            var ps = callee.GetParameters();
            return ps.Length > 0 && ps[0].ParameterType == typeof(byte[]);
        }

    }
}
