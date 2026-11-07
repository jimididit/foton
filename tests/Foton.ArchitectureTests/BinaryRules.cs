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
#if !DEBUG
                Assert.True(asm != null, path(p) + " missing; build the solution with -c Release first.");
#endif
                if (asm != null) yield return (p, asm);
            }
        }

        static IEnumerable<Type> TypesOf(Assembly a)
        {
            try { return a.GetTypes(); }
            catch (ReflectionTypeLoadException e) { return e.Types.Where(t => t != null)!; }
        }

        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;

        static string Token(AssemblyName n) =>
            string.Concat((n.GetPublicKeyToken() ?? new byte[0]).Select(b => b.ToString("x2")));

        [Fact]
        public void Shipped_executables_reference_only_Microsoft_framework_assemblies()
        {
            foreach (var (p, asm) in Built(p => p.OutputAssembly).Where(x => x.Project.IsExe))
            {
                foreach (var r in asm.GetReferencedAssemblies())
                {
                    Assert.False(r.Name.StartsWith("Foton", StringComparison.OrdinalIgnoreCase), p.AssemblyName + " still references " + r.Name + " (not merged).");
                    Assert.True(FrameworkKeys.Contains(Token(r)), p.AssemblyName + " references non-framework assembly " + r.FullName + "; endpoints get in-box .NET Framework only.");
                }
                if (p.Name != "Foton.Cli")
                    Assert.DoesNotContain(asm.GetReferencedAssemblies(), r => r.Name.Equals("System.Net.Http", StringComparison.OrdinalIgnoreCase));
            }
        }

        [Fact]
        public void PInvoke_and_COM_imports_are_compiled_only_into_Foton_Win()
        {
            // Intermediate (pre-merge) assemblies, so a cli exe is judged on its own code only.
            foreach (var (p, asm) in Built(p => p.IntermediateAssembly).Where(x => x.Project.Name != "Foton.Win"))
            {
                foreach (var t in TypesOf(asm))
                {
                    Assert.False(t.IsImport, p.Name + ": COM import " + t.FullName + " belongs in Foton.Win.");
                    foreach (var m in t.GetMethods(All))
                        Assert.False((m.Attributes & MethodAttributes.PinvokeImpl) != 0, p.Name + ": P/Invoke " + t.FullName + "." + m.Name + " belongs in Foton.Win.");
                }
            }
        }

        [Fact]
        public void No_code_loads_assemblies_from_bytes()
        {
            foreach (var (p, asm) in Built(p => p.IntermediateAssembly))
                foreach (var t in TypesOf(asm))
                    foreach (var m in t.GetMethods(All).Cast<MethodBase>().Concat(t.GetConstructors(All)))
                        foreach (var callee in Callees(m))
                            Assert.False(IsByteLoad(callee), p.Name + ": " + t.FullName + "." + m.Name + " calls " + callee.DeclaringType + "." + callee.Name + "(byte[])");
        }

        static bool IsByteLoad(MethodBase callee)
        {
            var type = callee.DeclaringType?.FullName;
            if (type != "System.Reflection.Assembly" && type != "System.AppDomain") return false;
            if (callee.Name != "Load" && callee.Name != "ReflectionOnlyLoad") return false;
            var ps = callee.GetParameters();
            return ps.Length > 0 && ps[0].ParameterType == typeof(byte[]);
        }

        /// <summary>Methods called by m (call / callvirt / newobj / ldftn operands), decoded from raw IL.</summary>
        static IEnumerable<MethodBase> Callees(MethodBase m)
        {
            byte[]? il;
            try { il = m.GetMethodBody()?.GetILAsByteArray(); } catch { yield break; }
            if (il == null) yield break;
            for (int i = 0; i + 4 < il.Length; i++)
            {
                bool call = il[i] == 0x28 || il[i] == 0x6F || il[i] == 0x73;
                bool ldftn = il[i] == 0xFE && i + 5 < il.Length && (il[i + 1] == 0x06 || il[i + 1] == 0x07);
                if (!call && !ldftn) continue;
                int at = ldftn ? i + 2 : i + 1;
                int token = BitConverter.ToInt32(il, at);
                if ((token >> 24) != 0x0A && (token >> 24) != 0x06 && (token >> 24) != 0x2B) continue;
                MethodBase? target = null;
                try { target = m.Module.ResolveMethod(token, m.DeclaringType?.GetGenericArguments(), m.IsGenericMethod ? m.GetGenericArguments() : null); }
                catch { }
                if (target != null) yield return target;
            }
        }
    }
}
