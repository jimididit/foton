using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Xml.Linq;

namespace Foton.ArchitectureTests
{
    /// <summary>One src/ or cli/ project: references as written in its csproj, and where its build output lands.</summary>
    sealed class ProjectInfo
    {
        public string Name = "";
        public string Path = "";
        public string Dir = "";
        public string AssemblyName = "";
        public bool IsExe;
        public List<string> ProjectRefs = new List<string>();
        public List<string> FrameworkRefs = new List<string>();
        public List<string> PackageRefs = new List<string>();

        /// <summary>Framework and NuGet references together: either kind can pull in WMI or HTTP.</summary>
        public IEnumerable<string> AssemblyRefs => FrameworkRefs.Concat(PackageRefs);

        public string Extension => IsExe ? ".exe" : ".dll";

        /// <summary>Compiled assembly before ILRepack merges anything into it.</summary>
        public string IntermediateAssembly =>
            System.IO.Path.Combine(Dir, "obj", Repo.Configuration, "net462", AssemblyName + Extension);

        /// <summary>What ships (for cli projects, the merged single exe).</summary>
        public string OutputAssembly =>
            System.IO.Path.Combine(Dir, "bin", Repo.Configuration, "net462", AssemblyName + Extension);
    }

    static class Repo
    {
#if DEBUG
        public const string Configuration = "Debug";
#else
        public const string Configuration = "Release";
#endif

        public static readonly string Root = FindRoot();

        static string FindRoot()
        {
            for (var d = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory); d != null; d = d.Parent)
                if (File.Exists(System.IO.Path.Combine(d.FullName, "Foton.sln")))
                    return d.FullName;
            throw new InvalidOperationException("Foton.sln not found above the test output directory.");
        }

        public static IReadOnlyDictionary<string, ProjectInfo> Projects { get; } = LoadProjects();

        static string ProjectNameFromInclude(string include) =>
            System.IO.Path.GetFileNameWithoutExtension(include.Replace('\\', System.IO.Path.DirectorySeparatorChar));

        static Dictionary<string, ProjectInfo> LoadProjects()
        {
            var map = new Dictionary<string, ProjectInfo>(StringComparer.OrdinalIgnoreCase);
            foreach (var top in new[] { "src", "cli" })
            {
                var dir = System.IO.Path.Combine(Root, top);
                if (!Directory.Exists(dir)) continue;
                foreach (var file in Directory.GetFiles(dir, "*.csproj", SearchOption.AllDirectories))
                {
                    var doc = XDocument.Load(file);
                    var name = System.IO.Path.GetFileNameWithoutExtension(file);
                    var p = new ProjectInfo
                    {
                        Name = name,
                        Path = file,
                        Dir = System.IO.Path.GetDirectoryName(file)!,
                        AssemblyName = doc.Descendants("AssemblyName").Select(e => e.Value).FirstOrDefault() ?? name,
                        IsExe = doc.Descendants("OutputType").Any(e => e.Value.Equals("Exe", StringComparison.OrdinalIgnoreCase)),
                    };
                    p.ProjectRefs.AddRange(doc.Descendants("ProjectReference").Select(e => ProjectNameFromInclude((string)e.Attribute("Include")!)));
                    p.FrameworkRefs.AddRange(doc.Descendants("Reference").Select(e => (string)e.Attribute("Include")!));
                    p.PackageRefs.AddRange(doc.Descendants("PackageReference").Select(e => (string)e.Attribute("Include")!));
                    map[p.Name] = p;
                }
            }
            return map;
        }

        /// <summary>The project plus everything it references, transitively.</summary>
        public static HashSet<string> Closure(string project)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var stack = new Stack<string>();
            stack.Push(project);
            while (stack.Count > 0)
            {
                var name = stack.Pop();
                if (!seen.Add(name) || !Projects.TryGetValue(name, out var p)) continue;
                foreach (var r in p.ProjectRefs) stack.Push(r);
            }
            return seen;
        }

        public static IEnumerable<string> AssemblyRefsOf(IEnumerable<string> projects) =>
            projects.Where(Projects.ContainsKey).SelectMany(n => Projects[n].AssemblyRefs);

        public static IEnumerable<string> SourceFiles() =>
            new[] { "src", "cli" }
                .Select(t => System.IO.Path.Combine(Root, t))
                .Where(Directory.Exists)
                .SelectMany(d => Directory.GetFiles(d, "*.cs", SearchOption.AllDirectories))
                .Where(f => !f.Contains(@"\obj\") && !f.Contains(@"\bin\"));

        /// <summary>
        /// Loads a built Foton assembly for inspection (never executed). Foton.* dependencies resolve from
        /// the other projects' outputs. Returns null when this configuration has not been built.
        /// </summary>
        public static Assembly? LoadBuilt(string path)
        {
            if (!File.Exists(path)) return null;
            EnsureResolver();
            return Assembly.LoadFile(path);
        }

        static bool _resolver;

        static void EnsureResolver()
        {
            if (_resolver) return;
            _resolver = true;
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                var short_ = new AssemblyName(e.Name).Name;
                if (!Projects.TryGetValue(short_, out var p)) return null;
                return File.Exists(p.OutputAssembly) ? Assembly.LoadFile(p.OutputAssembly) : null;
            };
        }
    }
}
