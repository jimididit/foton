using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace Foton.ArchitectureTests
{
    /// <summary>One src/ or cli/ project: its direct project references and .NET Framework references.</summary>
    sealed class ProjectInfo
    {
        public string Name = "";
        public string Path = "";
        public string Dir = "";
        public List<string> ProjectRefs = new List<string>();
        public List<string> FrameworkRefs = new List<string>();
    }

    static class Repo
    {
        public static readonly string Root = FindRoot();

        static string FindRoot()
        {
            for (var d = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory); d != null; d = d.Parent)
                if (File.Exists(System.IO.Path.Combine(d.FullName, "Foton.sln")))
                    return d.FullName;
            throw new InvalidOperationException("Foton.sln not found above the test output directory.");
        }

        public static IReadOnlyDictionary<string, ProjectInfo> Projects { get; } = LoadProjects();

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
                    var p = new ProjectInfo
                    {
                        Name = System.IO.Path.GetFileNameWithoutExtension(file),
                        Path = file,
                        Dir = System.IO.Path.GetDirectoryName(file)!,
                    };
                    p.ProjectRefs.AddRange(doc.Descendants("ProjectReference")
                        .Select(e => System.IO.Path.GetFileNameWithoutExtension((string)e.Attribute("Include")!)));
                    p.FrameworkRefs.AddRange(doc.Descendants("Reference").Select(e => (string)e.Attribute("Include")!));
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

        public static IEnumerable<string> FrameworkRefsOf(IEnumerable<string> projects) =>
            projects.Where(Projects.ContainsKey).SelectMany(n => Projects[n].FrameworkRefs);

        public static IEnumerable<string> SourceFiles() =>
            new[] { "src", "cli" }
                .Select(t => System.IO.Path.Combine(Root, t))
                .Where(Directory.Exists)
                .SelectMany(d => Directory.GetFiles(d, "*.cs", SearchOption.AllDirectories))
                .Where(f => !f.Contains(@"\obj\") && !f.Contains(@"\bin\"));
    }
}
