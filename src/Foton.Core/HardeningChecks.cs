using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Foton.Core
{
    /// <summary>One row of the registry hardening table (Name, Path, Expected, Note).</summary>
    public sealed class HardeningCheck
    {
        public string Name { get; set; } = "";
        public string Path { get; set; } = "";
        public string Expected { get; set; } = "";
        public string Note { get; set; } = "";
    }

    /// <summary>The registry hardening checks shared by Collect and Baseline (embedded data, in file order).</summary>
    public static class HardeningChecks
    {
        public static IReadOnlyList<HardeningCheck> All { get; } = Load();

        static IReadOnlyList<HardeningCheck> Load()
        {
            using (var s = typeof(HardeningChecks).Assembly.GetManifestResourceStream("Foton.Core.HardeningRegistryChecks.csv"))
            {
                if (s == null) throw new FileNotFoundException("Missing embedded HardeningRegistryChecks.csv");
                using (var r = new StreamReader(s, Encoding.UTF8))
                    return Csv.ReadText(r.ReadToEnd()).Select(row => new HardeningCheck
                    {
                        Name = row["Name"] ?? "",
                        Path = row["Path"] ?? "",
                        Expected = row.TryGetValue("Expected", out var e) ? e ?? "" : "",
                        Note = row.TryGetValue("Note", out var n) ? n ?? "" : "",
                    }).ToList();
            }
        }
    }
}
