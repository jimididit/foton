using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Foton.Core
{
    /// <summary>
    /// What a collection runs: the categories to collect, tasks to leave out, and default switches (-Profile file or
    /// -Category list). A task the profile does not select is recorded as NotSelected (sentinel artifact + manifest row),
    /// so the package says what was not collected; absence by choice is never read as absence on the host. The profile
    /// bytes are copied into the package and their SHA-256 is in the chain of custody.
    /// </summary>
    /// <remarks>
    /// To add a profile option, add it to <see cref="OptionNames"/>, read it in <see cref="Parse"/>, and apply it in
    /// <see cref="ApplyTo"/>. Unknown keys are refused, so a typo never silently collects everything.
    /// </remarks>
    public sealed class CollectionProfile
    {
        public const string FileName = "collection_profile.json";
        /// <summary>The raw EVTX export step (not a manifest task); excluding it skips the wevtutil exports.</summary>
        public const string EvtxExport = "evtx_export";
        const int MaxBytes = 65536;

        static readonly string[] TopNames = { "Name", "Description", "Categories", "ExcludeTasks", "Options" };
        static readonly string[] OptionNames =
        {
            "EventLogDays", "MaxEventsPerLog", "SkipEvtxExport", "SkipHashing", "LoadUserHives",
            "IncludeFileTimeline", "IncludeUsnJournal", "Deep", "NoZip", "RequireAdministrator",
        };

        public string Name { get; private set; } = "";
        public string Description { get; private set; } = "";
        /// <summary>Selected collection categories (CaseCategories keys), in package order.</summary>
        public IReadOnlyList<string> Categories { get; private set; } = new string[0];
        public IReadOnlyList<string> ExcludeTasks { get; private set; } = new string[0];
        /// <summary>Option values the profile sets (name to int or bool).</summary>
        public IReadOnlyDictionary<string, object> Options { get; private set; } = new Dictionary<string, object>();
        /// <summary>The exact bytes recorded in the package (the file for -Profile, generated JSON for -Category).</summary>
        public byte[] Bytes { get; private set; } = new byte[0];
        public string Sha256 => Hashing.Sha256Hex(Bytes);

        /// <summary>Every collection category a profile can select (all but 00_Collection, which always runs).</summary>
        public static IReadOnlyList<string> AllCategories { get; } = CaseCategories.All.Select(kv => kv.Key).Where(k => k != "Collection").ToArray();

        public bool Selects(string category, string task) =>
            Categories.Contains(category, StringComparer.OrdinalIgnoreCase) && !ExcludeTasks.Contains(task, StringComparer.OrdinalIgnoreCase);

        /// <summary>Loads and validates a profile file. Throws InvalidDataException naming the problem.</summary>
        public static CollectionProfile Load(string path)
        {
            var info = new FileInfo(path);
            if (!info.Exists) throw new FileNotFoundException("Profile not found: " + path, path);
            if (info.Length > MaxBytes) throw new InvalidDataException($"Profile is larger than {MaxBytes} bytes: {path}");
            var bytes = File.ReadAllBytes(path);
            var p = Parse(Encoding.UTF8.GetString(bytes).TrimStart('\uFEFF'), Path.GetFileNameWithoutExtension(path));
            p.Bytes = bytes;
            return p;
        }

        /// <summary>A profile for -Category a,b,c alone (every task in those categories).</summary>
        public static CollectionProfile FromCategories(string list)
        {
            var p = new CollectionProfile { Name = "Categories: " + list, Categories = CategoryList(list.Split(',').Select(c => c.Trim()).Where(c => c.Length > 0)) };
            p.Bytes = Encoding.UTF8.GetBytes(p.ToJson());
            return p;
        }

        /// <summary>This profile with its categories replaced by -Category (the rest of the file still applies).</summary>
        public CollectionProfile WithCategories(string list)
        {
            var p = new CollectionProfile
            {
                Name = Name, Description = Description, ExcludeTasks = ExcludeTasks, Options = Options,
                Categories = CategoryList(list.Split(',').Select(c => c.Trim()).Where(c => c.Length > 0)),
            };
            p.Bytes = Encoding.UTF8.GetBytes(p.ToJson());
            return p;
        }

        internal static CollectionProfile Parse(string json, string defaultName)
        {
            object? root;
            try { root = Json.Parse(json); }
            catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException) { throw new InvalidDataException("Profile is not valid JSON: " + ex.Message); }
            if (!(root is Dictionary<string, object> d)) throw new InvalidDataException("Profile must be a JSON object.");
            Unknown(d.Keys, TopNames, "profile");

            var p = new CollectionProfile
            {
                Name = d.TryGetValue("Name", out var n) ? Text(n, "Name") : defaultName,
                Description = d.TryGetValue("Description", out var desc) ? Text(desc, "Description") : "",
                Categories = d.TryGetValue("Categories", out var c) ? CategoryList(Strings(c, "Categories")) : AllCategories,
                ExcludeTasks = d.TryGetValue("ExcludeTasks", out var x) ? Strings(x, "ExcludeTasks").Distinct(StringComparer.OrdinalIgnoreCase).ToArray() : new string[0],
            };
            var options = new Dictionary<string, object>(StringComparer.Ordinal);
            if (d.TryGetValue("Options", out var o))
            {
                if (!(o is Dictionary<string, object> od)) throw new InvalidDataException("Profile Options must be a JSON object.");
                Unknown(od.Keys, OptionNames, "Options");
                foreach (var kv in od)
                {
                    var name = OptionNames.First(k => string.Equals(k, kv.Key, StringComparison.OrdinalIgnoreCase));
                    if (name == "EventLogDays" || name == "MaxEventsPerLog")
                    {
                        if (!(kv.Value is int i) || i < 0) throw new InvalidDataException($"Profile option {name} must be a whole number of 0 or more.");
                        options[name] = i;
                    }
                    else if (kv.Value is bool b) options[name] = b;
                    else throw new InvalidDataException($"Profile option {name} must be true or false.");
                }
            }
            p.Options = options;
            return p;
        }

        /// <summary>Sets every option the profile names; switches given on the command line (in <paramref name="explicitSwitches"/>) win.</summary>
        public void ApplyTo(SessionOptions o, ICollection<string> explicitSwitches)
        {
            foreach (var kv in Options)
            {
                if (explicitSwitches.Contains(kv.Key)) continue;
                switch (kv.Key)
                {
                    case "EventLogDays": o.EventLogDays = (int)kv.Value; break;
                    case "MaxEventsPerLog": o.MaxEventsPerLog = (int)kv.Value; break;
                    case "SkipEvtxExport": o.SkipEvtxExport = (bool)kv.Value; break;
                    case "SkipHashing": o.SkipHashing = (bool)kv.Value; break;
                    case "LoadUserHives": o.LoadUserHives = (bool)kv.Value; break;
                    case "IncludeFileTimeline": o.IncludeFileTimeline = (bool)kv.Value; break;
                    case "IncludeUsnJournal": o.IncludeUsnJournal = (bool)kv.Value; break;
                    case "Deep": o.Deep = (bool)kv.Value; break;
                    case "NoZip": o.NoZip = (bool)kv.Value; break;
                    case "RequireAdministrator": o.RequireAdministrator = (bool)kv.Value; break;
                }
            }
            o.Profile = this;
        }

        public string ToJson() => Json.Indented(new Dictionary<string, object?>
        {
            ["Name"] = Name,
            ["Description"] = Description,
            ["Categories"] = Categories,
            ["ExcludeTasks"] = ExcludeTasks,
            ["Options"] = Options.OrderBy(kv => kv.Key, StringComparer.Ordinal).ToDictionary(kv => kv.Key, kv => (object?)kv.Value),
        });

        static IReadOnlyList<string> CategoryList(IEnumerable<string> names)
        {
            var list = names.ToList();
            var unknown = list.Where(n => !AllCategories.Contains(n, StringComparer.OrdinalIgnoreCase)).ToList();
            if (unknown.Count > 0)
                throw new InvalidDataException($"Unknown categor{(unknown.Count == 1 ? "y" : "ies")} {string.Join(", ", unknown)}. Valid: {string.Join(", ", AllCategories)}.");
            if (list.Count == 0) throw new InvalidDataException("The profile selects no categories, so it would collect nothing.");
            // Package order and canonical spelling, whatever order and case the file used.
            return AllCategories.Where(a => list.Contains(a, StringComparer.OrdinalIgnoreCase)).ToArray();
        }

        static void Unknown(IEnumerable<string> keys, string[] known, string where)
        {
            var bad = keys.Where(k => !known.Contains(k, StringComparer.OrdinalIgnoreCase)).ToList();
            if (bad.Count > 0) throw new InvalidDataException($"Unknown {where} key(s) {string.Join(", ", bad)}. Valid: {string.Join(", ", known)}.");
        }

        static string Text(object? v, string name) =>
            v is string s ? TextFile.OneLine(s) : throw new InvalidDataException($"Profile {name} must be text.");

        static IEnumerable<string> Strings(object? v, string name)
        {
            if (!(v is IEnumerable e) || v is string || v is IDictionary) throw new InvalidDataException($"Profile {name} must be a list of names.");
            foreach (var item in e)
            {
                if (!(item is string s) || s.Trim().Length == 0) throw new InvalidDataException($"Profile {name} must hold only non-empty names.");
                yield return s.Trim();
            }
        }
    }
}
