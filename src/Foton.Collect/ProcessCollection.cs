using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;
using static Foton.Collect.CollectText;

namespace Foton.Collect
{
    /// <summary>Running processes, the process tree, loaded modules, PowerShell history, and other volatile state (Invoke-FotonProcessCollection).</summary>
    public static class ProcessCollection
    {
        const string Cat = "Processes", Cimv2 = @"root\cimv2";
        const string ProcessColumns = "ProcessId, Name, ParentProcessId, ExecutablePath, CommandLine, CreationDate, SessionId";

        public static void Run(FotonSession s)
        {
            s.Status.Write("Collecting running processes, modules, and volatile state", StatusLevel.Step);
            Task(s, Cat, "running_processes", "Processes with path, command line, parent, hash, signature", TaskFormat.Csv, () => RunningProcesses(s));
            Task(s, Cat, "process_tree", "Parent/child process tree rendering", TaskFormat.Txt, ProcessTree);
            Task(s, Cat, "loaded_modules_nonstandard", "Loaded DLLs outside System32/Program Files", TaskFormat.Csv, () => NonStandardModules(s));
            Task(s, Cat, "powershell_console_history", "PSReadLine history for every profile (analyst-critical)", TaskFormat.Csv, () => ConsoleHistory(s));
            Task(s, Cat, "clipboard_and_recent_docs", "Recent document MRU keys", TaskFormat.Txt, () => RecentDocs(s));
            Task(s, Cat, "named_pipes", "Named pipe names (volatile; Collect only)", TaskFormat.Csv, NamedPipes);
        }

        static Dictionary<int, ManagementBaseObject> Processes()
        {
            var map = new Dictionary<int, ManagementBaseObject>();
            foreach (var p in Wmi.Query(Cimv2, $"SELECT {ProcessColumns} FROM Win32_Process"))
                map[Convert.ToInt32(Raw(p, "ProcessId"))] = p;
            return map;
        }

        static object RunningProcesses(FotonSession s)
        {
            var procs = new Dictionary<int, ManagementBaseObject>();
            try { procs = Processes(); }
            catch (Exception ex) when (WmiFailed(ex)) { }
            var rows = new List<Dictionary<string, object?>>();
            var owners = new ProcessOwner();
            // Many processes share one image (svchost, browser and Electron helpers): check and hash each path once per task.
            var sigs = new Dictionary<string, SignatureInfo>(StringComparer.OrdinalIgnoreCase);
            var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in procs.OrderBy(kv => kv.Key).Select(kv => kv.Value))
            {
                var path = Wmi.Str(p, "ExecutablePath");
                if (!sigs.TryGetValue(path, out var sig)) sigs[path] = sig = Authenticode.Check(path);
                if (!hashes.TryGetValue(path, out var hash)) hashes[path] = hash = Hashing.SafeHash(path, s.Options.SkipHashing);
                var parent = Convert.ToInt32(Raw(p, "ParentProcessId") ?? 0);
                rows.Add(new Dictionary<string, object?>
                {
                    ["PID"] = Raw(p, "ProcessId"),
                    ["Name"] = Raw(p, "Name"),
                    ["ParentPID"] = Raw(p, "ParentProcessId"),
                    ["ParentName"] = procs.TryGetValue(parent, out var pp) ? Wmi.Str(pp, "Name") : "",
                    ["Owner"] = owners.Of(Convert.ToInt32(Raw(p, "ProcessId"))),
                    ["Path"] = path,
                    ["CommandLine"] = Raw(p, "CommandLine"),
                    ["CreationTimeUtc"] = Dmtf(Raw(p, "CreationDate")),
                    ["SessionId"] = Raw(p, "SessionId"),
                    ["SignatureStatus"] = sig.Status,
                    ["Signer"] = sig.Signer,
                    ["IsOSBinary"] = sig.IsOSBinary,
                    ["SHA256"] = hash,
                    ["UserWritablePath"] = UserWritable(path),
                    // Kept for schema continuity: Analyze derives the hits from CommandLine on the workstation, where the
                    // suspicious-command list is; the endpoint executable never carries it.
                    ["SuspiciousCmdHits"] = "",
                });
            }
            return rows;
        }

        /// <summary>Parent/child rendering as 1.38.x drew it: orphaned roots first, then the tree from System (PID 4), depth-capped at 12.</summary>
        static object ProcessTree()
        {
            Dictionary<int, ManagementBaseObject> procs;
            try { procs = Processes(); }
            catch (Exception ex) when (WmiFailed(ex)) { return "Unavailable"; }
            var children = procs.Values.GroupBy(p => Convert.ToInt32(Raw(p, "ParentProcessId") ?? 0)).ToDictionary(g => g.Key, g => g.OrderBy(p => Convert.ToInt32(Raw(p, "ProcessId"))).ToList());
            var lines = new List<string>();
            void Branch(int pid, int depth)
            {
                if (depth > 12 || !children.TryGetValue(pid, out var kids)) return;
                foreach (var child in kids)
                {
                    var id = Convert.ToInt32(Raw(child, "ProcessId"));
                    lines.Add($"{new string(' ', depth * 2)}[{id}] {Wmi.Str(child, "Name")}  {Wmi.Str(child, "ExecutablePath")}");
                    if (children.ContainsKey(id)) Branch(id, depth + 1);
                }
            }
            foreach (var root in children.Keys.OrderBy(k => k))
                if (!procs.ContainsKey(root))
                {
                    lines.Add($"[{root}] (parent no longer running)");
                    Branch(root, 1);
                }
            lines.Add("");
            lines.Add("--- Tree from System (PID 4) ---");
            Branch(4, 1);
            return lines;
        }

        /// <summary>
        /// A module under the real system roots. 1.38.x matched these names anywhere in the path, so a DLL in
        /// C:\Users\x\Windows\System32\ or "...\Program Files Fake\" was treated as standard and hidden from this list.
        /// </summary>
        static readonly string[] StandardRoots = StandardModuleRoots();

        static string[] StandardModuleRoots()
        {
            var win = HostInfo.WindowsDir.TrimEnd('\\');
            var roots = new List<string> { win + @"\System32\", win + @"\SysWOW64\", win + @"\WinSxS\" };
            foreach (var v in new[] { "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432" })
            {
                var p = Environment.GetEnvironmentVariable(v);
                if (!string.IsNullOrEmpty(p)) roots.Add(p!.TrimEnd('\\') + @"\");
            }
            return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        internal static bool IsStandardModule(string path) => StandardRoots.Any(r => path.StartsWith(r, StringComparison.OrdinalIgnoreCase));

        /// <summary>DLLs loaded from outside System32, SysWOW64, WinSxS, and Program Files: one row per path (first process in name order).</summary>
        static object NonStandardModules(FotonSession s)
        {
            var rows = new List<Dictionary<string, object?>>();
            // One row per path, from the first process in name order; later processes loading it are not re-read or re-hashed.
            var seen = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase);
            foreach (var proc in Process.GetProcesses().OrderBy(p => p.ProcessName, StringComparer.InvariantCultureIgnoreCase).ThenBy(p => p.Id))
            {
                using (proc)
                {
                    try
                    {
                        foreach (ProcessModule m in proc.Modules)
                        {
                            var fn = m.FileName ?? "";
                            if (IsStandardModule(fn) || seen.Contains(fn)) continue;
                            string company = "";
                            try { company = m.FileVersionInfo.CompanyName ?? ""; } catch (Exception ex) when (ex is IOException || ex is ArgumentException) { }
                            rows.Add(new Dictionary<string, object?>
                            {
                                ["ProcessName"] = proc.ProcessName, ["PID"] = proc.Id, ["Module"] = m.ModuleName, ["Path"] = fn,
                                ["Company"] = company, ["SHA256"] = Hashing.SafeHash(fn, s.Options.SkipHashing),
                            });
                            seen.Add(fn);
                        }
                    }
                    // Another user's or a protected process: its modules are not readable with this token.
                    catch (Exception ex) when (ex is System.ComponentModel.Win32Exception || ex is InvalidOperationException || ex is NotSupportedException) { }
                }
            }
            return rows.OrderBy(r => (string)r["Path"]!, StringComparer.InvariantCultureIgnoreCase).ToList();
        }

        static object ConsoleHistory(FotonSession s)
        {
            var rows = new List<Dictionary<string, object?>>();
            foreach (var p in HostInfo.Profiles(s.IsElevated))
            {
                var hist = Path.Combine(p.ProfilePath, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
                if (!HostInfo.Accessible(hist)) continue;
                string[] lines;
                // PSReadLine writes UTF-8; 1.38.x read it as ANSI and garbled non-ASCII commands.
                try { lines = File.ReadAllLines(hist, Encoding.UTF8); }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { continue; }
                for (int i = 0; i < lines.Length; i++)
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["User"] = p.UserName, ["HistoryFile"] = hist, ["LineNumber"] = i + 1, ["Command"] = lines[i], ["SuspiciousHits"] = "",
                    });
            }
            return rows;
        }

        static object RecentDocs(FotonSession s)
        {
            var lines = new List<string>();
            foreach (var h in HostInfo.HiveRoots(s.IsElevated))
            {
                var mru = Reg.Join(h.Root, @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs");
                if (!Reg.Exists(mru)) continue;
                lines.Add($"=== RecentDocs for {h.UserName} ===");
                var full = mru.Replace("Registry::", "");
                lines.AddRange(Reg.SubKeyNames(mru).Select(k => full + "\\" + k));
                lines.Add("");
            }
            if (lines.Count == 0) lines.Add("No RecentDocs keys accessible.");
            return lines;
        }

        const int MaxPipes = 2000;

        static object NamedPipes()
        {
            var rows = new List<Dictionary<string, object?>>();
            string[] names;
            try { names = Directory.GetFiles(@"\\.\pipe\"); }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException) { return rows; }
            foreach (var p in names.OrderBy(n => n, StringComparer.InvariantCultureIgnoreCase).Take(MaxPipes))
            {
                // Pipe names may hold characters Path.GetFileName rejects; take the text after the last backslash.
                var leaf = p.Substring(p.LastIndexOf('\\') + 1);
                rows.Add(new Dictionary<string, object?> { ["Name"] = leaf.Length == 0 ? p : leaf });
            }
            return rows;
        }
    }
}
