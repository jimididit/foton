using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace Foton.Core
{
    /// <summary>
    /// Host and tool facts for the custody header, gathered by the caller (Foton.Win at collect time).
    /// Anything left null is written as "unknown" rather than guessed.
    /// </summary>
    public sealed class CustodyFacts
    {
        public string? Domain { get; set; }
        public string? Manufacturer { get; set; }
        public string? Model { get; set; }
        public string? OsCaption { get; set; }
        public string? OsVersion { get; set; }
        public string? OsBuild { get; set; }
        public DateTime? LastBootUtc { get; set; }
        /// <summary>The running collector executable, and its SHA-256, so the record names the exact build.</summary>
        public string? ExecutablePath { get; set; }
        public string? ExecutableSha256 { get; set; }
        public TimeZoneInfo TimeZone { get; set; } = TimeZoneInfo.Local;
        public DateTime LocalTimeAtStart { get; set; } = DateTime.Now;
    }

    /// <summary>Case Number and Examiner as a package's chain_of_custody.txt records them; null when not recorded.</summary>
    public sealed class CustodyHeader
    {
        public string? CaseNumber { get; set; }
        public string? Examiner { get; set; }
        /// <summary>SHA-256 of the collector executable that ran (packages from 2.0.0 on), so its own rows can be told apart.</summary>
        public string? ExecutableSha256 { get; set; }
    }

    /// <summary>
    /// chain_of_custody.txt: collection record, parameters, and the methodology disclosure. Written before
    /// collection runs, so it states the method, not the outcome. Update the disclosure whenever the
    /// collector's footprint changes.
    /// </summary>
    public static class ChainOfCustody
    {
        public static IReadOnlyList<string> Lines(FotonSession s, CustodyFacts f)
        {
            var o = s.Options;
            // Every embedded value is one line (host facts and operator input could carry CR/LF).
            string L(string? v) => TextFile.OneLine(v);
            string Or(string? v) => string.IsNullOrWhiteSpace(v) ? "unknown" : L(v);
            var offset = f.TimeZone.GetUtcOffset(f.LocalTimeAtStart);
            var os = string.IsNullOrWhiteSpace(f.OsCaption) ? "unknown" : $"{L(f.OsCaption)} {Or(f.OsVersion)} (build {Or(f.OsBuild)})";
            var model = string.IsNullOrWhiteSpace(f.Manufacturer) && string.IsNullOrWhiteSpace(f.Model) ? "unknown" : $"{L(f.Manufacturer)} {L(f.Model)}".Trim();
            var l = new List<string>
            {
                "================================================================",
                " Foton - Collection Record / Chain of Custody Header",
                "================================================================",
                "",
                "Case Number          : " + (string.IsNullOrWhiteSpace(o.CaseNumber) ? "(not supplied)" : L(o.CaseNumber)),
                "Examiner             : " + L(o.Examiner),
                "Collection Tool      : Foton v" + s.Version,
                "Collection Type      : Live (running system) logical collection",
                "Collection Start UTC : " + FotonTime.Format(s.StartTimeUtc),
                "Local Time At Start  : " + f.LocalTimeAtStart.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                "System Time Zone     : " + L(f.TimeZone.Id) + " (UTC offset " + offset.ToString("c", CultureInfo.InvariantCulture) + ")",
                "",
                "Hostname             : " + L(s.Hostname),
                "Domain / Workgroup   : " + Or(f.Domain),
                "Manufacturer / Model : " + model,
                "Operating System     : " + os,
                "Last Boot UTC        : " + (f.LastBootUtc.HasValue ? FotonTime.Format(f.LastBootUtc.Value) : "unknown"),
                "",
                "Collection Account   : " + L(s.Account),
                "Elevated (Admin)     : " + (s.IsElevated ? "True" : "False"),
                "Coverage Profile     : " + Coverage.Profile(s.IsElevated),
                "Runtime              : .NET Framework (CLR " + Environment.Version + ")",
                "Executable           : " + Or(f.ExecutablePath),
                "Executable SHA-256   : " + Or(f.ExecutableSha256),
                "",
                "Parameters Used:",
                "  OutputPath          = " + L(o.OutputPath),
                "  EventLogDays        = " + o.EventLogDays.ToString(CultureInfo.InvariantCulture),
                "  MaxEventsPerLog     = " + o.MaxEventsPerLog.ToString(CultureInfo.InvariantCulture),
                "  SkipEvtxExport      = " + o.SkipEvtxExport,
                "  SkipHashing         = " + o.SkipHashing,
                "  LoadUserHives       = " + o.LoadUserHives,
                "  IncludeFileTimeline = " + o.IncludeFileTimeline,
                "  IncludeUsnJournal   = " + o.IncludeUsnJournal,
                "  Deep                = " + o.Deep,
                "  NoZip               = " + o.NoZip,
                "  RequireAdministrator = " + o.RequireAdministrator,
                "",
                "----------------------------------------------------------------",
                " METHODOLOGY DISCLOSURE",
                "----------------------------------------------------------------",
                "This was a LIVE collection. Executing this tool altered the target",
                "system state: it created a process, wrote files to the output path,",
                "generated event log entries, updated prefetch/AmCache, and read",
                "registry keys (updating last-access metadata on some artifacts).",
                "Volatile data (RAM, live network state) was captured only to the",
                "extent listed in the manifest. No memory image and no disk image",
                "were produced. If either is required, capture them before or",
                "independently of this collection.",
                "",
                "The tool also started in-box utilities from System32 (never through",
                "PATH), each a process-creation event on the host: arp, auditpol,",
                "bcdedit, bitsadmin, cmdkey, fsutil, gpresult, ipconfig, net, netsh,",
                "nltest, query, reg, route, secedit, vssadmin, w32tm, and wevtutil.",
                "Which ones ran depends on the token and options (collection.log).",
                "",
            };
            var profile = o.Profile;
            if (profile != null)
            {
                // Profile values are operator input: one line each, inside Parameters Used.
                l.InsertRange(l.FindIndex(x => x.StartsWith("  RequireAdministrator", StringComparison.Ordinal)) + 1, new[]
                {
                    "  Profile             = " + L(profile.Name),
                    "  ProfileSha256       = " + profile.Sha256,
                    "  Categories          = " + string.Join(", ", profile.Categories),
                    "  ExcludeTasks        = " + (profile.ExcludeTasks.Count == 0 ? "(none)" : L(string.Join(", ", profile.ExcludeTasks))),
                });
                l.Add("A collection profile limited this collection (" + CollectionProfile.FileName + " in");
                l.Add("00_Collection, SHA-256 above). Tasks it did not select are recorded in the");
                l.Add("manifest with Status=NotSelected and listed in collection_coverage.json. Their");
                l.Add("absence is the operator's choice, not evidence about the host.");
                l.Add("");
            }
            if (s.IsElevated)
            {
                l.Add("Loaded registry hives (SYSTEM, SOFTWARE, DEFAULT, and signed-in users");
                l.Add("NTUSER.DAT/UsrClass.dat) are exported with reg save. The export files");
                l.Add("in the output path are the only writes; no key is modified. Whether each");
                l.Add("export succeeded is recorded per file in registry_hives_machine.csv and");
                l.Add("registry_hives_user.csv (Status Saved / SaveError) and in the manifest.");
                l.Add("SAM and SECURITY are not collected by design (credential material).");
                l.Add("");
            }
            if (o.IncludeUsnJournal && s.IsElevated)
            {
                l.Add("The -IncludeUsnJournal option was used: the system volume was opened");
                l.Add("read-only and its NTFS change journal read with FSCTL_READ_USN_JOURNAL");
                l.Add("(the interface fsutil uses). Nothing on the volume is written.");
                l.Add("");
            }
            if (o.LoadUserHives && s.IsElevated)
            {
                l.Add("The -LoadUserHives option was used: NTUSER.DAT hives for users not");
                l.Add("logged on were mounted into HKEY_USERS and unloaded at the end");
                l.Add("of collection. This is a registry write operation on the target.");
                l.Add("");
            }
            else if (o.LoadUserHives)
            {
                l.Add("The -LoadUserHives option was requested but ignored: mounting NTUSER.DAT");
                l.Add("requires an elevated token. Per-user keys are limited to hives already loaded.");
                l.Add("");
            }
            if (!s.IsElevated)
            {
                l.Add("Coverage profile STANDARD USER. This process was not elevated. The package");
                l.Add("contains what the current token could read (typically the interactive user's");
                l.Add("processes, HKCU persistence, readable HKLM values, network snapshot, and that");
                l.Add("user's profile artifacts). The Security event log, Prefetch/Amcache/SRUM copies,");
                l.Add("VSS listing, auditpol, secedit export, and other users' files were not collected (see");
                l.Add("collection_coverage.json and manifest Status=SkippedNotElevated). Absence of");
                l.Add("those artifacts is a visibility gap, not evidence they were empty on the host.");
                l.Add("");
            }
            l.Add("SHA-256 hashes for every collected artifact are recorded in");
            l.Add("hashes.csv, produced after collection completed. Verify these hashes");
            l.Add("on receipt and at each transfer. Record custody transfers below.");
            l.Add("");
            l.Add("Transfer Log:");
            l.Add("  [Date/Time UTC] --- from ______________ to ______________ purpose ______________");
            l.Add("  [Date/Time UTC] --- from ______________ to ______________ purpose ______________");
            l.Add("");
            return l;
        }

        public static string Write(FotonSession s, CustodyFacts f)
        {
            var path = Path.Combine(s.Dir("Collection"), "chain_of_custody.txt");
            TextFile.WriteLines(path, Lines(s, f));
            return path;
        }

        /// <summary>
        /// Reads Case Number and Examiner from the header of a case's chain_of_custody.txt (Foton 1.38.x and v2 write
        /// the same "Label : value" lines). Only the header is read, up to "Parameters Used:". A missing or unreadable
        /// file gives an empty header, and "(not supplied)" reads as not recorded.
        /// </summary>
        public static CustodyHeader ReadHeader(string? caseRoot)
        {
            var h = new CustodyHeader();
            if (string.IsNullOrEmpty(caseRoot)) return h;
            try
            {
                var path = Path.Combine(caseRoot, CaseTree.CollectionFolder, "chain_of_custody.txt");
                if (!File.Exists(path)) return h;
                foreach (var line in File.ReadLines(path).Take(60))
                {
                    if (line.StartsWith("Parameters Used", StringComparison.Ordinal)) break;
                    var colon = line.IndexOf(':');
                    if (colon < 0) continue;
                    var label = line.Substring(0, colon).Trim();
                    var value = line.Substring(colon + 1).Trim();
                    if (value.Length == 0 || value == "(not supplied)") continue;
                    if (h.CaseNumber == null && label == "Case Number") h.CaseNumber = value;
                    else if (h.Examiner == null && label == "Examiner") h.Examiner = value;
                    else if (h.ExecutableSha256 == null && label == "Executable SHA-256" && value.Length == 64 && value.All(Uri.IsHexDigit)) h.ExecutableSha256 = value;
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException) { }
            return h;
        }
    }
}
