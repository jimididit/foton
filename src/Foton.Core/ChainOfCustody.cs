using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

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
    }
}
