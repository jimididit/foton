using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;
using static Foton.Collect.CollectText;

namespace Foton.Collect
{
    /// <summary>System identity, configuration, and boot state (Invoke-FotonSystemCollection). Live facts only.</summary>
    public static class SystemCollection
    {
        const string Cat = "System", Cimv2 = @"root\cimv2";
        const string CurrentVersion = @"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

        public static void Run(FotonSession s)
        {
            s.Status.Write("Collecting system identity, configuration, and boot state", StatusLevel.Step);
            Task(s, Cat, "os_info", "Operating system build, install date, uptime", TaskFormat.Json, () => OsInfo(s));
            Task(s, Cat, "entra_workplace_join", "Entra/Azure AD join, workplace join, and MDM enrollment from local registry (no dsregcmd, no Graph)", TaskFormat.Csv,
                () => CloudJoin.Rows(HostInfo.HiveRoots(s.IsElevated)));
            Task(s, Cat, "time_sync", "NTP/time source configuration (timestamp reliability)", TaskFormat.Txt, TimeSync);
            Task(s, Cat, "hotfixes", "Installed updates and patch dates", TaskFormat.Csv, Hotfixes);
            Task(s, Cat, "boot_and_firmware", "Secure Boot, TPM, BitLocker, Firmware-class devices (staged UEFI updates), boot configuration", TaskFormat.Json, BootAndFirmware);
            Task(s, Cat, "disks_and_volumes", "Logical volumes, free space, filesystem type", TaskFormat.Csv, Disks);
            Task(s, Cat, "environment_variables", "Process/machine environment variables", TaskFormat.Csv, () =>
                Environment.GetEnvironmentVariables().Cast<DictionaryEntry>()
                    .Select(e => new Dictionary<string, object?> { ["Name"] = (string)e.Key, ["Value"] = e.Value as string ?? "" })
                    .OrderBy(r => (string)r["Name"]!, StringComparer.InvariantCultureIgnoreCase).ToList());
            Task(s, Cat, "system_restore_and_shadowcopies", "Volume shadow copies (deletion is a ransomware indicator)", TaskFormat.Txt, () => new List<string>
            {
                "--- vssadmin list shadows ---", Exec.System32("vssadmin.exe", "list shadows"),
                "--- vssadmin list shadowstorage ---", Exec.System32("vssadmin.exe", "list shadowstorage"),
            }, elevated: true);
        }

        static object OsInfo(FotonSession s)
        {
            var os = First(Cimv2, "SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, SerialNumber, RegisteredUser, SystemDirectory FROM Win32_OperatingSystem")
                ?? throw new InvalidOperationException("Win32_OperatingSystem returned no instance.");
            var cs = TryFirst(Cimv2, "SELECT Domain, PartOfDomain, Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem");
            var bios = TryFirst(Cimv2, "SELECT BIOSVersion, SMBIOSBIOSVersion, ReleaseDate, EmbeddedControllerMajorVersion, EmbeddedControllerMinorVersion, SerialNumber FROM Win32_BIOS");
            var boot = DmtfTime(Raw(os, "LastBootUpTime"));
            object? ec = null;
            if (bios != null) ec = Raw(bios, "EmbeddedControllerMajorVersion");
            return new Dictionary<string, object?>
            {
                ["Hostname"] = s.Hostname,
                ["Caption"] = Raw(os, "Caption"),
                ["Version"] = Raw(os, "Version"),
                ["BuildNumber"] = Raw(os, "BuildNumber"),
                ["DisplayVersion"] = Reg.Value(CurrentVersion, "DisplayVersion"),
                ["UBR"] = Reg.Value(CurrentVersion, "UBR"),
                ["Architecture"] = Raw(os, "OSArchitecture"),
                ["InstallDateUtc"] = Dmtf(Raw(os, "InstallDate")),
                ["LastBootUtc"] = boot.HasValue ? FotonTime.Format(boot.Value) : "",
                ["UptimeDays"] = boot.HasValue ? Math.Round((DateTime.UtcNow - boot.Value).TotalDays, 2) : (double?)null,
                ["SerialNumber"] = Raw(os, "SerialNumber"),
                ["RegisteredUser"] = Raw(os, "RegisteredUser"),
                ["SystemDirectory"] = Raw(os, "SystemDirectory"),
                ["Domain"] = cs != null ? Raw(cs, "Domain") : "",
                ["PartOfDomain"] = cs != null ? Raw(cs, "PartOfDomain") : null,
                ["Manufacturer"] = cs != null ? Raw(cs, "Manufacturer") : "",
                ["Model"] = cs != null ? Raw(cs, "Model") : "",
                ["TotalPhysicalMemGB"] = cs != null && Raw(cs, "TotalPhysicalMemory") is ulong mem ? Math.Round(mem / 1073741824.0, 2) : (double?)null,
                ["BiosVersion"] = bios != null && Raw(bios, "BIOSVersion") is string[] bv ? string.Join(" ", bv) : "",
                ["SmbiosBiosVersion"] = bios != null ? Wmi.Str(bios, "SMBIOSBIOSVersion") : "",
                ["BiosReleaseDateUtc"] = bios != null ? Dmtf(Raw(bios, "ReleaseDate")) : "",
                // SMBIOS uses 255 for "no embedded controller version"; "255.255" would read as a real version.
                ["EmbeddedControllerVersion"] = ec == null ? "" : Convert.ToInt32(ec, CultureInfo.InvariantCulture) == 255 ? "NotReported"
                    : $"{ec}.{Raw(bios!, "EmbeddedControllerMinorVersion")}",
                ["BiosSerial"] = bios != null ? Raw(bios, "SerialNumber") : "",
                ["TimeZone"] = TimeZoneInfo.Local.Id,
                ["UtcOffset"] = TimeZoneInfo.Local.GetUtcOffset(DateTime.Now).ToString(),
            };
        }

        static object TimeSync()
        {
            var lines = new List<string>
            {
                "--- w32tm /query /status ---", Exec.System32("w32tm.exe", "/query /status"),
                "--- w32tm /query /configuration ---", Exec.System32("w32tm.exe", "/query /configuration"),
                "--- Time Service ---",
            };
            try
            {
                using (var svc = new ServiceController("W32Time"))
                    lines.AddRange(Table(new[] { "Name", "Status", "StartType" }, new[] { new[] { svc.ServiceName, svc.Status.ToString(), svc.StartType.ToString() } }));
            }
            catch (Exception ex) when (ex is InvalidOperationException || ex is System.ComponentModel.Win32Exception) { }
            return lines;
        }

        static object Hotfixes()
        {
            // Get-HotFix parsed InstalledOn with an invariant M/d/yyyy format; anything else is left blank.
            return Wmi.Query(Cimv2, "SELECT HotFixID, Description, InstalledBy, InstalledOn FROM Win32_QuickFixEngineering").Select(q =>
            {
                var raw = Wmi.Str(q, "InstalledOn");
                var on = DateTime.TryParse(raw, DateTimeFormatInfo.InvariantInfo, DateTimeStyles.None, out var d) ? d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "";
                return new Dictionary<string, object?>
                {
                    ["HotFixID"] = Wmi.Str(q, "HotFixID"), ["Description"] = Wmi.Str(q, "Description"),
                    ["InstalledBy"] = Wmi.Str(q, "InstalledBy"), ["InstalledOn"] = on,
                };
            }).OrderByDescending(r => (string)r["InstalledOn"]!, StringComparer.Ordinal).ThenBy(r => (string)r["HotFixID"]!, StringComparer.Ordinal).ToList();
        }

        static object BootAndFirmware()
        {
            // The SecureBoot\State value is readable by any token; Confirm-SecureBootUEFI needed Administrator and read
            // access denied as "not supported".
            var sb = Reg.Value(@"HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
            var secureBoot = sb == null ? "NotSupportedOrLegacyBIOS" : Convert.ToInt32(sb, CultureInfo.InvariantCulture) == 1 ? "True" : "False";

            // Null means the class could not be read with this token: unknown, not absent.
            bool? tpmPresent = null;
            ManagementBaseObject? tpm = null;
            try
            {
                tpm = First(@"root\cimv2\security\microsofttpm", "SELECT IsEnabled_InitialValue, IsActivated_InitialValue, SpecVersion FROM Win32_Tpm");
                tpmPresent = tpm != null;
            }
            catch (Exception ex) when (ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException) { }

            List<Dictionary<string, object?>>? bde = null;
            try
            {
                bde = Wmi.Query(@"root\cimv2\security\microsoftvolumeencryption", "SELECT DriveLetter, ProtectionStatus, ConversionStatus, EncryptionMethod FROM Win32_EncryptableVolume")
                    .Select(v => new Dictionary<string, object?>
                    {
                        ["DriveLetter"] = Raw(v, "DriveLetter"), ["ProtectionStatus"] = Raw(v, "ProtectionStatus"),
                        ["ConversionStatus"] = Raw(v, "ConversionStatus"), ["EncryptionMethod"] = Raw(v, "EncryptionMethod"),
                    }).ToList();
            }
            catch (Exception ex) when (ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException) { }

            // Windows Update ships UEFI capsules as Firmware-class devices. A device whose name carries a newer version
            // than SMBIOS, in an error state, is a staged update waiting for the next reboot.
            var fw = new List<Dictionary<string, object?>>();
            try
            {
                var drivers = new Dictionary<string, ManagementBaseObject>(StringComparer.OrdinalIgnoreCase);
                foreach (var d in Wmi.Query(Cimv2, "SELECT DeviceID, DriverVersion, InfName FROM Win32_PnPSignedDriver WHERE DeviceClass='FIRMWARE'"))
                {
                    var id = Wmi.Str(d, "DeviceID");
                    if (id.Length > 0) drivers[id] = d;
                }
                foreach (var p in Wmi.Query(Cimv2, "SELECT Name, DeviceID, Status, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE PNPClass='Firmware'"))
                {
                    drivers.TryGetValue(Wmi.Str(p, "DeviceID"), out var drv);
                    fw.Add(new Dictionary<string, object?>
                    {
                        ["Name"] = Wmi.Str(p, "Name"), ["DeviceID"] = Wmi.Str(p, "DeviceID"), ["Status"] = Wmi.Str(p, "Status"),
                        ["ProblemCode"] = Raw(p, "ConfigManagerErrorCode"),
                        ["DriverVersion"] = drv != null ? Wmi.Str(drv, "DriverVersion") : "", ["InfName"] = drv != null ? Wmi.Str(drv, "InfName") : "",
                    });
                }
            }
            catch (Exception ex) when (ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException) { }

            return new Dictionary<string, object?>
            {
                ["SecureBootEnabled"] = secureBoot,
                ["TpmPresent"] = tpmPresent,
                ["TpmEnabled"] = tpm != null ? Raw(tpm, "IsEnabled_InitialValue") : null,
                ["TpmActivated"] = tpm != null ? Raw(tpm, "IsActivated_InitialValue") : null,
                ["TpmVersion"] = tpm != null ? Wmi.Str(tpm, "SpecVersion") : "",
                ["BitLockerVolumes"] = bde,
                ["FirmwareDevices"] = fw,
                ["BcdOutput"] = Exec.System32("bcdedit.exe", "/enum"),
            };
        }

        static object Disks() =>
            Wmi.Query(Cimv2, "SELECT DeviceID, DriveType, FileSystem, VolumeName, Size, FreeSpace, VolumeSerialNumber FROM Win32_LogicalDisk").Select(d => new Dictionary<string, object?>
            {
                ["DeviceID"] = Raw(d, "DeviceID"),
                ["DriveType"] = Raw(d, "DriveType"),
                ["FileSystem"] = Raw(d, "FileSystem"),
                ["VolumeName"] = Raw(d, "VolumeName"),
                ["SizeGB"] = Math.Round(Convert.ToDouble(Raw(d, "Size") ?? 0UL, CultureInfo.InvariantCulture) / 1073741824.0, 2),
                ["FreeGB"] = Math.Round(Convert.ToDouble(Raw(d, "FreeSpace") ?? 0UL, CultureInfo.InvariantCulture) / 1073741824.0, 2),
                ["VolumeSerialNumber"] = Raw(d, "VolumeSerialNumber"),
            }).ToList();
    }

    /// <summary>
    /// Local Entra / workplace-join / MDM enrollment facts from the registry (Get-FotonCloudJoinRows). No dsregcmd,
    /// Graph, or network call. Empty is a visibility gap (keys missing, other users' hives not loaded), not proof the
    /// host was never joined. Values whose names suggest secrets are never read.
    /// </summary>
    public static class CloudJoin
    {
        static readonly Regex Guid = new Regex(@"^[\{]?[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}[\}]?$");
        static readonly Regex Secret = new Regex("(?i)(password|secret|private|token|prt|refresh|encrypted)");

        public static List<Dictionary<string, object?>> Rows(IEnumerable<UserHive> hives)
        {
            var rows = new List<Dictionary<string, object?>>();
            Dictionary<string, object?> Row(string kind, string scope, string user, string identity, string tenantId, string tenantName, string deviceId,
                string upn, string idp, string provider, string etype, string key, string note) => new Dictionary<string, object?>
            {
                ["Kind"] = kind, ["Scope"] = scope, ["User"] = user, ["Identity"] = identity, ["TenantId"] = tenantId, ["TenantName"] = tenantName,
                ["DeviceId"] = deviceId, ["UPN"] = upn, ["IdpDomain"] = idp, ["ProviderId"] = provider, ["EnrollmentType"] = etype,
                ["SourceKey"] = key, ["Note"] = note,
            };

            foreach (var k in GuidKeys(@"HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"))
            {
                var device = V(k, "DeviceId");
                rows.Add(Row("AzureAdJoin", "Machine", "N/A", device.Length > 0 ? device : Leaf(k), V(k, "TenantId"), "", device, V(k, "UserEmail"), V(k, "IdpDomain"), "", "", Display(k),
                    "CloudDomainJoin JoinInfo. Local cache only; not a live tenant lookup."));
            }
            foreach (var k in GuidKeys(@"HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"))
            {
                var tenant = V(k, "TenantId");
                if (tenant.Length == 0) tenant = Leaf(k);
                rows.Add(Row("TenantInfo", "Machine", "N/A", tenant, tenant, V(k, "DisplayName"), "", "", "", "", "", Display(k),
                    "CloudDomainJoin TenantInfo DisplayName is cached locally and can lag a rename."));
            }
            foreach (var k in GuidKeys(@"HKLM:\SOFTWARE\Microsoft\Enrollments"))
            {
                string upn = V(k, "UPN"), tenant = V(k, "AADTenantID"), prov = V(k, "ProviderID"), etype = V(k, "EnrollmentType"), state = V(k, "EnrollmentState");
                if (upn.Length == 0 && tenant.Length == 0 && prov.Length == 0 && etype.Length == 0) continue;
                rows.Add(Row("MdmEnrollment", "Machine", "N/A", Leaf(k), tenant, "", "", upn, "", prov, etype, Display(k),
                    $"EnrollmentState={(state.Length > 0 ? state : "(not set)")}. Numeric EnrollmentType is recorded as stored; do not treat a number as a join verdict."));
            }
            foreach (var h in hives)
                foreach (var k in GuidKeys(Reg.Join(h.Root, @"Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo")))
                {
                    var device = V(k, "DeviceId");
                    rows.Add(Row("WorkplaceJoin", "User", h.UserName.Length > 0 ? h.UserName : h.Sid, device.Length > 0 ? device : Leaf(k), V(k, "TenantId"), "", device,
                        V(k, "UserEmail"), V(k, "IdpDomain"), "", "", Display(k), "WorkplaceJoin JoinInfo from a loaded user hive. Unloaded NTUSER is a visibility gap."));
                }

            return rows.OrderBy(r => (string)r["Kind"]!, StringComparer.OrdinalIgnoreCase).ThenBy(r => (string)r["Scope"]!, StringComparer.OrdinalIgnoreCase)
                .ThenBy(r => (string)r["User"]!, StringComparer.OrdinalIgnoreCase).ThenBy(r => (string)r["Identity"]!, StringComparer.OrdinalIgnoreCase).ToList();
        }

        static IEnumerable<string> GuidKeys(string root) => Reg.SubKeyNames(root).Where(n => Guid.IsMatch(n)).Select(n => Reg.Join(root, n)).Where(Reg.Exists);

        static string Leaf(string key) => key.Substring(key.LastIndexOf('\\') + 1);

        /// <summary>The key as a full registry path (HKEY_LOCAL_MACHINE\..., HKEY_USERS\...).</summary>
        static string Display(string key) => key.Replace("Registry::", "").Replace(@"HKLM:\", @"HKEY_LOCAL_MACHINE\");

        static string V(string key, string name)
        {
            if (Secret.IsMatch(name)) return "";
            var raw = Reg.Value(key, name);
            if (raw == null) return "";
            if (raw is byte[] b) return $"(binary {b.Length} bytes)";
            return BaselineDocument.PsString(raw);
        }
    }
}
