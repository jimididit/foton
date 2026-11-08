using System;
using System.Management;
using System.Reflection;
using Foton.Core;
using Foton.Win;

namespace Foton.Collect
{
    /// <summary>Host and collector facts for the custody header (Write-FotonChainOfCustody). Anything unreadable stays null ("unknown").</summary>
    public static class HostFacts
    {
        public static CustodyFacts Custody()
        {
            var f = new CustodyFacts();
            try
            {
                foreach (var os in Wmi.Query(@"root\cimv2", "SELECT Caption, Version, BuildNumber, LastBootUpTime FROM Win32_OperatingSystem"))
                {
                    f.OsCaption = Wmi.Str(os, "Caption");
                    f.OsVersion = Wmi.Str(os, "Version");
                    f.OsBuild = Wmi.Str(os, "BuildNumber");
                    var boot = Wmi.Str(os, "LastBootUpTime");
                    if (boot.Length > 0) f.LastBootUtc = ManagementDateTimeConverter.ToDateTime(boot).ToUniversalTime();
                }
            }
            catch (Exception ex) when (ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException || ex is ArgumentException) { }
            try
            {
                foreach (var cs in Wmi.Query(@"root\cimv2", "SELECT Domain, Manufacturer, Model FROM Win32_ComputerSystem"))
                {
                    f.Domain = Wmi.Str(cs, "Domain");
                    f.Manufacturer = Wmi.Str(cs, "Manufacturer");
                    f.Model = Wmi.Str(cs, "Model");
                }
            }
            catch (Exception ex) when (ex is ManagementException || ex is UnauthorizedAccessException || ex is System.Runtime.InteropServices.COMException) { }
            var exe = Assembly.GetEntryAssembly()?.Location;
            if (!string.IsNullOrEmpty(exe))
            {
                f.ExecutablePath = exe;
                try { f.ExecutableSha256 = Hashing.Sha256Hex(exe!); } catch (Exception ex) when (ex is System.IO.IOException || ex is UnauthorizedAccessException) { }
            }
            return f;
        }
    }
}
