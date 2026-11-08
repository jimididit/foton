using System.Text.RegularExpressions;
using Foton.Core;

namespace Foton.Win
{
    /// <summary>
    /// The DLL a svchost-hosted service runs: svchost.exe is shared, so the code that runs is the ServiceDll value under
    /// the service's Parameters key (older services set it on the service key itself). Per-user service instances
    /// (Name_&lt;hex&gt;, created at logon) have none of their own and run their template's DLL. Used by Collect
    /// (services.csv) and Baseline (Service records) so both report the same value.
    /// </summary>
    public static class ServiceDll
    {
        const string ServicesKey = @"HKLM:\SYSTEM\CurrentControlSet\Services\";
        static readonly Regex PerUserInstance = new Regex("^(?<base>.+)_[0-9a-fA-F]{4,8}$");

        /// <summary>The ServiceDll value ("" when none) and where it came from: Parameters, ServiceKey, or Template:&lt;name&gt;.</summary>
        public static string Resolve(string serviceName, out string source)
        {
            var dll = Read(serviceName, out source);
            if (dll.Length > 0) return dll;
            var inst = PerUserInstance.Match(serviceName);
            if (inst.Success)
            {
                var template = inst.Groups["base"].Value;
                dll = Read(template, out _);
                if (dll.Length > 0) { source = "Template:" + template; return dll; }
            }
            source = "";
            return "";
        }

        static string Read(string name, out string source)
        {
            source = "Parameters";
            var dll = BaselineDocument.PsString(Reg.Value(ServicesKey + name + @"\Parameters", "ServiceDll"));
            if (dll.Length > 0) return dll;
            source = "ServiceKey";
            dll = BaselineDocument.PsString(Reg.Value(ServicesKey + name, "ServiceDll"));
            if (dll.Length > 0) return dll;
            source = "";
            return "";
        }
    }
}
