using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;

namespace Foton.Win
{
    public sealed class AppxPackage
    {
        public string Name { get; set; } = "";
        public string PackageFullName { get; set; } = "";
        public string Publisher { get; set; } = "";
        public string Version { get; set; } = "";
        public string InstallLocation { get; set; } = "";
        public string SignatureKind { get; set; } = "";
        public string Status { get; set; } = "";
    }

    /// <summary>
    /// Installed Store/AppX packages through Windows.Management.Deployment.PackageManager, the WinRT API Get-AppxPackage
    /// wraps. The type is bound by name (ContentType=WindowsRuntime), so no Windows metadata reference ships in the
    /// executable. Main and framework packages, as Get-AppxPackage lists by default.
    /// </summary>
    public static class Appx
    {
        const string ManagerType = "Windows.Management.Deployment.PackageManager, Windows.Management.Deployment, ContentType=WindowsRuntime";
        const string TypesEnum = "Windows.Management.Deployment.PackageTypes, Windows.Management.Deployment, ContentType=WindowsRuntime";
        const uint MainAndFramework = 1 | 2;

        /// <summary>Every user's packages (needs Administrator), or the current user's.</summary>
        public static List<AppxPackage> Packages(bool allUsers)
        {
            var managerType = Type.GetType(ManagerType, throwOnError: true)!;
            var typesType = Type.GetType(TypesEnum, throwOnError: true)!;
            var manager = Activator.CreateInstance(managerType)!;
            var types = Enum.ToObject(typesType, MainAndFramework);
            var found = allUsers
                ? managerType.GetMethod("FindPackagesWithPackageTypes", new[] { typesType })!.Invoke(manager, new[] { types })
                : managerType.GetMethod("FindPackagesForUserWithPackageTypes", new[] { typeof(string), typesType })!.Invoke(manager, new object[] { "", types });
            var list = new List<AppxPackage>();
            foreach (var p in (IEnumerable)found!)
            {
                var id = Get(p, "Id");
                var version = Get(id, "Version");
                list.Add(new AppxPackage
                {
                    Name = Str(Get(id, "Name")),
                    PackageFullName = Str(Get(id, "FullName")),
                    Publisher = Str(Get(id, "Publisher")),
                    Version = version == null ? "" : string.Join(".", new[] { "Major", "Minor", "Build", "Revision" }.Select(f => Str(Field(version, f)))),
                    InstallLocation = Str(Get(Get(p, "InstalledLocation"), "Path")),
                    SignatureKind = Str(Get(p, "SignatureKind")),
                    Status = StatusOf(Get(p, "Status")),
                });
            }
            return list;
        }

        /// <summary>Ok, or the package status flags that are set (Get-AppxPackage's Status).</summary>
        static string StatusOf(object? status)
        {
            if (status == null) return "";
            var ok = status.GetType().GetMethod("VerifyIsOK");
            if (ok != null && ok.Invoke(status, null) is bool b && b) return "Ok";
            var set = new List<string>();
            foreach (var flag in new[] { "LicenseIssue", "Modified", "Tampered", "Disabled", "NotAvailable", "PackageOffline", "DataOffline", "DeploymentInProgress", "DependencyIssue", "NeedsRemediation", "Servicing" })
                if (Get(status, flag) is bool v && v) set.Add(flag);
            return string.Join(", ", set);
        }

        /// <summary>A WinRT property, or null when it is missing or throws (InstalledLocation throws for some staged packages).</summary>
        static object? Get(object? o, string name)
        {
            if (o == null) return null;
            try { return o.GetType().GetProperty(name)?.GetValue(o); }
            catch (Exception ex) when (ex is TargetInvocationException || ex is System.Runtime.InteropServices.COMException || ex is UnauthorizedAccessException || ex is ArgumentException) { return null; }
        }

        static object? Field(object o, string name) => o.GetType().GetField(name)?.GetValue(o);

        static string Str(object? v) => v == null ? "" : Convert.ToString(v, CultureInfo.InvariantCulture) ?? "";
    }
}
