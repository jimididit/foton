using System;
using System.Linq;

namespace Foton.Baseline.Compare
{
    /// <summary>
    /// Attention weight for a baseline change (Get-FotonBaselineChangeSeverity, same rules and order;
    /// later rules win). A fact ranking, not a verdict: High = persistence or trust surface,
    /// Info = expected software churn. Comparisons are case-insensitive, as PowerShell -eq / -like are.
    /// </summary>
    public static class ChangeSeverity
    {
        public static string Of(BaselineChange c)
        {
            bool T(string type) => Eq(c.RecordType, type);
            bool F(string field) => Eq(c.Field, field);
            bool C(params string[] kinds) => kinds.Any(k => Eq(c.ChangeType, k));
            bool I(params string[] ids) => ids.Any(i => Eq(c.Identity, i));
            bool Like(string prefix) => c.Identity.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

            var sev = "Medium";
            if (T("InstalledSoftware") && F("DisplayVersion")) sev = "Info";
            if (T("Listener") && C("Added")) sev = "Low";
            if (T("FirewallRule") && C("Added")) sev = "Medium";
            if (T("LocalAccount") && C("Added")) sev = "Medium";
            if (T("Service") && F("PathName")) sev = "High";
            if (T("Driver") && F("PathName")) sev = "High";
            if (T("Autorun") && F("Command")) sev = "High";
            if (T("ScheduledTask") && F("Actions")) sev = "High";
            if (T("HardeningRegistry") && I("UseLogonCredential", "EnableLUA", "AlwaysInstallElevated")) sev = "High";
            if (T("LocalGroupMember") && C("Added") && Like("Administrators|")) sev = "High";
            if (T("Certificate") && C("Added") && Like(@"Cert:\LocalMachine\Root|")) sev = "High";
            if (T("NetworkShare") && C("Added")) sev = "High";
            if (T("SystemBinary") && F("Sha256")) sev = "High";
            if (T("HostsEntry") && C("Added")) sev = "High";
            if (T("WmiPermanentEvent") && C("Added")) sev = "High";
            if (T("StartupFile") && C("Added")) sev = "High";
            if (T("ImageFileExecution") && (C("Added") || F("Debugger"))) sev = "High";
            if (T("Winlogon") && I("Userinit", "Shell", "GinaDLL", "System", "UIHost")) sev = "High";
            if (T("AppInitDll") && C("Added", "Modified")) sev = "High";
            if (T("MachineEnvironment") && I("Path") && C("Modified")) sev = "High";
            if (T("StartupApproved") && F("State")) sev = "High";
            if (T("UserAutorun") && (C("Added") || F("Command"))) sev = "High";
            if (T("DefenderPreference") && I("Switch|DisableRealtimeMonitoring")) sev = "High";
            if (T("RemoteAccessConfig") && C("Added", "Removed", "Modified")) sev = "High";
            if (T("LsaPackage") && C("Added", "Removed")) sev = "High";
            if (T("PrintMonitor") && (C("Added", "Removed") || F("Driver"))) sev = "High";
            if (T("BitsJob") && F("NotifyCmdLine")) sev = "High";
            if (T("CmdAutoRun")) sev = "High";
            if (T("SessionManager")) sev = "High";
            if (T("KnownDll")) sev = "High";
            if (T("ProxyConfig")) sev = "High";
            if (T("ProxyConfig") && c.Identity.EndsWith("|AutoConfigURL", StringComparison.OrdinalIgnoreCase)) sev = "Medium";
            if (T("WinsockLsp")) sev = "High";
            if (T("ActiveSetup") && (C("Added", "Removed") || F("StubPath"))) sev = "High";
            if (T("ActiveSetup") && F("Version")) sev = "Info";
            if (T("SilentProcessExit") && (C("Added", "Removed") || F("MonitorProcess"))) sev = "High";
            if (T("NetshHelper")) sev = "High";
            if (T("TimeProvider") && (C("Added", "Removed") || F("DllName"))) sev = "High";
            if (T("TimeProvider") && (F("Enabled") || F("InputProvider"))) sev = "Medium";
            if (T("WdacApplockerPolicy") && (C("Added", "Removed") || F("PolicyHash"))) sev = "High";
            return sev;
        }

        static bool Eq(string a, string b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }
}
