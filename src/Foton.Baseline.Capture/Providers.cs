using System.Collections.Generic;

namespace Foton.Baseline.Capture
{
    /// <summary>
    /// Every baseline provider, in the order 1.38.x loaded them (alphabetical by provider file). The order is
    /// the order of record types in baseline.json and therefore part of the payload hash: append new types in
    /// alphabetical position and bump the baseline schema.
    /// </summary>
    public static class Providers
    {
        public static IReadOnlyList<Provider> All => new[]
        {
            RegistryProviders.ActiveSetup,
            RegistryProviders.AppInitDll,
            RegistryProviders.Autorun,
            OtherProviders.BitsJob,
            OtherProviders.Certificate,
            RegistryProviders.CmdAutoRun,
            WmiProviders.DefenderPreference,
            WmiProviders.Driver,
            WmiProviders.FirewallRule,
            RegistryProviders.HardeningRegistry,
            OtherProviders.HostsEntry,
            RegistryProviders.ImageFileExecution,
            RegistryProviders.InstalledSoftware,
            RegistryProviders.KnownDll,
            WmiProviders.Listener,
            WmiProviders.LocalAccount,
            OtherProviders.LocalGroupMember,
            RegistryProviders.LsaPackage,
            RegistryProviders.MachineEnvironment,
            RegistryProviders.NetshHelper,
            WmiProviders.NetworkShare,
            RegistryProviders.PrintMonitor,
            RegistryProviders.ProxyConfig,
            RegistryProviders.RemoteAccessConfig,
            WmiProviders.ScheduledTask,
            WmiProviders.Service,
            RegistryProviders.SessionManager,
            RegistryProviders.SilentProcessExit,
            RegistryProviders.StartupApproved,
            OtherProviders.StartupFile,
            OtherProviders.SystemBinary,
            RegistryProviders.TimeProvider,
            RegistryProviders.UserAutorun,
            OtherProviders.WdacApplockerPolicy,
            RegistryProviders.Winlogon,
            RegistryProviders.WinsockLsp,
            WmiProviders.WmiPermanentEvent,
        };
    }
}
