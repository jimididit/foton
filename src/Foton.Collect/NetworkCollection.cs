using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using Foton.Core;
using Foton.Win;
using static Foton.Collect.CollectText;

namespace Foton.Collect
{
    /// <summary>
    /// Connections, DNS, firewall, shares, proxy, and Wi-Fi (Invoke-FotonNetworkCollection). The NetTCPIP, DnsClient,
    /// NetSecurity, and SmbShare cmdlets 1.38.x called are CDXML wrappers over these root\StandardCimv2 and SMB classes;
    /// enum values are rendered with the cmdlets' names.
    /// </summary>
    public static class NetworkCollection
    {
        const string Cat = "Network", Cimv2 = @"root\cimv2", Std = @"root\StandardCimv2", Smb = @"root\Microsoft\Windows\SMB";

        public static void Run(FotonSession s)
        {
            s.Status.Write("Collecting network configuration, connections, and DNS state", StatusLevel.Step);
            Task(s, Cat, "active_connections", "TCP connections mapped to owning process", TaskFormat.Csv, ActiveConnections);
            Task(s, Cat, "listening_ports", "Listening TCP/UDP endpoints with owning process", TaskFormat.Csv, ListeningPorts);
            Task(s, Cat, "ip_configuration", "Adapters, addresses, routes, ARP cache", TaskFormat.Txt, () => new List<string>
            {
                "--- ipconfig /all ---", Exec.System32("ipconfig.exe", "/all"),
                "--- route print ---", Exec.System32("route.exe", "print"),
                "--- arp -a ---", Exec.System32("arp.exe", "-a"),
                "--- netsh interface show interface ---", Exec.System32("netsh.exe", "interface show interface"),
            });
            Task(s, Cat, "dns_cache", "Resolved DNS entries currently cached", TaskFormat.Csv, () =>
                Wmi.Query(Std, "SELECT Entry, Name, Type, Status, TimeToLive, Data FROM MSFT_DNSClientCache").Select(d => new Dictionary<string, object?>
                {
                    ["Entry"] = Raw(d, "Entry"), ["Name"] = Raw(d, "Name"), ["Type"] = Raw(d, "Type"), ["Status"] = Raw(d, "Status"),
                    ["TimeToLive"] = Raw(d, "TimeToLive"), ["Data"] = Raw(d, "Data"),
                }).ToList());
            Task(s, Cat, "dns_client_servers", "Configured DNS servers per interface", TaskFormat.Csv, () =>
                Wmi.Query(Std, "SELECT InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses FROM MSFT_DNSClientServerAddress").Select(d => new Dictionary<string, object?>
                {
                    ["InterfaceAlias"] = Raw(d, "InterfaceAlias"), ["InterfaceIndex"] = Raw(d, "InterfaceIndex"),
                    ["AddressFamily"] = Raw(d, "AddressFamily"),
                    ["ServerAddresses"] = Raw(d, "ServerAddresses") is string[] a ? string.Join(", ", a) : "",
                }).ToList());
            Task(s, Cat, "hosts_file", "hosts file contents (redirection indicator)", TaskFormat.Txt, () =>
            {
                var p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
                return HostInfo.Accessible(p) ? (object)File.ReadAllLines(p) : "hosts file not found";
            });
            Task(s, Cat, "firewall_profiles", "Firewall profile enablement and default actions", TaskFormat.Csv, () =>
                Wmi.Query(Std, "SELECT Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFileName FROM MSFT_NetFirewallProfile")
                    .Select(p => new Dictionary<string, object?>
                    {
                        ["Name"] = Raw(p, "Name"), ["Enabled"] = Gpo(Raw(p, "Enabled")),
                        ["DefaultInboundAction"] = FwAction(Raw(p, "DefaultInboundAction")), ["DefaultOutboundAction"] = FwAction(Raw(p, "DefaultOutboundAction")),
                        ["LogAllowed"] = Gpo(Raw(p, "LogAllowed")), ["LogBlocked"] = Gpo(Raw(p, "LogBlocked")), ["LogFileName"] = Raw(p, "LogFileName"),
                    }).ToList());
            Task(s, Cat, "firewall_rules_inbound_allow", "Enabled inbound allow rules (exposure surface)", TaskFormat.Csv, InboundAllowRules);
            Task(s, Cat, "shares_and_sessions", "SMB shares, permissions, open sessions and files", TaskFormat.Txt, Shares);
            Task(s, Cat, "proxy_and_winhttp", "User and system proxy configuration", TaskFormat.Txt, () => Proxy(s));
            Task(s, Cat, "wifi_profiles", "Saved wireless profiles", TaskFormat.Txt, () => Exec.System32("netsh.exe", "wlan show profiles"));
        }

        // CDXML enum names the cmdlets printed (NetTCPIP TcpState, NetSecurity GpoBoolean and Action). DnsClient's
        // AddressFamily and the DNS cache Type and Status were written as their raw numbers.
        static readonly Dictionary<int, string> TcpStates = new Dictionary<int, string>
        {
            [1] = "Closed", [2] = "Listen", [3] = "SynSent", [4] = "SynReceived", [5] = "Established", [6] = "FinWait1", [7] = "FinWait2",
            [8] = "CloseWait", [9] = "Closing", [10] = "LastAck", [11] = "TimeWait", [12] = "DeleteTCB", [100] = "Bound",
        };

        static string Named(Dictionary<int, string> names, object? v) =>
            v == null ? "" : names.TryGetValue(Convert.ToInt32(v), out var n) ? n : Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) ?? "";

        static string Gpo(object? v) => Named(new Dictionary<int, string> { [0] = "False", [1] = "True", [2] = "NotConfigured" }, v);
        static string FwAction(object? v) => Named(new Dictionary<int, string> { [0] = "NotConfigured", [2] = "Allow", [4] = "Block" }, v);
        [Flags] enum FwProfile { Any = 0, Domain = 1, Private = 2, Public = 4, NotApplicable = 65535 }

        static Dictionary<int, ManagementBaseObject> ProcessMap()
        {
            var map = new Dictionary<int, ManagementBaseObject>();
            try
            {
                foreach (var p in Wmi.Query(Cimv2, "SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process"))
                    map[Convert.ToInt32(Raw(p, "ProcessId"))] = p;
            }
            catch (Exception ex) when (WmiFailed(ex)) { }
            return map;
        }

        // Loopback, unspecified, RFC 1918, link-local, multicast, broadcast, and IPv6 unique-local are not external.
        // 1.38.x's test knew only ff00: for multicast.
        static readonly Regex Internal = new Regex(
            @"^(127\.|0\.0\.0\.0|::1$|::$|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|22[4-9]\.|23[0-9]\.|255\.255\.255\.255$|fe80:|ff[0-9a-f]{2}:|f[cd][0-9a-f]{2}:)",
            RegexOptions.IgnoreCase);

        internal static bool IsExternal(string remote) => !Internal.IsMatch(remote);

        static object ActiveConnections()
        {
            var procs = ProcessMap();
            var rows = new List<Dictionary<string, object?>>();
            try
            {
                foreach (var c in Wmi.Query(Std, "SELECT LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, CreationTime FROM MSFT_NetTCPConnection"))
                {
                    procs.TryGetValue(Convert.ToInt32(Raw(c, "OwningProcess") ?? 0), out var proc);
                    var remote = Wmi.Str(c, "RemoteAddress");
                    var path = proc != null ? Wmi.Str(proc, "ExecutablePath") : "";
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["LocalAddress"] = Wmi.Str(c, "LocalAddress"), ["LocalPort"] = Raw(c, "LocalPort"),
                        ["RemoteAddress"] = remote, ["RemotePort"] = Raw(c, "RemotePort"),
                        ["State"] = Named(TcpStates, Raw(c, "State")), ["OwningPID"] = Raw(c, "OwningProcess"),
                        ["ProcessName"] = proc != null ? Wmi.Str(proc, "Name") : "", ["ProcessPath"] = path,
                        ["CommandLine"] = proc != null ? Wmi.Str(proc, "CommandLine") : "",
                        ["RemoteIsExternal"] = IsExternal(remote),
                        ["UserWritablePath"] = proc != null && UserWritable(path),
                        ["CreationTimeUtc"] = Dmtf(Raw(c, "CreationTime")),
                    });
                }
            }
            catch (Exception ex) when (WmiFailed(ex))
            {
                rows.Add(new Dictionary<string, object?>
                {
                    ["LocalAddress"] = "ERROR", ["LocalPort"] = 0, ["RemoteAddress"] = ex.Message, ["RemotePort"] = 0, ["State"] = "", ["OwningPID"] = 0,
                    ["ProcessName"] = "", ["ProcessPath"] = "", ["CommandLine"] = "", ["RemoteIsExternal"] = false, ["UserWritablePath"] = false, ["CreationTimeUtc"] = "",
                });
            }
            return rows;
        }

        static object ListeningPorts()
        {
            var procs = ProcessMap();
            var rows = new List<Dictionary<string, object?>>();
            void Add(string protocol, ManagementBaseObject e)
            {
                procs.TryGetValue(Convert.ToInt32(Raw(e, "OwningProcess") ?? 0), out var proc);
                rows.Add(new Dictionary<string, object?>
                {
                    ["Protocol"] = protocol, ["LocalAddress"] = Wmi.Str(e, "LocalAddress"), ["LocalPort"] = Raw(e, "LocalPort"), ["OwningPID"] = Raw(e, "OwningProcess"),
                    ["ProcessName"] = proc != null ? Wmi.Str(proc, "Name") : "", ["ProcessPath"] = proc != null ? Wmi.Str(proc, "ExecutablePath") : "",
                });
            }
            try { foreach (var c in Wmi.Query(Std, "SELECT LocalAddress, LocalPort, OwningProcess FROM MSFT_NetTCPConnection WHERE State = 2")) Add("TCP", c); }
            catch (Exception ex) when (WmiFailed(ex)) { }
            try { foreach (var u in Wmi.Query(Std, "SELECT LocalAddress, LocalPort, OwningProcess FROM MSFT_NetUDPEndpoint")) Add("UDP", u); }
            catch (Exception ex) when (WmiFailed(ex)) { }
            return rows.OrderBy(r => (string)r["Protocol"]!, StringComparer.OrdinalIgnoreCase).ThenBy(r => Convert.ToInt32(r["LocalPort"] ?? 0)).ToList();
        }

        static object InboundAllowRules()
        {
            var rows = new List<Dictionary<string, object?>>();
            try
            {
                var filters = new Dictionary<string, ManagementBaseObject>(StringComparer.OrdinalIgnoreCase);
                // Get-NetFirewallPortFilter wraps MSFT_NetProtocolPortFilter; its InstanceID is the rule's. A standard token is
                // denied some filters; the readable ones are kept, as the cmdlet kept them.
                var readable = Wmi.QueryReadable(Std, "SELECT * FROM MSFT_NetProtocolPortFilter", out var bulkError);
                foreach (var pf in readable) filters[Wmi.Str(pf, "InstanceID")] = pf;
                // Direction 1 Inbound, Action 2 Allow, Enabled 1 True.
                foreach (var r in Wmi.Query(Std, "SELECT InstanceID, DisplayName, Profiles, DisplayGroup, Description FROM MSFT_NetFirewallRule WHERE Direction = 1 AND Action = 2 AND Enabled = 1"))
                {
                    var id = Wmi.Str(r, "InstanceID");
                    // An access-denied instance ends the bulk enumeration early (Get-CimInstance skipped past it), so a rule
                    // left without a filter is looked up on its own.
                    if (!filters.TryGetValue(id, out var f) && bulkError != null)
                    {
                        f = Wmi.QueryReadable(Std, $"SELECT * FROM MSFT_NetProtocolPortFilter WHERE InstanceID = '{WqlString(id)}'", out _).FirstOrDefault();
                        if (f != null) filters[id] = f;
                    }
                    var profiles = Raw(r, "Profiles");
                    rows.Add(new Dictionary<string, object?>
                    {
                        ["Name"] = Wmi.Str(r, "DisplayName"),
                        ["Profile"] = profiles == null ? "" : ((FwProfile)Convert.ToInt32(profiles)).ToString(),
                        ["Protocol"] = f != null ? Wmi.Str(f, "Protocol") : "",
                        // An empty LocalPort is "any port"; the cmdlet printed it as Any.
                        ["LocalPort"] = f == null ? "" : Raw(f, "LocalPort") is string[] ports && ports.Length > 0 ? string.Join(",", ports) : "Any",
                        ["Program"] = "",
                        ["Group"] = Wmi.Str(r, "DisplayGroup"),
                        ["Description"] = Wmi.Str(r, "Description"),
                    });
                }
            }
            catch (Exception ex) when (WmiFailed(ex)) { }
            return rows;
        }

        static readonly Dictionary<int, string> AccessControlType = new Dictionary<int, string> { [0] = "Allow", [1] = "Deny" };
        static readonly Dictionary<int, string> AccessRight = new Dictionary<int, string> { [0] = "Full", [1] = "Change", [2] = "Read", [3] = "Custom" };

        static object Shares()
        {
            var lines = new List<string> { "--- net share ---", Exec.System32("net.exe", "share"), "--- Get-SmbShare ---" };
            List<ManagementBaseObject>? shares = null;
            try
            {
                // SELECT *: GetAccessRights needs the instance path, which a column list leaves out.
                shares = Wmi.Query(Smb, "SELECT * FROM MSFT_SmbShare");
                lines.AddRange(Table(new[] { "Name", "Path", "Description", "ShareType" },
                    shares.Select(s => new[] { Wmi.Str(s, "Name"), Wmi.Str(s, "Path"), Wmi.Str(s, "Description"), Wmi.Str(s, "ShareType") })));
            }
            catch (Exception ex) when (WmiFailed(ex)) { }
            lines.Add("--- Get-SmbShareAccess ---");
            if (shares != null)
                foreach (var share in shares.OfType<ManagementObject>())
                {
                    try
                    {
                        using (var result = share.InvokeMethod("GetAccessRights", null, null))
                        {
                            var entries = result?["ShareAccessControlEntries"] as ManagementBaseObject[] ?? new ManagementBaseObject[0];
                            try
                            {
                                lines.AddRange(Table(new[] { "Name", "ScopeName", "AccountName", "AccessControlType", "AccessRight" }, entries.Select(e => new[]
                                {
                                    Wmi.Str(e, "Name"), Wmi.Str(e, "ScopeName"), Wmi.Str(e, "AccountName"),
                                    Named(AccessControlType, Raw(e, "AccessControlType")), Named(AccessRight, Raw(e, "AccessRight")),
                                }).ToList()));
                            }
                            finally { foreach (var e in entries) e.Dispose(); }
                        }
                    }
                    catch (Exception ex) when (WmiFailed(ex)) { }
                }
            lines.Add("--- net session ---");
            lines.Add(Exec.System32("net.exe", "session"));
            lines.Add("--- Get-SmbOpenFile ---");
            try
            {
                lines.AddRange(Table(new[] { "ClientUserName", "ClientComputerName", "Path" },
                    Wmi.Query(Smb, "SELECT ClientUserName, ClientComputerName, Path FROM MSFT_SmbOpenFile")
                        .Select(f => new[] { Wmi.Str(f, "ClientUserName"), Wmi.Str(f, "ClientComputerName"), Wmi.Str(f, "Path") })));
            }
            catch (Exception ex) when (WmiFailed(ex)) { }
            lines.Add("--- net use ---");
            lines.Add(Exec.System32("net.exe", "use"));
            return lines;
        }

        static readonly Regex ProxyValue = new Regex("Proxy|AutoConfig", RegexOptions.IgnoreCase);

        static object Proxy(FotonSession s)
        {
            var lines = new List<string> { "--- netsh winhttp show proxy ---", Exec.System32("netsh.exe", "winhttp show proxy") };
            foreach (var h in HostInfo.HiveRoots(s.IsElevated))
            {
                var key = Reg.Join(h.Root, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
                if (!Reg.Exists(key)) continue;
                lines.Add($"=== Internet Settings for {h.UserName} ===");
                lines.AddRange(Table(new[] { "Key", "Name", "Value" }, Reg.ValueList(key).Where(v => ProxyValue.IsMatch(v.Name)).Select(v => new[] { v.Key, v.Name, v.Value })));
            }
            return lines;
        }
    }
}
