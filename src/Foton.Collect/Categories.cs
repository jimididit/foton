using System;
using System.Collections.Generic;
using System.Linq;
using Foton.Core;

namespace Foton.Collect
{
    /// <summary>One collection category: its CaseCategories key and the method that runs its tasks.</summary>
    public sealed class CollectCategory
    {
        public CollectCategory(string key, Action<FotonSession> run) { Key = key; Run = run; }
        /// <summary>The CaseCategories key (System, Users, Processes, ...).</summary>
        public string Key { get; }
        public Action<FotonSession> Run { get; }
    }

    /// <summary>
    /// Categories in the 1.38.x run order (Invoke-FotonTriage): Processes, Network, Users, System, Persistence, Security,
    /// Software, EventLogs, Filesystem. Volatile state comes first so the collector's own activity disturbs it least.
    /// To add a category, add a static class with a Run(FotonSession) method that calls TaskRunner.Run per task, and
    /// list it here in that order.
    /// </summary>
    public static class Categories
    {
        public static readonly IReadOnlyList<CollectCategory> InOrder = new[]
        {
            new CollectCategory("Processes", ProcessCollection.Run),
            new CollectCategory("Network", NetworkCollection.Run),
            new CollectCategory("Users", UserCollection.Run),
            new CollectCategory("System", SystemCollection.Run),
            new CollectCategory("Persistence", PersistenceCollection.Run),
            new CollectCategory("Security", SecurityCollection.Run),
            new CollectCategory("Software", SoftwareCollection.Run),
            new CollectCategory("EventLogs", EventLogCollection.Run),
            new CollectCategory("Filesystem", FilesystemCollection.Run),
        };

        /// <summary>
        /// Every task name a -Deep collection records in its manifest, so a profile's ExcludeTasks typo is refused before
        /// anything runs. A test runs every category and fails when a task is added or renamed without updating this list.
        /// </summary>
        public static readonly IReadOnlyList<string> TaskNames = new[]
        {
            "accessibility_binary_integrity", "active_connections", "active_setup", "alternate_data_streams", "amcache_hive", "app_crashes",
            "appcompatcache_export", "applocker_wdac_and_policy", "appx_packages", "audit_policy", "autorun_registry_keys", "bam_dam_user_settings",
            "bits_client", "bits_jobs", "boot_and_firmware", "browser_databases", "browser_extensions", "clipboard_and_recent_docs", "cmd_autorun",
            "com_hijack_candidates", "defender_detections", "defender_operational", "defender_preferences_and_exclusions", "defender_status",
            "disks_and_volumes", "dns_cache", "dns_client_servers", "drivers", "driverstore_inventory", "entra_workplace_join", "environment_variables",
            "event_log_configuration", "executables_in_user_writable_paths", "firewall_profiles", "firewall_rules_inbound_allow", "gpresult_html",
            "hardening_registry_settings", "hidden_or_odd_root_items", "host_text_logs", "hosts_file", "hotfixes", "installed_av_products",
            "installed_software", "ip_configuration", "known_dlls", "listening_ports", "loaded_modules_nonstandard", "local_group_membership",
            "local_users", "logged_on_sessions", "named_pipes", "netsh_helpers", "non_microsoft_root_certificates", "office_addins_and_templates",
            "onedrive_teams_local", "os_info", "password_and_lockout_policy", "pnp_devices", "powershell_classic", "powershell_console_history",
            "powershell_environment", "powershell_operational", "prefetch_files", "prefetch_listing", "process_tree", "proxy_and_winhttp",
            "rdp_configuration", "recently_modified_system_files", "recycle_bin_contents", "registry_hives_machine", "registry_hives_user",
            "remote_access_tool_indicators", "running_processes", "scheduled_task_files", "scheduled_task_xml", "scheduled_tasks", "screensaver",
            "security_account_management", "security_kerberos_ntlm", "security_logon_events", "security_object_and_share_access",
            "security_policy_and_log_changes", "security_process_creation", "security_scheduled_task_and_service", "services", "session_manager_boot",
            "shares_and_sessions", "shortcut_and_jumplist_files", "shortcut_and_jumplist_inventory", "silent_process_exit", "smb_and_winrm_config",
            "srum_database", "startup_approved", "startup_folder_items", "stored_credentials_and_trusts", "sysmon_operational", "system_log_and_boot",
            "system_restore_and_shadowcopies", "system_service_and_driver", "task_action_scripts", "task_scheduler_operational",
            "terminal_services_local", "terminal_services_remote", "time_providers", "time_sync", "usb_device_history", "user_profiles",
            "user_rights_and_secpol", "usn_journal", "wifi_profiles", "windows_firewall", "winlogon_lsa_and_dll_hijacks", "winsock_lsp", "wmi_activity",
            "wmi_event_subscriptions",
        };

        /// <summary>ExcludeTasks names that are not a Collect task (nor the evtx_export step).</summary>
        public static string[] UnknownTaskNames(IEnumerable<string> names) =>
            names.Where(n => !string.Equals(n, CollectionProfile.EvtxExport, StringComparison.OrdinalIgnoreCase)
                && !TaskNames.Contains(n, StringComparer.OrdinalIgnoreCase)).ToArray();
    }
}
