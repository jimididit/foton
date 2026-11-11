using System;
using System.Collections.Generic;
using System.Linq;

namespace Foton.Core
{
    /// <summary>
    /// Every task a -Deep collection records in its manifest, by category, plus the evtx_export step. Profiles name tasks
    /// from this list, so an ExcludeTasks typo is refused before anything runs (foton-collect) or while editing (the
    /// console). A Collect test runs every category and fails when a task is added, renamed, or moved without updating it.
    /// </summary>
    public static class CollectTasks
    {
        public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> ByCategory = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["System"] = new[]
            {
                "boot_and_firmware", "disks_and_volumes", "entra_workplace_join", "environment_variables", "hotfixes", "os_info",
                "system_restore_and_shadowcopies", "time_sync",
            },
            ["Users"] = new[]
            {
                "local_group_membership", "local_users", "logged_on_sessions", "password_and_lockout_policy", "rdp_configuration",
                "stored_credentials_and_trusts", "user_profiles", "user_rights_and_secpol",
            },
            ["Processes"] = new[]
            {
                "clipboard_and_recent_docs", "loaded_modules_nonstandard", "named_pipes", "powershell_console_history", "process_tree", "running_processes",
            },
            ["Network"] = new[]
            {
                "active_connections", "dns_cache", "dns_client_servers", "firewall_profiles", "firewall_rules_inbound_allow", "hosts_file",
                "ip_configuration", "listening_ports", "proxy_and_winhttp", "shares_and_sessions", "wifi_profiles",
            },
            ["Persistence"] = new[]
            {
                "accessibility_binary_integrity", "active_setup", "autorun_registry_keys", "bits_jobs", "cmd_autorun", "com_hijack_candidates",
                "known_dlls", "netsh_helpers", "office_addins_and_templates", "scheduled_task_files", "scheduled_tasks", "screensaver", "services",
                "session_manager_boot", "silent_process_exit", "startup_approved", "startup_folder_items", "time_providers",
                "winlogon_lsa_and_dll_hijacks", "winsock_lsp", "wmi_event_subscriptions",
            },
            ["Security"] = new[]
            {
                "applocker_wdac_and_policy", "audit_policy", "defender_detections", "defender_preferences_and_exclusions", "defender_status",
                "gpresult_html", "hardening_registry_settings", "installed_av_products", "non_microsoft_root_certificates", "powershell_environment",
                "smb_and_winrm_config",
            },
            ["EventLogs"] = new[]
            {
                "app_crashes", "bits_client", "defender_operational", "event_log_configuration", CollectionProfile.EvtxExport, "powershell_classic",
                "powershell_operational", "security_account_management", "security_kerberos_ntlm", "security_logon_events",
                "security_object_and_share_access", "security_policy_and_log_changes", "security_process_creation",
                "security_scheduled_task_and_service", "sysmon_operational", "system_log_and_boot", "system_service_and_driver",
                "task_scheduler_operational", "terminal_services_local", "terminal_services_remote", "windows_firewall", "wmi_activity",
            },
            ["Filesystem"] = new[]
            {
                "alternate_data_streams", "amcache_hive", "appcompatcache_export", "bam_dam_user_settings", "browser_databases",
                "executables_in_user_writable_paths", "hidden_or_odd_root_items", "host_text_logs", "onedrive_teams_local", "prefetch_files",
                "prefetch_listing", "recently_modified_system_files", "recycle_bin_contents", "registry_hives_machine", "registry_hives_user",
                "scheduled_task_xml", "shortcut_and_jumplist_files", "shortcut_and_jumplist_inventory", "srum_database", "task_action_scripts",
                "usb_device_history", "usn_journal",
            },
            ["Software"] = new[]
            {
                "appx_packages", "browser_extensions", "drivers", "driverstore_inventory", "installed_software", "pnp_devices",
                "remote_access_tool_indicators",
            },
        };

        /// <summary>The category a task (or evtx_export) belongs to; null for a name that is not a Collect task.</summary>
        public static string? CategoryOf(string task) =>
            ByCategory.Where(kv => kv.Value.Contains(task, StringComparer.OrdinalIgnoreCase)).Select(kv => kv.Key).FirstOrDefault();

        /// <summary>ExcludeTasks names that are not a Collect task (nor the evtx_export step).</summary>
        public static string[] Unknown(IEnumerable<string> names) => names.Where(n => CategoryOf(n) == null).ToArray();
    }
}
