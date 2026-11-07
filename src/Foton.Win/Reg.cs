using System;
using System.Collections.Generic;
using Microsoft.Win32;
using Foton.Core;

namespace Foton.Win
{
    /// <summary>One registry value as Get-FotonRegValueList returned it.</summary>
    public sealed class RegValue
    {
        public string Key { get; set; } = "";
        public string Name { get; set; } = "";
        /// <summary>The value rendered as 1.38.x did ("$value -join ' '"): arrays and binary space-joined.</summary>
        public string Value { get; set; } = "";
    }

    /// <summary>
    /// Read-only registry access that accepts the 1.38.x path forms ("HKLM:\...", "Registry::HKEY_USERS\...",
    /// "HKEY_LOCAL_MACHINE\..."), always in the 64-bit view on 64-bit Windows, and never throws: a missing
    /// or unreadable key is null / empty, as Get-FotonRegValue was.
    /// </summary>
    public static class Reg
    {
        static readonly RegistryView View = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default;

        public static RegistryKey? Open(string path)
        {
            try
            {
                if (!Split(path, out var hive, out var sub)) return null;
                var root = RegistryKey.OpenBaseKey(hive, View);
                return sub.Length == 0 ? root : root.OpenSubKey(sub, writable: false);
            }
            catch (Exception) { return null; }
        }

        public static bool Exists(string path)
        {
            using (var k = Open(path)) return k != null;
        }

        /// <summary>The raw value (string, int, long, string[], byte[]; REG_EXPAND_SZ expanded), or null.</summary>
        public static object? Value(string path, string name)
        {
            try
            {
                using (var k = Open(path))
                    return k?.GetValue(name);
            }
            catch (Exception) { return null; }
        }

        /// <summary>Every value under a key (the default value appears as "(default)", as in PowerShell).</summary>
        public static List<RegValue> ValueList(string path)
        {
            var list = new List<RegValue>();
            try
            {
                using (var k = Open(path))
                {
                    if (k == null) return list;
                    foreach (var n in k.GetValueNames())
                        list.Add(new RegValue { Key = path, Name = n.Length == 0 ? "(default)" : n, Value = BaselineDocument.PsString(k.GetValue(n)) });
                }
            }
            catch (Exception) { }
            return list;
        }

        public static string[] SubKeyNames(string path)
        {
            try
            {
                using (var k = Open(path)) return k?.GetSubKeyNames() ?? new string[0];
            }
            catch (Exception) { return new string[0]; }
        }

        /// <summary>Joins a child the way Join-Path did: one backslash between parent and child.</summary>
        public static string Join(string parent, string child) => parent.TrimEnd('\\') + "\\" + child.TrimStart('\\');

        static bool Split(string path, out RegistryHive hive, out string sub)
        {
            hive = RegistryHive.LocalMachine;
            var p = path;
            if (p.StartsWith("Registry::", StringComparison.OrdinalIgnoreCase)) p = p.Substring("Registry::".Length);
            int colon = p.IndexOf(":\\", StringComparison.Ordinal);
            string head, rest;
            if (colon > 0) { head = p.Substring(0, colon); rest = p.Substring(colon + 2); }
            else
            {
                int slash = p.IndexOf('\\');
                head = slash < 0 ? p : p.Substring(0, slash);
                rest = slash < 0 ? "" : p.Substring(slash + 1);
            }
            sub = rest;
            switch (head.ToUpperInvariant())
            {
                case "HKLM": case "HKEY_LOCAL_MACHINE": hive = RegistryHive.LocalMachine; return true;
                case "HKCU": case "HKEY_CURRENT_USER": hive = RegistryHive.CurrentUser; return true;
                case "HKU": case "HKEY_USERS": hive = RegistryHive.Users; return true;
                case "HKCR": case "HKEY_CLASSES_ROOT": hive = RegistryHive.ClassesRoot; return true;
                default: return false;
            }
        }
    }
}
