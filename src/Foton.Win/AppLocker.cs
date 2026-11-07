using System;
using System.Reflection;

namespace Foton.Win
{
    /// <summary>
    /// The effective AppLocker policy as XML. Prefers the in-box managed PolicyManager that
    /// Get-AppLockerPolicy -Effective -Xml used (its XML is re-serialized, so the hash matches 1.38.x);
    /// falls back to the raw AppIdPolicyEngineApi COM object. Null when neither is available.
    /// </summary>
    public static class AppLocker
    {
        public static string? EffectiveXml()
        {
            try
            {
                // Loaded by strong name from the Global Assembly Cache, never from bytes.
                var asm = Assembly.Load("Microsoft.Security.ApplicationId.PolicyManagement.PolicyManager, Version=10.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35");
                var pm = asm.GetType("Microsoft.Security.ApplicationId.PolicyManagement.PolicyManager", true)!;
                var policy = pm.GetMethod("GetEffectivePolicy", BindingFlags.Public | BindingFlags.Static)!.Invoke(null, null);
                if (policy != null)
                {
                    var xml = policy.GetType().GetMethod("ToXml", Type.EmptyTypes)?.Invoke(policy, null) as string;
                    if (!string.IsNullOrEmpty(xml)) return xml;
                }
            }
            catch (Exception) { }
            try
            {
                var t = Type.GetTypeFromCLSID(new Guid("f1ed7d4c-f863-4de6-a1ca-7253efdee1f3"), throwOnError: false);
                if (t == null) return null;
                var o = Activator.CreateInstance(t);
                return t.InvokeMember("GetEffectivePolicy", BindingFlags.InvokeMethod, null, o, null) as string;
            }
            catch (Exception) { return null; }
        }
    }
}
