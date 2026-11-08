using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Foton.Win
{
    /// <summary>A file's Authenticode state as Get-AuthenticodeSignature reported it.</summary>
    public sealed class SignatureInfo
    {
        /// <summary>Valid, NotSigned, HashMismatch, NotTrusted, UnknownError; or Unknown / FileNotFound / SignatureCheckError.</summary>
        public string Status { get; set; } = "Unknown";
        public string Signer { get; set; } = "";
        public bool IsOSBinary { get; set; }
    }

    /// <summary>
    /// Authenticode verification through wintrust WTGetSignatureInfo, the API Get-AuthenticodeSignature used on
    /// Windows 8+: catalog-first (most OS files carry no embedded signature and are signed through a catalog), with
    /// the OS-binary check. Invalid or unknown is not malice; it is a fact to corroborate.
    /// </summary>
    public static class Authenticode
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SignatureInfoNative
        {
            public uint CbSize;
            public uint SignatureState;
            public uint SignatureType;
            public uint SignatureInfoAvailability;
            public uint InfoAvailability;
            public IntPtr DisplayName;
            public uint CchDisplayName;
            public IntPtr PublisherName;
            public uint CchPublisherName;
            public IntPtr MoreInfoUrl;
            public uint CchMoreInfoUrl;
            public IntPtr Hash;
            public uint CbHash;
            public int OSBinary;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WTGetSignatureInfo(string file, IntPtr fileHandle, uint flags, ref SignatureInfoNative info, out IntPtr certContext, IntPtr stateData);

        [DllImport("crypt32.dll")]
        static extern bool CertFreeCertificateContext(IntPtr certContext);

        // SIF_AUTHENTICODE_SIGNED | SIF_CATALOG_SIGNED | SIF_CHECK_OS_BINARY | SIF_BASE_VERIFICATION | SIF_CATALOG_FIRST
        const uint CatalogFirst = 0x001 | 0x002 | 0x800 | 0x1000 | 0x2000;
        // SIF_AUTHENTICODE_SIGNED | SIF_CHECK_OS_BINARY | SIF_BASE_VERIFICATION: the embedded signature only.
        const uint EmbeddedOnly = 0x001 | 0x800 | 0x1000;

        /// <summary>
        /// The catalog first; when that is not Valid, the embedded signature (a file signed only by an embedded signature
        /// has no catalog entry). The embedded result replaces a catalog NotSigned or UnknownError, or wins when it is
        /// Valid; a definitive catalog HashMismatch or NotTrusted is never overwritten by an embedded NotSigned.
        /// </summary>
        public static SignatureInfo Check(string? path)
        {
            var result = new SignatureInfo();
            if (string.IsNullOrWhiteSpace(path)) return result;
            try
            {
                if (!File.Exists(path)) { result.Status = "FileNotFound"; return result; }
                result = Query(path!, CatalogFirst);
                if (result.Status != "Valid")
                {
                    var embedded = Query(path!, EmbeddedOnly);
                    if (embedded.Status == "Valid" || result.Status == "NotSigned" || result.Status == "UnknownError") result = embedded;
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is CryptographicException || ex is ArgumentException
                || ex is NotSupportedException || ex is EntryPointNotFoundException || ex is DllNotFoundException)
            {
                result = new SignatureInfo { Status = "SignatureCheckError" };
            }
            return result;
        }

        static SignatureInfo Query(string path, uint flags)
        {
            var result = new SignatureInfo();
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var info = new SignatureInfoNative { CbSize = (uint)Marshal.SizeOf(typeof(SignatureInfoNative)) };
                int hr = WTGetSignatureInfo(path, fs.SafeFileHandle.DangerousGetHandle(), flags, ref info, out var cert, IntPtr.Zero);
                try
                {
                    if (hr < 0) { result.Status = "UnknownError"; return result; }
                    result.Status = StatusOf(info.SignatureState);
                    result.IsOSBinary = info.OSBinary != 0;
                    if (cert != IntPtr.Zero)
                        using (var c = new X509Certificate2(cert)) result.Signer = c.Subject;
                }
                finally { if (cert != IntPtr.Zero) CertFreeCertificateContext(cert); }
            }
            return result;
        }

        /// <summary>
        /// A driver or service image path as WMI reports it, made openable: the NT prefix \??\ is dropped and
        /// \SystemRoot\ becomes the Windows folder. The reported path is still what gets recorded.
        /// </summary>
        public static string Openable(string path)
        {
            path = path.Trim().Trim('"');
            if (path.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + path.Substring(@"\??\UNC\".Length);
            if (path.StartsWith(@"\??\", StringComparison.Ordinal)) return path.Substring(4);
            if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), path.Substring(@"\SystemRoot\".Length));
            return path;
        }

        /// <summary>SIGNATURE_STATE to SignatureStatus, through the Win32 error PowerShell derived from each state.</summary>
        internal static string StatusOf(uint state)
        {
            switch (state)
            {
                case 0: return "NotSigned";              // UNSIGNED_MISSING -> TRUST_E_NOSIGNATURE
                case 1: return "UnknownError";           // UNSIGNED_UNSUPPORTED (no SIP for the file type; Get-AuthenticodeSignature: UnknownError)
                case 2: return "NotSigned";              // UNSIGNED_POLICY -> TRUST_E_NOSIGNATURE
                case 3: return "HashMismatch";           // INVALID_CORRUPT -> TRUST_E_BAD_DIGEST
                case 4: return "HashMismatch";           // INVALID_POLICY -> CRYPT_E_BAD_MSG
                case 5: return "Valid";                  // VALID
                case 6: return "Valid";                  // TRUSTED
                case 7: return "NotTrusted";             // UNTRUSTED -> TRUST_E_EXPLICIT_DISTRUST
                default: return "UnknownError";
            }
        }

        /// <summary>For struct-size tests: SIGNATURE_INFO.</summary>
        internal static int StructSize() => Marshal.SizeOf(typeof(SignatureInfoNative));
    }
}
