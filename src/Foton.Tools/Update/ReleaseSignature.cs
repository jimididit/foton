using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Foton.Tools.Update
{
    /// <summary>
    /// Checks foton-release.json.sig: base64 of a 64-byte ECDSA P-256 signature (IEEE P1363, r then s) over the exact
    /// bytes of foton-release.json, SHA-256. Pure: bytes in, the matching pinned key (or null) out.
    /// </summary>
    public static class ReleaseSignature
    {
        public const int MaxSignatureFileBytes = 4 * 1024;

        /// <summary>The key whose signature this is, or null when no given key signed these exact bytes.</summary>
        public static ReleaseKey? Verify(byte[] statement, byte[] signatureFile, IEnumerable<ReleaseKey> keys)
        {
            var signature = Decode(signatureFile);
            if (signature == null) return null;
            foreach (var key in keys)
            {
                try
                {
                    using (var cng = CngKey.Import(key.Blob, CngKeyBlobFormat.EccPublicBlob))
                    using (var ecdsa = new ECDsaCng(cng))
                    {
                        if (ecdsa.KeySize == 256 && ecdsa.VerifyData(statement, signature, HashAlgorithmName.SHA256)) return key;
                    }
                }
                catch (CryptographicException) { }
            }
            return null;
        }

        /// <summary>The 64 signature bytes, or null for anything else (oversize, not base64, wrong length).</summary>
        static byte[]? Decode(byte[] signatureFile)
        {
            if (signatureFile.Length == 0 || signatureFile.Length > MaxSignatureFileBytes) return null;
            try
            {
                var bytes = Convert.FromBase64String(Encoding.ASCII.GetString(signatureFile).Trim());
                return bytes.Length == 64 ? bytes : null;
            }
            catch (FormatException) { return null; }
        }
    }
}
