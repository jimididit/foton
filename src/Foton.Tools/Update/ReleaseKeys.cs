using System;
using System.Collections.Generic;

namespace Foton.Tools.Update
{
    /// <summary>One public half of a release signing key: a CNG ECCPUBLICBLOB (ECDSA P-256) and its fingerprint.</summary>
    public sealed class ReleaseKey
    {
        public ReleaseKey(string role, string blobBase64, string fingerprint)
        {
            Role = role;
            Blob = Convert.FromBase64String(blobBase64);
            Fingerprint = fingerprint;
        }

        public string Role { get; }
        public byte[] Blob { get; }
        /// <summary>SHA-256 of <see cref="Blob"/>, lowercase hex: what packaging\sign-release.ps1 prints when it signs.</summary>
        public string Fingerprint { get; }
    }

    /// <summary>
    /// The public halves of the owner's offline release keys (packaging\new-release-key.ps1). The updater trusts a
    /// release only when its foton-release.json carries a signature from one of these. GitHub access alone can publish
    /// files but cannot sign them. Changing a key is a release of its own, signed with a key already pinned here, and
    /// these values live only in this file (an architecture test) so the change is always a visible diff.
    /// </summary>
    public static class ReleaseKeys
    {
        public static readonly IReadOnlyList<ReleaseKey> All = new[]
        {
            new ReleaseKey("primary",
                "RUNTMSAAAAAVn/M5W4BbpB6kdyiNbDV36K8cHhuvKGfzvk5VwNvmwqpKrLp0Df3GBdXhAhR5qoLpvwiPusy/KQhcWVPPOYpt",
                "010afa6652bf2e495118bc711f484e88c7ea87d0c6db5781a4b4b8cd6a17bf02"),
            new ReleaseKey("backup",
                "RUNTMSAAAADXTpD7oIPStcKZlWk/YHUlSfRPpcmFugwvKilrE/SS5SXN7nINf7NkLPxGQFfT7PumLS7012Et+Vsf7sH51rIR",
                "a0f42ace5da28ddca292c6f17bf307a755eae6dc70d8360f6ec9c2fbf95a7596"),
        };
    }
}
