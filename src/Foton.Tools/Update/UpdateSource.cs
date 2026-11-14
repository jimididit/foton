using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using Foton.Core;

namespace Foton.Tools.Update
{
    /// <summary>Where the updater reads from. Tests give it a fake; the product uses <see cref="HttpUpdateSource"/>.</summary>
    public interface IUpdateSource
    {
        /// <summary>Copies the body at url into output; throws IOException when it fails or exceeds maxBytes.</summary>
        void Fetch(string url, Stream output, long maxBytes);
    }

    public static class UpdateSourceExtensions
    {
        public static byte[] Get(this IUpdateSource source, string url, long maxBytes)
        {
            using (var ms = new MemoryStream())
            {
                source.Fetch(url, ms, maxBytes);
                return ms.ToArray();
            }
        }
    }

    /// <summary>
    /// HTTPS to GitHub only, on request. Redirects are followed here (at most five) so none can leave HTTPS or the GitHub
    /// hosts; every body is capped. Integrity does not rest on the transport: the signature and the signed hashes do.
    /// </summary>
    public sealed class HttpUpdateSource : IUpdateSource
    {
        static readonly string[] Hosts = { "api.github.com", "github.com" };
        const string AssetHostSuffix = ".githubusercontent.com";

        public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(5);

        public void Fetch(string url, Stream output, long maxBytes)
        {
            // .NET Framework 4.6.2 defaults can exclude TLS 1.2, which GitHub requires.
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            try
            {
                using (var handler = new HttpClientHandler { AllowAutoRedirect = false })
                using (var client = new HttpClient(handler) { Timeout = Timeout })
                {
                    var uri = Allowed(url);
                    for (int hop = 0; ; hop++)
                    {
                        using (var request = new HttpRequestMessage(HttpMethod.Get, uri))
                        {
                            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("Foton", FotonVersion.Product));
                            if (uri.Host == "api.github.com") request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
                            using (var response = client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult())
                            {
                                int code = (int)response.StatusCode;
                                if (code >= 300 && code < 400 && response.Headers.Location != null)
                                {
                                    if (hop >= 5) throw new IOException("Too many redirects from " + url);
                                    uri = Allowed(new Uri(uri, response.Headers.Location).AbsoluteUri);
                                    continue;
                                }
                                if (!response.IsSuccessStatusCode) throw new IOException($"GitHub answered {code} {response.ReasonPhrase} for {uri.AbsoluteUri}");
                                var length = response.Content.Headers.ContentLength;
                                if (length > maxBytes) throw new IOException($"{uri.AbsoluteUri} is {length} bytes, over the {maxBytes}-byte limit.");
                                using (var body = response.Content.ReadAsStreamAsync().GetAwaiter().GetResult())
                                    CopyCapped(body, output, maxBytes, uri.AbsoluteUri);
                                return;
                            }
                        }
                    }
                }
            }
            catch (HttpRequestException ex) { throw new IOException("Could not reach GitHub: " + (ex.InnerException?.Message ?? ex.Message), ex); }
            catch (OperationCanceledException ex) { throw new IOException("GitHub did not answer within " + Timeout.TotalSeconds + " seconds.", ex); }
        }

        static Uri Allowed(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps
                || !(Hosts.Contains(uri.Host, StringComparer.OrdinalIgnoreCase) || uri.Host.EndsWith(AssetHostSuffix, StringComparison.OrdinalIgnoreCase)))
                throw new IOException("Refusing a non-GitHub or non-HTTPS address: " + url);
            return uri;
        }

        /// <summary>Copies at most maxBytes; one byte more fails, so an oversize body never lands whole.</summary>
        internal static void CopyCapped(Stream input, Stream output, long maxBytes, string what)
        {
            var buffer = new byte[81920];
            long total = 0;
            int n;
            while ((n = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                total += n;
                if (total > maxBytes) throw new IOException($"{what} is over the {maxBytes}-byte limit.");
                output.Write(buffer, 0, n);
            }
        }
    }
}
