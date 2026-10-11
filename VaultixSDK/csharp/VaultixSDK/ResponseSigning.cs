using System.Security.Cryptography;
using System.Text;

namespace Vaultix.SDK
{
    /// <summary>
    /// Response signature verification (vaultix-resp-v1), a port of the C++ SDK.
    ///
    /// Every request carries a fresh random X-Vaultix-Nonce. Vaultix answers with
    /// X-Vaultix-Signature (base64url Ed25519), X-Vaultix-Key-Id and
    /// X-Vaultix-Signed-At (unix seconds). The signature covers these 11 lines
    /// joined by '\n' (no field can contain a line break):
    ///
    ///   vaultix-resp-v1
    ///   key id
    ///   nonce (as sent)
    ///   signed_at (as received)
    ///   HTTP method (as sent)
    ///   path?query (as sent; no '?' when there is no query)
    ///   status code
    ///   SHA-256 hex of the complete response body ("zk1-stream" for zk1 deliveries)
    ///   X-Encryption-Key value or ""
    ///   X-Encryption-IV value or ""
    ///   Content-Type value or ""
    ///
    /// This must match backend/response_signing.py.
    /// </summary>
    internal static class ResponseSigning
    {
        internal const string CanonicalVersion = "vaultix-resp-v1";
        internal const string StreamBodyMarker = "zk1-stream";

        /// <summary>
        /// Keys Vaultix signs responses with (key id, raw 32-byte Ed25519 public key
        /// as hex). Same list as kTrustedResponseKeys in VaultixClient.cpp. A key
        /// rotation ships an SDK that lists the old and the new key side by side.
        /// </summary>
        internal static readonly (string KeyId, string PublicKeyHex)[] TrustedResponseKeys =
        {
            ("vx-sig-22545e6918734982", "c21b9ba40714e61eaaf8529941400264996decd9fb8480121d3e4c7533cf2d8c"),
        };

        private static bool HasLineBreak(string value) => value.IndexOf('\n') >= 0 || value.IndexOf('\r') >= 0;

        /// <summary>Canonical string, or null if a field contains a line break.</summary>
        internal static string? Canonical(string keyId, string nonce, string signedAt, string method,
                                          string pathAndQuery, string status, string bodySha256Hex,
                                          string encryptionKey, string encryptionIV, string contentType)
        {
            string[] fields = { keyId, nonce, signedAt, method, pathAndQuery, status, bodySha256Hex,
                                encryptionKey, encryptionIV, contentType };
            var canonical = new StringBuilder(CanonicalVersion);
            foreach (string field in fields)
            {
                if (HasLineBreak(field)) return null;
                canonical.Append('\n').Append(field);
            }
            return canonical.ToString();
        }

        internal static string Sha256Hex(ReadOnlySpan<byte> data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

        /// <summary>"vx-sig-" + first 16 hex characters of sha256(raw public key).</summary>
        internal static string KeyIdFor(byte[] publicKey) => "vx-sig-" + Sha256Hex(publicKey).Substring(0, 16);

        /// <summary>Strict, unpadded base64url (what the server sends). Null on failure.</summary>
        internal static byte[]? DecodeBase64Url(string input)
        {
            if (input.Length % 4 == 1) return null;
            var output = new List<byte>(input.Length * 3 / 4);
            uint buffer = 0;
            int bits = 0;
            foreach (char c in input)
            {
                int value;
                if (c >= 'A' && c <= 'Z') value = c - 'A';
                else if (c >= 'a' && c <= 'z') value = c - 'a' + 26;
                else if (c >= '0' && c <= '9') value = c - '0' + 52;
                else if (c == '-') value = 62;
                else if (c == '_') value = 63;
                else return null;
                buffer = (buffer << 6) | (uint)value;
                bits += 6;
                if (bits >= 8)
                {
                    bits -= 8;
                    output.Add((byte)((buffer >> bits) & 0xFF));
                }
            }
            return output.ToArray();
        }

        internal static bool VerifyEd25519(byte[] publicKey, string message, string signatureBase64Url)
        {
            byte[]? signature = DecodeBase64Url(signatureBase64Url);
            if (signature == null || signature.Length != 64 || publicKey.Length != 32) return false;
            return Zk1.Ed25519Verify(publicKey, Encoding.UTF8.GetBytes(message), signature);
        }

        /// <summary>Path and query of a URI as they go on the request line.</summary>
        internal static string PathAndQuery(Uri uri)
        {
            string target = uri.PathAndQuery;
            if (target.Length == 0) return "/";
            if (target[0] == '?') target = "/" + target;
            if (target.Length > 1 && target[target.Length - 1] == '?') target = target.Substring(0, target.Length - 1);
            return target;
        }

        /// <summary>24 random bytes as 48 hex characters.</summary>
        internal static string GenerateNonce() => Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();

        internal static string Printable(string value)
        {
            var output = new StringBuilder();
            foreach (char c in value.Length > 48 ? value.Substring(0, 48) : value)
            {
                output.Append(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_' ? c : '?');
            }
            return output.ToString();
        }
    }
}
