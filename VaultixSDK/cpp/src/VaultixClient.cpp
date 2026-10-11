#include "VaultixClient.h"
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <memory>
#include <chrono>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <cctype>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// URL encoding function
std::string urlEncode(const std::string& str) {
    std::string encoded;
    encoded.reserve(str.size());
    
    for (char c : str) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded += c;
        } else {
            encoded += '%';
            encoded += "0123456789ABCDEF"[static_cast<unsigned char>(c) >> 4];
            encoded += "0123456789ABCDEF"[static_cast<unsigned char>(c) & 0x0F];
        }
    }
    
    return encoded;
}

// JSON string escaping function
std::string jsonEscape(const std::string& str) {
    std::string escaped;
    escaped.reserve(str.size());
    
    for (char c : str) {
        switch (c) {
            case '"':  escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    // Control character - escape as \uXXXX
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    escaped += buf;
                } else {
                    escaped += c;
                }
                break;
        }
    }
    
    return escaped;
}

// Helper function to convert hex string to bytes
std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

#ifdef _WIN32
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#pragma comment(lib, "wbemuuid.lib")
#undef DecryptFile
#else
#include <sys/utsname.h>
#include <sys/stat.h>
#ifdef __linux__
#include <netpacket/packet.h>
#endif
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace Vaultix {

    // Forward declaration for certificate pinning data
    struct PinningData {
        std::vector<std::string>* pins;
        bool* debugMode;
        std::string* lastError;
    };

    // Static variable to store current pinning data for SSL verify callback
    // Note: This is not thread-safe, but works for the single-threaded use case
    static PinningData* g_currentPinData = nullptr;

    // Simple JSON parsing class for basic operations
    class SimpleJSON {
    public:
        std::map<std::string, std::string> data;

        // Parse a JSON string starting at json[i] (must point at '"').
        // Advances i past the closing quote. Returns the unescaped value.
        static std::string parseJsonString(const std::string& json, size_t& i) {
            std::string value;
            i++; // skip opening quote
            while (i < json.size()) {
                char c = json[i];
                if (c == '\\') {
                    i++;
                    if (i >= json.size()) break;
                    switch (json[i]) {
                        case '"':  value += '"';  break;
                        case '\\': value += '\\'; break;
                        case '/':  value += '/';  break;
                        case 'b':  value += '\b'; break;
                        case 'f':  value += '\f'; break;
                        case 'n':  value += '\n'; break;
                        case 'r':  value += '\r'; break;
                        case 't':  value += '\t'; break;
                        case 'u': {
                            if (i + 4 < json.size()) {
                                int code = strtol(json.substr(i + 1, 4).c_str(), nullptr, 16);
                                // Encode as UTF-8
                                if (code < 0x80) {
                                    value += static_cast<char>(code);
                                } else if (code < 0x800) {
                                    value += static_cast<char>(0xC0 | (code >> 6));
                                    value += static_cast<char>(0x80 | (code & 0x3F));
                                } else {
                                    value += static_cast<char>(0xE0 | (code >> 12));
                                    value += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                                    value += static_cast<char>(0x80 | (code & 0x3F));
                                }
                                i += 4;
                            }
                            break;
                        }
                        default: value += json[i]; break;
                    }
                    i++;
                } else if (c == '"') {
                    i++;
                    break;
                } else {
                    value += c;
                    i++;
                }
            }
            return value;
        }

        // Parse any JSON value starting at json[i]. Advances i past it.
        // Nested objects/arrays are returned as their raw JSON text.
        static std::string parseJsonValue(const std::string& json, size_t& i) {
            while (i < json.size() && std::isspace(static_cast<unsigned char>(json[i]))) i++;
            if (i >= json.size()) return "";
            if (json[i] == '"') {
                return parseJsonString(json, i);
            }
            // Literal / number / nested structure: scan until depth-0 delimiter
            std::string value;
            int depth = 0;
            bool inStr = false;
            while (i < json.size()) {
                char c = json[i];
                if (inStr) {
                    value += c;
                    if (c == '\\' && i + 1 < json.size()) {
                        value += json[i + 1];
                        i += 2;
                        continue;
                    }
                    if (c == '"') inStr = false;
                    i++;
                } else if (c == '"') {
                    inStr = true;
                    value += c;
                    i++;
                } else if (c == '{' || c == '[') {
                    depth++;
                    value += c;
                    i++;
                } else if (c == '}' || c == ']') {
                    if (depth == 0) break; // end of parent object
                    depth--;
                    value += c;
                    i++;
                } else if ((c == ',' || c == '}') && depth == 0) {
                    break;
                } else {
                    value += c;
                    i++;
                }
            }
            // Trim trailing whitespace
            while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
            return value;
        }

        bool parse(const std::string& json) {
            data.clear();
            size_t i = 0;
            // Find start of the root object
            while (i < json.size() && json[i] != '{') i++;
            if (i == json.size()) return false;
            i++; // skip '{'

            while (i < json.size()) {
                while (i < json.size() &&
                       (std::isspace(static_cast<unsigned char>(json[i])) || json[i] == ',')) i++;
                if (i >= json.size() || json[i] == '}') break;
                if (json[i] != '"') { i++; continue; }

                std::string key = parseJsonString(json, i);

                while (i < json.size() && std::isspace(static_cast<unsigned char>(json[i]))) i++;
                if (i >= json.size() || json[i] != ':') continue;
                i++; // skip ':'

                data[key] = parseJsonValue(json, i);
            }
            return true;
        }
        
        std::string get(const std::string& key, const std::string& defaultValue = "") const {
            auto it = data.find(key);
            return (it != data.end()) ? it->second : defaultValue;
        }
        
        bool getBool(const std::string& key, bool defaultValue = false) const {
            auto it = data.find(key);
            if (it != data.end()) {
                return it->second == "true" || it->second == "1";
            }
            return defaultValue;
        }
    };

    // Base64 encoding/decoding helper functions
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    // URL-safe base64 characters (used by Fernet)
    static const std::string base64_url_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    static inline bool is_base64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/') || (c == '-') || (c == '_'));
    }

    std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
        std::string ret;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        while (in_len--) {
            char_array_3[i++] = *(bytes_to_encode++);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for(i = 0; (i <4) ; i++)
                    ret += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i) {
            for(j = 0; j < i; j++)
                char_array_3[j] = '\0';

            char_array_4[0] = ( char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (j = 0; (j < i + 1); j++)
                ret += base64_chars[char_array_4[j]];

            while((i++ < 3))
                ret += '=';
        }

        return ret;
    }

    std::vector<uint8_t> base64_decode(std::string const& encoded_string) {
        size_t in_len = encoded_string.size();
        int i = 0;
        int j = 0;
        int in = 0;
        unsigned char char_array_4[4], char_array_3[3];

        std::vector<uint8_t> ret;

        while (in_len-- && ( encoded_string[in] != '=') && is_base64(encoded_string[in])) {
            char_array_4[i++] = encoded_string[in]; in++;
            if (i ==4) {
                for (i = 0; i <4; i++) {
                    // Try URL-safe base64 first (for Fernet), then standard base64
                    size_t pos = base64_url_chars.find(char_array_4[i]);
                    if (pos == std::string::npos) {
                        pos = base64_chars.find(char_array_4[i]);
                    }
                    char_array_4[i] = static_cast<unsigned char>(pos);
                }

                char_array_3[0] = ( char_array_4[0] << 2       ) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3];

                for (i = 0; (i < 3); i++)
                    ret.push_back(char_array_3[i]);
                i = 0;
            }
        }

        if (i) {
            for (j = 0; j < i; j++) {
                // Try URL-safe base64 first (for Fernet), then standard base64
                size_t pos = base64_url_chars.find(char_array_4[j]);
                if (pos == std::string::npos) {
                    pos = base64_chars.find(char_array_4[j]);
                }
                char_array_4[j] = static_cast<unsigned char>(pos);
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

            for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
        }

        return ret;
    }

    static std::string ExtractJsonStringValue(const std::string& json, const std::string& key) {
        std::string pattern = "\"" + key + "\"";
        size_t pos = json.find(pattern);
        if (pos == std::string::npos) {
            return "";
        }

        pos = json.find(':', pos);
        if (pos == std::string::npos) {
            return "";
        }
        pos++;

        while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
            pos++;
        }

        if (pos >= json.size()) {
            return "";
        }

        if (json.compare(pos, 4, "null") == 0) {
            return "";
        }

        if (json[pos] == '"') {
            pos++;
            std::string value;
            bool escape = false;
            for (; pos < json.size(); ++pos) {
                char ch = json[pos];
                if (escape) {
                    value.push_back(ch);
                    escape = false;
                } else if (ch == '\\') {
                    escape = true;
                } else if (ch == '"') {
                    break;
                } else {
                    value.push_back(ch);
                }
            }
            return value;
        }

        size_t end = pos;
        while (end < json.size() && json[end] != ',' && json[end] != '}' && json[end] != ']') {
            end++;
        }
        return json.substr(pos, end - pos);
    }

    static std::string ExtractJsonObjectValue(const std::string& json, const std::string& key) {
        std::string pattern = "\"" + key + "\"";
        size_t pos = json.find(pattern);
        if (pos == std::string::npos) {
            return "";
        }

        pos = json.find(':', pos);
        if (pos == std::string::npos) {
            return "";
        }
        pos++;

        while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
            pos++;
        }

        if (pos >= json.size() || json[pos] != '{') {
            if (json.compare(pos, 4, "null") == 0) {
                return "";
            }
            return "";
        }

        size_t start = pos;
        int braceDepth = 0;
        for (; pos < json.size(); ++pos) {
            char ch = json[pos];
            if (ch == '{') {
                braceDepth++;
            } else if (ch == '}') {
                braceDepth--;
                if (braceDepth == 0) {
                    return json.substr(start, pos - start + 1);
                }
            } else if (ch == '"') {
                bool escape = false;
                ++pos;
                while (pos < json.size()) {
                    char inner = json[pos];
                    if (!escape && inner == '\\') {
                        escape = true;
                    } else if (!escape && inner == '"') {
                        break;
                    } else {
                        escape = false;
                    }
                    ++pos;
                }
            }
        }

        return "";
    }

    // ========== RESPONSE SIGNATURE VERIFICATION (vaultix-resp-v1) ==========
    //
    // Every request carries a fresh random X-Vaultix-Nonce. Vaultix answers
    // with X-Vaultix-Signature (base64url Ed25519), X-Vaultix-Key-Id and
    // X-Vaultix-Signed-At (unix seconds). The signature covers these 11 lines
    // joined by '\n' (no field can contain a line break):
    //
    //   vaultix-resp-v1
    //   key id
    //   nonce (as sent)
    //   signed_at (as received)
    //   HTTP method (as sent)
    //   path?query (as sent; no '?' when there is no query)
    //   status code
    //   SHA-256 hex of the complete response body
    //   X-Encryption-Key value or ""
    //   X-Encryption-IV value or ""
    //   Content-Type value or ""
    //
    // This must match backend/response_signing.py. Both implementations are
    // tested against backend/tests/response_signing_golden.json.

    struct TrustedResponseKey {
        const char* keyId;         // "vx-sig-" + first 16 hex chars of sha256(public key)
        const char* publicKeyHex;  // raw 32-byte Ed25519 public key
    };

    // Keys Vaultix signs responses with. A key rotation ships an SDK that lists
    // the old and the new key side by side for a while.
    static const TrustedResponseKey kTrustedResponseKeys[] = {
        { "vx-sig-22545e6918734982", "c21b9ba40714e61eaaf8529941400264996decd9fb8480121d3e4c7533cf2d8c" },
#if defined(VAULTIX_TESTING_EXTRA_RESPONSE_KEY_ID) && defined(VAULTIX_TESTING_EXTRA_RESPONSE_KEY_HEX)
        // Vaultix SDK test builds only (set with -D). Never define these in a release build.
        { VAULTIX_TESTING_EXTRA_RESPONSE_KEY_ID, VAULTIX_TESTING_EXTRA_RESPONSE_KEY_HEX },
#endif
    };

    namespace ResponseSigning {

        static bool hasLineBreak(const std::string& value) {
            return value.find('\n') != std::string::npos || value.find('\r') != std::string::npos;
        }

        // Canonical string, or "" if a field contains a line break.
        std::string Canonical(const std::string& keyId, const std::string& nonce,
                              const std::string& signedAt, const std::string& method,
                              const std::string& pathAndQuery, const std::string& status,
                              const std::string& bodySha256Hex, const std::string& encryptionKey,
                              const std::string& encryptionIV, const std::string& contentType) {
            const std::string* fields[] = { &keyId, &nonce, &signedAt, &method, &pathAndQuery, &status,
                                            &bodySha256Hex, &encryptionKey, &encryptionIV, &contentType };
            std::string canonical = "vaultix-resp-v1";
            for (const std::string* field : fields) {
                if (hasLineBreak(*field)) return "";
                canonical += '\n';
                canonical += *field;
            }
            return canonical;
        }

        std::string Sha256Hex(const std::string& data) {
            unsigned char digest[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
            static const char* hexDigits = "0123456789abcdef";
            std::string hex;
            hex.reserve(SHA256_DIGEST_LENGTH * 2);
            for (unsigned char byte : digest) {
                hex += hexDigits[byte >> 4];
                hex += hexDigits[byte & 0x0F];
            }
            return hex;
        }

        // Strict, unpadded base64url (what the server sends).
        bool DecodeBase64Url(const std::string& input, std::vector<unsigned char>& output) {
            output.clear();
            if (input.size() % 4 == 1) return false;
            unsigned int buffer = 0;
            int bits = 0;
            for (char c : input) {
                int value;
                if (c >= 'A' && c <= 'Z') value = c - 'A';
                else if (c >= 'a' && c <= 'z') value = c - 'a' + 26;
                else if (c >= '0' && c <= '9') value = c - '0' + 52;
                else if (c == '-') value = 62;
                else if (c == '_') value = 63;
                else return false;
                buffer = (buffer << 6) | static_cast<unsigned int>(value);
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    output.push_back(static_cast<unsigned char>((buffer >> bits) & 0xFF));
                }
            }
            return true;
        }

        static bool decodeHex32(const std::string& hex, unsigned char out[32]) {
            if (hex.size() != 64) return false;
            for (size_t i = 0; i < 32; ++i) {
                int value = 0;
                for (size_t j = 0; j < 2; ++j) {
                    char c = hex[i * 2 + j];
                    int nibble;
                    if (c >= '0' && c <= '9') nibble = c - '0';
                    else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
                    else return false;
                    value = (value << 4) | nibble;
                }
                out[i] = static_cast<unsigned char>(value);
            }
            return true;
        }

        // Raw public key (hex) for a trusted key id, or nullptr.
        const char* TrustedPublicKeyHex(const std::string& keyId) {
            for (const TrustedResponseKey& key : kTrustedResponseKeys) {
                if (keyId == key.keyId) return key.publicKeyHex;
            }
            return nullptr;
        }

        bool VerifyEd25519(const std::string& publicKeyHex, const std::string& message,
                           const std::string& signatureBase64Url) {
            unsigned char publicKey[32];
            std::vector<unsigned char> signature;
            if (!decodeHex32(publicKeyHex, publicKey) ||
                !DecodeBase64Url(signatureBase64Url, signature) || signature.size() != 64) {
                return false;
            }
            EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicKey, sizeof(publicKey));
            if (!key) return false;
            EVP_MD_CTX* context = EVP_MD_CTX_new();
            bool valid = context &&
                EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
                EVP_DigestVerify(context, signature.data(), signature.size(),
                                 reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1;
            if (context) EVP_MD_CTX_free(context);
            EVP_PKEY_free(key);
            ERR_clear_error();
            return valid;
        }

        // Path and query of a URL as curl puts them on the request line.
        std::string PathAndQueryFromUrl(const std::string& url) {
            std::string rest = url.substr(0, url.find('#'));
            size_t schemeEnd = rest.find("://");
            size_t start = schemeEnd == std::string::npos ? 0 : schemeEnd + 3;
            size_t pathStart = rest.find_first_of("/?", start);
            if (pathStart == std::string::npos) return "/";
            std::string target = rest.substr(pathStart);
            if (target[0] == '?') target.insert(0, "/");
            if (target.back() == '?') target.pop_back();  // an empty query is not sent as such
            return target;
        }

        // 24 random bytes as 48 hex characters, or "" if the CSPRNG fails.
        std::string GenerateNonce() {
            unsigned char bytes[24];
            if (RAND_bytes(bytes, sizeof(bytes)) != 1) return "";
            static const char* hexDigits = "0123456789abcdef";
            std::string nonce;
            for (unsigned char byte : bytes) {
                nonce += hexDigits[byte >> 4];
                nonce += hexDigits[byte & 0x0F];
            }
            return nonce;
        }

        static std::string printable(const std::string& value) {
            std::string out;
            for (char c : value.substr(0, 48)) {
                out += (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') ? c : '?';
            }
            return out;
        }
    }

    bool VaultixClient::verifyResponseSignature(const std::string& method,
                                                const std::string& pathAndQuery,
                                                long statusCode,
                                                const std::string& body,
                                                const std::map<std::string, std::string>& lowerCaseHeaders,
                                                const std::string& nonce,
                                                std::string& failureReason) {
        return verifyResponseSignatureFields(method, pathAndQuery, statusCode, ResponseSigning::Sha256Hex(body),
                                             lowerCaseHeaders, nonce, failureReason);
    }

    // For zk1 deliveries (X-Encryption-Key "zk1d.") the body-hash field is the
    // literal "zk1-stream": the body streams, and the signed X-Encryption-Key
    // carries the server's one-time key, so the AES-GCM tags under the derived
    // key authenticate the body.
    bool VaultixClient::verifyResponseSignatureFields(const std::string& method,
                                                      const std::string& pathAndQuery,
                                                      long statusCode,
                                                      const std::string& bodyHashField,
                                                      const std::map<std::string, std::string>& lowerCaseHeaders,
                                                      const std::string& nonce,
                                                      std::string& failureReason) {
        auto header = [&](const char* name) -> std::string {
            auto it = lowerCaseHeaders.find(name);
            return it == lowerCaseHeaders.end() ? std::string() : it->second;
        };
        const std::string signature = header("x-vaultix-signature");
        const std::string keyId = header("x-vaultix-key-id");
        const std::string signedAt = header("x-vaultix-signed-at");
        if (signature.empty() || keyId.empty() || signedAt.empty()) {
            failureReason = "the response is not signed";
            return false;
        }
        const char* publicKeyHex = ResponseSigning::TrustedPublicKeyHex(keyId);
        if (!publicKeyHex) {
            failureReason = "unknown signing key '" + ResponseSigning::printable(keyId) + "'";
            return false;
        }
        if (signedAt.size() > 12 ||
            signedAt.find_first_not_of("0123456789") != std::string::npos) {
            failureReason = "invalid signing time";
            return false;
        }
        std::string canonical = ResponseSigning::Canonical(
            keyId, nonce, signedAt, method, pathAndQuery, std::to_string(statusCode),
            bodyHashField, header("x-encryption-key"), header("x-encryption-iv"),
            header("content-type"));
        if (canonical.empty() || !ResponseSigning::VerifyEd25519(publicKeyHex, canonical, signature)) {
            failureReason = "invalid signature (the response was altered, replayed, or does not come from Vaultix)";
            return false;
        }
        long long now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        long long skew = now - std::strtoll(signedAt.c_str(), nullptr, 10);
        if (skew < 0) skew = -skew;
        if (skew > responseClockSkewSeconds) {
            failureReason = "the signature time differs from this computer's clock by " +
                std::to_string(skew) + " seconds (check the system date and time)";
            return false;
        }
        return true;
    }

    // ========== END RESPONSE SIGNATURE VERIFICATION ==========

    // ========== END-TO-END ENCRYPTION (zk1) ==========
    //
    // Format: docs/E2EE_FORMAT.md. Reference: backend/tests/zk1_reference.py
    // (client side) and backend/content_crypto.py. client/tests checks this
    // code against backend/tests/crypto_vectors/zk1.json byte for byte.

    namespace zk1 {

        static const char kB64uAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        static const uint8_t kSealVersion = 1;
        static const uint8_t kStreamVersion = 1;
        static const size_t kFileKeyPayloadBytes = 72;                   // fk || sha256 || u64be size
        static const size_t kMaxVarsPayloadBytes = 64u * 1024u * 1024u;  // decrypted variables JSON
        static const char kStoredMagic[4] = { 'V', 'X', 'Z', '1' };
        static const char kDeliveryMagic[4] = { 'V', 'X', 'D', '1' };
        static const char kNeedContentKey[] =
            "This app uses end-to-end encryption: call SetContentKey with the vxk_ key from App Settings";

        void Wipe(void* data, size_t length) {
            if (data && length) OPENSSL_cleanse(data, length);
        }

        static void wipeVector(std::vector<uint8_t>& data) {
            if (!data.empty()) OPENSSL_cleanse(data.data(), data.size());
            data.clear();
        }

        static void wipeString(std::string& data) {
            if (!data.empty()) OPENSSL_cleanse(&data[0], data.size());
            data.clear();
        }

        static uint32_t readU32be(const uint8_t* p) {
            return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
                   (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
        }

        static uint64_t readU64be(const uint8_t* p) {
            return (static_cast<uint64_t>(readU32be(p)) << 32) | readU32be(p + 4);
        }

        static void append(std::vector<uint8_t>& out, const std::string& text) {
            out.insert(out.end(), text.begin(), text.end());
        }

        static void appendU64be(std::vector<uint8_t>& out, uint64_t value) {
            for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(value >> shift));
        }

        static bool hasNul(const std::string& text) { return text.find('\0') != std::string::npos; }

        // Strict UTF-8, like Python's bytes.decode("utf-8").
        static bool validUtf8(const uint8_t* p, size_t n) {
            size_t i = 0;
            while (i < n) {
                uint8_t c = p[i];
                if (c < 0x80) { ++i; continue; }
                size_t length;
                uint32_t cp;
                uint32_t minimum;
                if ((c & 0xE0) == 0xC0) { length = 2; cp = c & 0x1F; minimum = 0x80; }
                else if ((c & 0xF0) == 0xE0) { length = 3; cp = c & 0x0F; minimum = 0x800; }
                else if ((c & 0xF8) == 0xF0) { length = 4; cp = c & 0x07; minimum = 0x10000; }
                else return false;
                if (n - i < length) return false;
                for (size_t k = 1; k < length; ++k) {
                    if ((p[i + k] & 0xC0) != 0x80) return false;
                    cp = (cp << 6) | (p[i + k] & 0x3F);
                }
                if (cp < minimum || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
                i += length;
            }
            return true;
        }

        // SHA-256 of a || b
        static bool sha256(const uint8_t* a, size_t aLength, const uint8_t* b, size_t bLength, uint8_t out[32]) {
            EVP_MD_CTX* context = EVP_MD_CTX_new();
            unsigned int length = 0;
            bool ok = context && EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
                (aLength == 0 || EVP_DigestUpdate(context, a, aLength) == 1) &&
                (bLength == 0 || EVP_DigestUpdate(context, b, bLength) == 1) &&
                EVP_DigestFinal_ex(context, out, &length) == 1 && length == 32;
            if (context) EVP_MD_CTX_free(context);
            return ok;
        }

        bool X25519Generate(uint8_t secret[32], uint8_t publicKey[32]) {
            EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
            EVP_PKEY* key = nullptr;
            size_t secretLength = 32;
            size_t publicLength = 32;
            bool ok = context && EVP_PKEY_keygen_init(context) == 1 && EVP_PKEY_keygen(context, &key) == 1 &&
                EVP_PKEY_get_raw_private_key(key, secret, &secretLength) == 1 && secretLength == 32 &&
                EVP_PKEY_get_raw_public_key(key, publicKey, &publicLength) == 1 && publicLength == 32;
            if (key) EVP_PKEY_free(key);
            if (context) EVP_PKEY_CTX_free(context);
            ERR_clear_error();
            if (!ok) {
                Wipe(secret, 32);
                Wipe(publicKey, 32);
            }
            return ok;
        }

        bool X25519Public(const uint8_t secret[32], uint8_t publicKey[32]) {
            EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, secret, 32);
            size_t length = 32;
            bool ok = key && EVP_PKEY_get_raw_public_key(key, publicKey, &length) == 1 && length == 32;
            if (key) EVP_PKEY_free(key);
            ERR_clear_error();
            return ok;
        }

        bool X25519Shared(const uint8_t secret[32], const uint8_t peerPublic[32], uint8_t shared[32]) {
            EVP_PKEY* own = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, secret, 32);
            EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peerPublic, 32);
            EVP_PKEY_CTX* context = own ? EVP_PKEY_CTX_new(own, nullptr) : nullptr;
            size_t length = 32;
            bool ok = own && peer && context && EVP_PKEY_derive_init(context) == 1 &&
                EVP_PKEY_derive_set_peer(context, peer) == 1 &&
                EVP_PKEY_derive(context, shared, &length) == 1 && length == 32;
            if (ok) {
                // A low-order public key gives an all-zero secret with every key.
                uint8_t any = 0;
                for (size_t i = 0; i < 32; ++i) any |= shared[i];
                ok = any != 0;
            }
            if (context) EVP_PKEY_CTX_free(context);
            if (peer) EVP_PKEY_free(peer);
            if (own) EVP_PKEY_free(own);
            ERR_clear_error();
            if (!ok) Wipe(shared, 32);
            return ok;
        }

        bool HkdfSha256(const uint8_t* ikm, size_t ikmLength, const uint8_t* salt, size_t saltLength,
                        const uint8_t* info, size_t infoLength, uint8_t* out, size_t outLength) {
            if (!out || outLength == 0 || outLength > 255 * 32 || saltLength > INT_MAX) return false;
            static const uint8_t empty = 0;  // HMAC() wants a non-null key pointer
            uint8_t prk[32];
            uint8_t block[32];
            unsigned int length = 0;
            bool ok = HMAC(EVP_sha256(), saltLength ? salt : &empty, static_cast<int>(saltLength),
                           ikmLength ? ikm : &empty, ikmLength, prk, &length) != nullptr && length == 32;
            std::vector<uint8_t> input;
            size_t done = 0;
            for (unsigned int counter = 1; ok && done < outLength; ++counter) {
                input.clear();
                if (counter > 1) input.insert(input.end(), block, block + 32);
                if (infoLength) input.insert(input.end(), info, info + infoLength);
                input.push_back(static_cast<uint8_t>(counter));
                ok = HMAC(EVP_sha256(), prk, 32, input.data(), input.size(), block, &length) != nullptr && length == 32;
                if (ok) {
                    size_t take = outLength - done < 32 ? outLength - done : 32;
                    memcpy(out + done, block, take);
                    done += take;
                }
            }
            Wipe(prk, sizeof(prk));
            Wipe(block, sizeof(block));
            wipeVector(input);
            if (!ok) Wipe(out, outLength);
            return ok;
        }

        bool HmacSha256(const uint8_t* key, size_t keyLength, const uint8_t* data, size_t length, uint8_t out[32]) {
            if (!out || keyLength > static_cast<size_t>(INT_MAX)) return false;
            static const uint8_t empty = 0;  // HMAC() wants non-null pointers
            unsigned int outLength = 0;
            bool ok = HMAC(EVP_sha256(), keyLength ? key : &empty, static_cast<int>(keyLength),
                           length ? data : &empty, length, out, &outLength) != nullptr && outLength == 32;
            ERR_clear_error();
            if (!ok) Wipe(out, 32);
            return ok;
        }

        bool Ed25519Verify(const uint8_t publicKey[32], const uint8_t* message, size_t messageLength,
                           const uint8_t signature[64]) {
            static const uint8_t empty = 0;
            EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, publicKey, 32);
            EVP_MD_CTX* context = key ? EVP_MD_CTX_new() : nullptr;
            bool ok = context && signature &&
                EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, key) == 1 &&
                EVP_DigestVerify(context, signature, 64, messageLength ? message : &empty, messageLength) == 1;
            if (context) EVP_MD_CTX_free(context);
            if (key) EVP_PKEY_free(key);
            ERR_clear_error();
            return ok;
        }

        // One AES-256-GCM open on a context that already has the cipher (and,
        // when key is null, the key). in = ciphertext || tag.
        static bool gcmOpen(EVP_CIPHER_CTX* context, const uint8_t* key, const uint8_t nonce[12],
                            const uint8_t* aad, size_t aadLength, const uint8_t* in, size_t inLength, uint8_t* out) {
            if (!context || inLength < kTagBytes || inLength - kTagBytes > static_cast<size_t>(INT_MAX) ||
                aadLength > static_cast<size_t>(INT_MAX)) {
                return false;
            }
            const size_t cipherLength = inLength - kTagBytes;
            uint8_t tag[16];
            memcpy(tag, in + cipherLength, sizeof(tag));
            int length = 0;
            bool ok = EVP_DecryptInit_ex(context, nullptr, nullptr, key, nonce) == 1 &&
                (aadLength == 0 || EVP_DecryptUpdate(context, nullptr, &length, aad, static_cast<int>(aadLength)) == 1);
            if (ok && cipherLength > 0) {
                ok = EVP_DecryptUpdate(context, out, &length, in, static_cast<int>(cipherLength)) == 1 &&
                     static_cast<size_t>(length) == cipherLength;
            }
            ok = ok && EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag) == 1;
            if (ok) {
                uint8_t rest[16];
                int restLength = 0;
                ok = EVP_DecryptFinal_ex(context, rest, &restLength) == 1 && restLength == 0;
            }
            ERR_clear_error();
            return ok;
        }

        bool AesGcmDecrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aadLength,
                           const uint8_t* in, size_t inLength, uint8_t* out) {
            EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
            bool ok = context && EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
                gcmOpen(context, key, nonce, aad, aadLength, in, inLength, out);
            if (context) EVP_CIPHER_CTX_free(context);
            ERR_clear_error();
            if (!ok && inLength > kTagBytes) Wipe(out, inLength - kTagBytes);
            return ok;
        }

        bool AesGcmEncrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t* aad, size_t aadLength,
                           const uint8_t* in, size_t inLength, uint8_t* out) {
            if (inLength > static_cast<size_t>(INT_MAX) || aadLength > static_cast<size_t>(INT_MAX)) return false;
            EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
            int length = 0;
            bool ok = context && EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, key, nonce) == 1 &&
                (aadLength == 0 || EVP_EncryptUpdate(context, nullptr, &length, aad, static_cast<int>(aadLength)) == 1);
            if (ok && inLength > 0) {
                ok = EVP_EncryptUpdate(context, out, &length, in, static_cast<int>(inLength)) == 1 &&
                     static_cast<size_t>(length) == inLength;
            }
            if (ok) {
                uint8_t rest[16];
                int restLength = 0;
                ok = EVP_EncryptFinal_ex(context, rest, &restLength) == 1 && restLength == 0 &&
                     EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, out + inLength) == 1;
            }
            if (context) EVP_CIPHER_CTX_free(context);
            ERR_clear_error();
            return ok;
        }

        std::string B64uEncode(const uint8_t* data, size_t length) {
            std::string out;
            out.reserve((length * 4 + 2) / 3);
            size_t i = 0;
            for (; i + 3 <= length; i += 3) {
                uint32_t v = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8) | data[i + 2];
                out += kB64uAlphabet[(v >> 18) & 63];
                out += kB64uAlphabet[(v >> 12) & 63];
                out += kB64uAlphabet[(v >> 6) & 63];
                out += kB64uAlphabet[v & 63];
            }
            if (length - i == 1) {
                uint32_t v = static_cast<uint32_t>(data[i]) << 16;
                out += kB64uAlphabet[(v >> 18) & 63];
                out += kB64uAlphabet[(v >> 12) & 63];
            } else if (length - i == 2) {
                uint32_t v = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
                out += kB64uAlphabet[(v >> 18) & 63];
                out += kB64uAlphabet[(v >> 12) & 63];
                out += kB64uAlphabet[(v >> 6) & 63];
            }
            return out;
        }

        // Like content_crypto.b64u_decode: base64url without padding, the
        // reference's length limit, no other characters.
        bool B64uDecode(const std::string& text, std::vector<uint8_t>& out, size_t maxBytes) {
            out.clear();
            if (text.empty() || text.size() > 4 * maxBytes / 3 + 4 || text.size() % 4 == 1) return false;
            out.reserve(text.size() * 3 / 4);
            uint32_t buffer = 0;
            int bits = 0;
            for (char c : text) {
                int value;
                if (c >= 'A' && c <= 'Z') value = c - 'A';
                else if (c >= 'a' && c <= 'z') value = c - 'a' + 26;
                else if (c >= '0' && c <= '9') value = c - '0' + 52;
                else if (c == '-') value = 62;
                else if (c == '_') value = 63;
                else {
                    wipeVector(out);
                    return false;
                }
                buffer = (buffer << 6) | static_cast<uint32_t>(value);
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
                }
            }
            return true;
        }

        // "vxk_" + b64u(0x02 || sk_sdk(32) || aspk(32) || SHA256("vaultix-vxk" || 0x02 || sk_sdk || aspk)[0:4])
        // (zk1_reference.sdk_key_decode). Other versions, the 52-character
        // version-1 keys included, are refused.
        bool SdkKeyDecode(const std::string& vxk, uint8_t secret[32], uint8_t signPublic[32]) {
            static const size_t kBody = 1 + 32 + 32;
            size_t start = vxk.find_first_not_of(" \t\r\n\v\f");
            size_t end = vxk.find_last_not_of(" \t\r\n\v\f");
            if (start == std::string::npos) return false;
            std::string value = vxk.substr(start, end - start + 1);
            std::vector<uint8_t> raw;
            bool ok = value.size() == kSdkKeyChars && value.compare(0, 4, "vxk_") == 0 &&
                      B64uDecode(value.substr(4), raw, kBody + 4) && raw.size() == kBody + 4 && raw[0] == 2;
            if (ok) {
                static const char label[] = "vaultix-vxk";
                uint8_t digest[32];
                ok = sha256(reinterpret_cast<const uint8_t*>(label), sizeof(label) - 1, raw.data(), kBody, digest) &&
                     CRYPTO_memcmp(digest, raw.data() + kBody, 4) == 0;
                if (ok) {
                    memcpy(secret, raw.data() + 1, 32);
                    memcpy(signPublic, raw.data() + 33, 32);
                }
                Wipe(digest, sizeof(digest));
            }
            wipeVector(raw);
            wipeString(value);
            return ok;
        }

        bool HashKey(const uint8_t sdkSecret[32], uint8_t hashKey[32]) {
            static const char salt[] = "vaultix-e2ee-v1";
            static const char info[] = "hash-key";
            return HkdfSha256(sdkSecret, 32, reinterpret_cast<const uint8_t*>(salt), sizeof(salt) - 1,
                              reinterpret_cast<const uint8_t*>(info), sizeof(info) - 1, hashKey, 32);
        }

        void WipeContentKey(ContentKey& key) { Wipe(&key, sizeof(key)); }

        bool ContentKeyFromSdkKey(const std::string& vxk, ContentKey& key) {
            bool ok = SdkKeyDecode(vxk, key.sdkSecret, key.signPublic) && HashKey(key.sdkSecret, key.hashKey);
            if (!ok) WipeContentKey(key);
            return ok;
        }

        std::string Fingerprint(const uint8_t sdkPublic[32], const uint8_t signPublic[32]) {
            static const char label[] = "vaultix-fp";
            static const char digits[] = "0123456789ABCDEF";
            uint8_t keys[64];
            uint8_t digest[32];
            memcpy(keys, sdkPublic, 32);
            memcpy(keys + 32, signPublic, 32);
            if (!sha256(reinterpret_cast<const uint8_t*>(label), sizeof(label) - 1, keys, sizeof(keys), digest)) return "";
            std::string out;
            for (size_t i = 0; i < 8; ++i) {
                if (i > 0 && i % 2 == 0) out += '-';
                out += digits[digest[i] >> 4];
                out += digits[digest[i] & 0x0F];
            }
            return out;
        }

        // kind || 0x00 || scope || 0x00 || name. The scope is the product id
        // (variables, product files and folders) or "" (general files and folders).
        std::vector<uint8_t> SealContext(const std::string& kind, const std::string& name, const std::string& productId) {
            std::vector<uint8_t> context;
            if (kind == "var" || kind == "file" || kind == "folder") {
                append(context, kind);
                context.push_back(0);
                append(context, productId);
                context.push_back(0);
                append(context, name);
            }
            return context;
        }

        bool Unseal(const uint8_t appSecret[32], const uint8_t* sealed, size_t sealedLength,
                    const std::vector<uint8_t>& context, std::vector<uint8_t>& payload) {
            wipeVector(payload);
            if (!sealed || sealedLength < 1 + 32 + kTagBytes || sealed[0] != kSealVersion || context.empty()) return false;
            const uint8_t* ephPublic = sealed + 1;
            uint8_t appPublic[32];
            uint8_t shared[32];
            uint8_t key[32];
            bool ok = X25519Public(appSecret, appPublic) && X25519Shared(appSecret, ephPublic, shared);
            if (ok) {
                uint8_t salt[64];
                memcpy(salt, ephPublic, 32);
                memcpy(salt + 32, appPublic, 32);
                std::vector<uint8_t> info;
                append(info, "vaultix-zk1-seal");
                info.push_back(0);
                info.insert(info.end(), context.begin(), context.end());
                ok = HkdfSha256(shared, 32, salt, sizeof(salt), info.data(), info.size(), key, 32);
            }
            if (ok) {
                static const uint8_t zeroNonce[12] = { 0 };
                payload.resize(sealedLength - 1 - 32 - kTagBytes);
                uint8_t none = 0;
                ok = AesGcmDecrypt(key, zeroNonce, context.data(), context.size(), sealed + 33, sealedLength - 33,
                                   payload.empty() ? &none : payload.data());
                if (!ok) wipeVector(payload);
            }
            Wipe(shared, sizeof(shared));
            Wipe(key, sizeof(key));
            return ok;
        }

        // ----- signed content (content_crypto.member_message / upload_message /
        // variable_message / SignatureBlock) -----

        std::vector<uint8_t> MemberMessage(const std::string& appId, const std::string& userId,
                                           const uint8_t encPublic[32], const uint8_t signPublic[32],
                                           uint64_t issuedAtMs) {
            std::vector<uint8_t> m;
            if (hasNul(appId) || hasNul(userId)) return m;
            append(m, "vaultix-member-v1");
            m.push_back(0);
            append(m, appId);
            m.push_back(0);
            append(m, userId);
            m.push_back(0);
            m.insert(m.end(), encPublic, encPublic + 32);
            m.insert(m.end(), signPublic, signPublic + 32);
            appendU64be(m, issuedAtMs);
            return m;
        }

        std::vector<uint8_t> UploadMessage(const std::string& appId, const std::string& kind,
                                           const std::string& scope, const std::string& name,
                                           const uint8_t keyedHash[32], uint64_t size, uint64_t signedAtMs) {
            std::vector<uint8_t> m;
            if ((kind != "file" && kind != "folder") || hasNul(appId) || hasNul(scope) || hasNul(name)) return m;
            append(m, "vaultix-upload-v1");
            m.push_back(0);
            append(m, appId);
            m.push_back(0);
            append(m, kind);
            m.push_back(0);
            append(m, scope);
            m.push_back(0);
            append(m, name);
            m.push_back(0);
            m.insert(m.end(), keyedHash, keyedHash + 32);
            appendU64be(m, size);
            appendU64be(m, signedAtMs);
            return m;
        }

        std::vector<uint8_t> VariableMessage(const std::string& appId, const std::string& productId,
                                             const std::string& name, const uint8_t keyedHash[32],
                                             uint64_t signedAtMs) {
            std::vector<uint8_t> m;
            if (hasNul(appId) || hasNul(productId) || hasNul(name)) return m;
            append(m, "vaultix-var-v1");
            m.push_back(0);
            append(m, appId);
            m.push_back(0);
            append(m, productId);
            m.push_back(0);
            append(m, name);
            m.push_back(0);
            m.insert(m.end(), keyedHash, keyedHash + 32);
            appendU64be(m, signedAtMs);
            return m;
        }

        bool ParseSignatureBlock(const uint8_t* data, size_t length, SignatureBlock& block) {
            block = SignatureBlock();
            if (!data || length < 3 || data[0] != 1) return false;
            const size_t idLength = (static_cast<size_t>(data[1]) << 8) | data[2];
            if (idLength < 1 || idLength > kMaxUserIdBytes || length != 3 + idLength + 32 + 32 + 8 + 64 + 8 + 64) return false;
            const uint8_t* p = data + 3;
            if (!validUtf8(p, idLength)) return false;
            block.userId.assign(reinterpret_cast<const char*>(p), idLength);
            p += idLength;
            memcpy(block.encPublic, p, 32);
            p += 32;
            memcpy(block.signPublic, p, 32);
            p += 32;
            block.issuedAtMs = readU64be(p);
            p += 8;
            memcpy(block.certSignature, p, 64);
            p += 64;
            block.signedAtMs = readU64be(p);
            p += 8;
            memcpy(block.signature, p, 64);
            return true;
        }

        // zk1_reference.verify_signature_block
        bool VerifySignatureBlock(const uint8_t* data, size_t length, const std::string& appId,
                                  const uint8_t appSignPublic[32], const MessageFor& messageFor,
                                  SignatureBlock& block, std::string& error) {
            error.clear();
            if (!ParseSignatureBlock(data, length, block)) {
                error = "invalid signature block";
                return false;
            }
            std::vector<uint8_t> member = MemberMessage(appId, block.userId, block.encPublic, block.signPublic,
                                                        block.issuedAtMs);
            if (member.empty() || !Ed25519Verify(appSignPublic, member.data(), member.size(), block.certSignature)) {
                error = "the signer is not approved by the app owner";
                block = SignatureBlock();
                return false;
            }
            std::vector<uint8_t> message = messageFor ? messageFor(block.signedAtMs) : std::vector<uint8_t>();
            if (message.empty() || !Ed25519Verify(block.signPublic, message.data(), message.size(), block.signature)) {
                error = "invalid signature";
                block = SignatureBlock();
                return false;
            }
            return true;
        }

        bool ParseDeliveryHeader(const std::string& value, uint8_t serverPublic[32],
                                 std::string& kind, std::string& objectId) {
            static const std::string prefix = "zk1d.";
            if (value.compare(0, prefix.size(), prefix) != 0) return false;
            const std::string rest = value.substr(prefix.size());
            size_t first = rest.find('.');
            size_t second = first == std::string::npos ? std::string::npos : rest.find('.', first + 1);
            if (second == std::string::npos || rest.find('.', second + 1) != std::string::npos) return false;
            std::string publicPart = rest.substr(0, first);
            std::string kindPart = rest.substr(first + 1, second - first - 1);
            std::string objectPart = rest.substr(second + 1);
            if ((kindPart != "file" && kindPart != "folder" && kindPart != "vars") || objectPart.empty()) return false;
            std::vector<uint8_t> raw;
            if (!B64uDecode(publicPart, raw, 32) || raw.size() != 32) return false;
            memcpy(serverPublic, raw.data(), 32);
            kind = kindPart;
            objectId = objectPart;
            return true;
        }

        bool DeliveryKey(const uint8_t clientSecret[32], const uint8_t serverPublic[32],
                         const std::string& kind, const std::string& objectId, uint8_t key[32]) {
            uint8_t clientPublic[32];
            uint8_t shared[32];
            bool ok = X25519Public(clientSecret, clientPublic) && X25519Shared(clientSecret, serverPublic, shared);
            if (ok) {
                uint8_t salt[64];
                memcpy(salt, clientPublic, 32);
                memcpy(salt + 32, serverPublic, 32);
                std::vector<uint8_t> info;
                append(info, "vaultix-zk1-deliver");
                info.push_back(0);
                append(info, kind);
                info.push_back(0);
                append(info, objectId);
                ok = HkdfSha256(shared, 32, salt, sizeof(salt), info.data(), info.size(), key, 32);
            }
            Wipe(shared, sizeof(shared));
            if (!ok) Wipe(key, 32);
            return ok;
        }

        // ----- StreamDecryptor -----

        struct StreamDecryptor::Impl {
            EVP_CIPHER_CTX* context = nullptr;
            char magic[4] = { 0, 0, 0, 0 };
            Sink sink;
            uint8_t header[kHeaderBytes] = { 0 };
            size_t headerLength = 0;
            bool headerChecked = false;
            std::vector<uint8_t> pending;   // ciphertext after the header, not yet opened
            std::vector<uint8_t> plain;     // plaintext of one chunk
            uint64_t index = 0;
            uint64_t plaintextBytes = 0;
            bool failed = false;
            bool finished = false;
            std::string error;

            bool fail(const std::string& message) {
                if (!failed) error = message;
                failed = true;
                return false;
            }

            bool openChunk(const uint8_t* data, size_t length, bool last) {
                if (length < kTagBytes) return fail(index == 0 ? "stream too short" : "truncated stream");
                if (index > 0xFFFFFFFFull) return fail("too many chunks");
                uint8_t nonce[12] = { 0 };
                nonce[7] = static_cast<uint8_t>(index >> 24);
                nonce[8] = static_cast<uint8_t>(index >> 16);
                nonce[9] = static_cast<uint8_t>(index >> 8);
                nonce[10] = static_cast<uint8_t>(index);
                nonce[11] = last ? 1 : 0;
                const size_t plainLength = length - kTagBytes;
                if (!gcmOpen(context, nullptr, nonce, header, kHeaderBytes, data, length, plain.data())) {
                    Wipe(plain.data(), plainLength);
                    return fail("chunk " + std::to_string(index) + " failed authentication");
                }
                ++index;
                plaintextBytes += plainLength;
                if (plainLength > 0 && sink && !sink(plain.data(), plainLength)) {
                    return fail("the decrypted data could not be stored");
                }
                return true;
            }
        };

        StreamDecryptor::StreamDecryptor(const uint8_t key[32], const char magic[4], Sink sink) : impl(new Impl) {
            memcpy(impl->magic, magic, 4);
            impl->sink = sink;
            impl->plain.resize(kChunkSize);
            impl->context = EVP_CIPHER_CTX_new();
            if (!impl->context ||
                EVP_DecryptInit_ex(impl->context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
                EVP_DecryptInit_ex(impl->context, nullptr, nullptr, key, nullptr) != 1) {
                impl->fail("AES-256-GCM is not available");
            }
            ERR_clear_error();
        }

        StreamDecryptor::~StreamDecryptor() {
            if (impl->context) EVP_CIPHER_CTX_free(impl->context);  // also clears the key schedule
            Wipe(impl->plain.data(), impl->plain.size());
        }

        bool StreamDecryptor::Update(const uint8_t* data, size_t length) {
            Impl& s = *impl;
            if (s.failed) return false;
            if (s.finished) return s.fail("data after the end of the stream");
            while (s.headerLength < kHeaderBytes && length > 0) {
                s.header[s.headerLength++] = *data++;
                --length;
            }
            if (s.headerLength < kHeaderBytes) return true;
            if (!s.headerChecked) {
                if (memcmp(s.header, s.magic, 4) != 0 || s.header[4] != kStreamVersion) {
                    return s.fail("unsupported stream header");
                }
                if (readU32be(s.header + 5) != kChunkSize) return s.fail("unsupported chunk size");
                s.headerChecked = true;
            }
            if (length == 0) return true;
            // While more than one full chunk is buffered, the first one cannot
            // be the final chunk; the rest is decided at Finish().
            s.pending.insert(s.pending.end(), data, data + length);
            const size_t full = kChunkSize + kTagBytes;
            size_t offset = 0;
            while (s.pending.size() - offset > full) {
                if (!s.openChunk(s.pending.data() + offset, full, false)) return false;
                offset += full;
            }
            if (offset > 0) s.pending.erase(s.pending.begin(), s.pending.begin() + static_cast<std::ptrdiff_t>(offset));
            return true;
        }

        bool StreamDecryptor::Finish() {
            Impl& s = *impl;
            if (s.failed) return false;
            if (s.finished) return true;
            if (s.headerLength < kHeaderBytes || (s.index == 0 && s.pending.size() < kTagBytes)) {
                return s.fail("stream too short");
            }
            if (!s.openChunk(s.pending.data(), s.pending.size(), true)) return false;
            s.pending.clear();
            s.finished = true;
            return true;
        }

        const std::string& StreamDecryptor::Error() const { return impl->error; }
        uint64_t StreamDecryptor::PlaintextBytes() const { return impl->plaintextBytes; }

        // ----- DeliveryOpener -----

        struct DeliveryOpener::Impl {
            uint8_t clientSecret[32];
            bool haveClientSecret = false;
            std::string expectedKind;
            std::string kind;
            std::string objectId;
            ContentKey key;
            bool haveKey = false;
            std::string appId;
            std::string name;
            std::string productId;
            std::string scope;                        // the scope the sealed key opened with
            Sink contentSink;
            std::unique_ptr<StreamDecryptor> outer;   // VXD1 under the one-time key
            std::unique_ptr<StreamDecryptor> inner;   // VXZ1 under the file key, once the signature verified
            uint8_t prefix[2 + kSealedFileKeyBytes + 2];  // u16be(121) || sealed file key || u16be(len signature block)
            size_t prefixLength = 0;
            bool sealedOpened = false;
            uint8_t fileKey[32];
            uint8_t signatureBlock[kMaxSignatureBlockBytes];
            size_t signatureLength = 0;
            size_t signatureReceived = 0;
            uint64_t signedAt = 0;                    // set once the signature verified
            uint8_t contentSha256[32];
            uint64_t contentSize = 0;
            uint64_t contentWritten = 0;
            EVP_MD_CTX* hash = nullptr;
            std::string vars;
            std::string error;
            bool failed = false;
            bool begun = false;
            bool finished = false;

            bool fail(const std::string& message) {
                if (!failed) error = message;
                failed = true;
                return false;
            }

            // The sealed file key and the signature block's length are in.
            bool openSealedKey() {
                if (!haveKey) return fail("no content key");
                // A download by name gets the product's own file or, failing
                // that, the general file of that name: try the product scope,
                // then the general scope (zk1_reference.sdk_unseal_file_key).
                std::vector<uint8_t> payload;
                bool ok = Unseal(key.sdkSecret, prefix + 2, kSealedFileKeyBytes, SealContext(kind, name, productId), payload);
                scope = productId;
                if (!ok && !productId.empty()) {
                    ok = Unseal(key.sdkSecret, prefix + 2, kSealedFileKeyBytes, SealContext(kind, name, ""), payload);
                    scope.clear();
                }
                ok = ok && payload.size() == kFileKeyPayloadBytes;
                if (!ok) {
                    wipeVector(payload);
                    scope.clear();
                    return fail("cannot open the sealed file key (wrong content key, or it was sealed for another name or product)");
                }
                memcpy(fileKey, payload.data(), 32);
                memcpy(contentSha256, payload.data() + 32, 32);
                contentSize = readU64be(payload.data() + 64);
                wipeVector(payload);
                sealedOpened = true;
                const size_t sigAt = 2 + kSealedFileKeyBytes;
                signatureLength = (static_cast<size_t>(prefix[sigAt]) << 8) | prefix[sigAt + 1];
                if (signatureLength < kMinSignatureBlockBytes || signatureLength > kMaxSignatureBlockBytes) {
                    return fail("invalid signature block in delivery");
                }
                return true;
            }

            // The whole signature block is in: verify it (zk1_reference.sdk_open_file),
            // and only then start decrypting the content.
            bool verifySignature() {
                uint8_t keyedHash[32];
                if (!HmacSha256(key.hashKey, sizeof(key.hashKey), contentSha256, sizeof(contentSha256), keyedHash)) {
                    return fail("HMAC-SHA256 is not available");
                }
                SignatureBlock block;
                std::string reason;
                bool ok = VerifySignatureBlock(signatureBlock, signatureLength, appId, key.signPublic,
                    [&](uint64_t at) { return UploadMessage(appId, kind, scope, name, keyedHash, contentSize, at); },
                    block, reason);
                if (!ok) return fail("signature check failed: " + reason);
                signedAt = block.signedAtMs;
                WipeContentKey(key);   // not needed any more
                haveKey = false;
                hash = EVP_MD_CTX_new();
                if (!hash || EVP_DigestInit_ex(hash, EVP_sha256(), nullptr) != 1) return fail("SHA-256 is not available");
                Impl* self = this;
                inner.reset(new StreamDecryptor(fileKey, kStoredMagic,
                    [self](const uint8_t* data, size_t length) { return self->onContent(data, length); }));
                Wipe(fileKey, sizeof(fileKey));
                if (!inner->Error().empty()) return fail(inner->Error());
                return true;
            }

            bool onPayload(const uint8_t* data, size_t length) {
                if (failed) return false;
                if (kind == "vars") {
                    if (length > kMaxVarsPayloadBytes - vars.size()) return fail("variables payload too large");
                    vars.append(reinterpret_cast<const char*>(data), length);
                    return true;
                }
                // u16be(len sealed) || sealed || u16be(len sig) || signature block || VXZ1 stream
                while (prefixLength < sizeof(prefix) && length > 0) {
                    prefix[prefixLength++] = *data++;
                    --length;
                    if (prefixLength == 2 && ((static_cast<size_t>(prefix[0]) << 8) | prefix[1]) != kSealedFileKeyBytes) {
                        return fail("invalid sealed key in delivery");
                    }
                }
                if (prefixLength < sizeof(prefix)) return true;
                if (!sealedOpened && !openSealedKey()) return false;
                if (!inner) {
                    size_t take = signatureLength - signatureReceived;
                    if (take > length) take = length;
                    memcpy(signatureBlock + signatureReceived, data, take);
                    signatureReceived += take;
                    data += take;
                    length -= take;
                    if (signatureReceived < signatureLength) return true;
                    if (!verifySignature()) return false;
                }
                if (length == 0) return true;
                if (!inner->Update(data, length)) return fail(inner->Error());
                return true;
            }

            bool onContent(const uint8_t* data, size_t length) {
                if (failed) return false;
                if (length > contentSize - contentWritten) return fail("the file is larger than its sealed size");
                if (EVP_DigestUpdate(hash, data, length) != 1) return fail("SHA-256 failed");
                contentWritten += length;
                if (contentSink && !contentSink(data, length)) return fail("the decrypted file could not be stored");
                return true;
            }
        };

        DeliveryOpener::DeliveryOpener(const uint8_t clientSecret[32], const std::string& expectedKind) : impl(new Impl) {
            memcpy(impl->clientSecret, clientSecret, 32);
            impl->haveClientSecret = true;
            impl->expectedKind = expectedKind;
        }

        DeliveryOpener::~DeliveryOpener() {
            impl->inner.reset();
            impl->outer.reset();
            if (impl->hash) EVP_MD_CTX_free(impl->hash);
            Wipe(impl->clientSecret, sizeof(impl->clientSecret));
            WipeContentKey(impl->key);
            Wipe(impl->fileKey, sizeof(impl->fileKey));
            Wipe(impl->prefix, sizeof(impl->prefix));
            Wipe(impl->contentSha256, sizeof(impl->contentSha256));
            wipeString(impl->vars);
        }

        void DeliveryOpener::SetFileContext(const ContentKey& key, const std::string& appId, const std::string& name,
                                            const std::string& productId, Sink contentSink) {
            impl->key = key;
            impl->haveKey = true;
            impl->appId = appId;
            impl->name = name;
            impl->productId = productId;
            impl->contentSink = contentSink;
        }

        bool DeliveryOpener::Begin(const std::string& headerValue) {
            Impl& s = *impl;
            if (s.failed) return false;
            if (s.begun || !s.haveClientSecret) return s.fail("delivery already started");
            uint8_t serverPublic[32];
            std::string kind;
            std::string objectId;
            if (!ParseDeliveryHeader(headerValue, serverPublic, kind, objectId)) return s.fail("invalid delivery header");
            if (!s.expectedKind.empty() && kind != s.expectedKind) {
                return s.fail("unexpected delivery kind '" + kind + "' (asked for " + s.expectedKind + ")");
            }
            if (kind != "vars" && !s.haveKey) return s.fail("no content key");
            uint8_t key[32];
            bool ok = DeliveryKey(s.clientSecret, serverPublic, kind, objectId, key);
            Wipe(s.clientSecret, sizeof(s.clientSecret));  // one delivery per request key
            s.haveClientSecret = false;
            if (!ok) return s.fail("invalid server key in the delivery header");
            s.kind = kind;
            s.objectId = objectId;
            s.begun = true;
            Impl* self = &s;
            s.outer.reset(new StreamDecryptor(key, kDeliveryMagic,
                [self](const uint8_t* data, size_t length) { return self->onPayload(data, length); }));
            Wipe(key, sizeof(key));
            if (!s.outer->Error().empty()) return s.fail(s.outer->Error());
            return true;
        }

        bool DeliveryOpener::Update(const uint8_t* data, size_t length) {
            Impl& s = *impl;
            if (s.failed) return false;
            if (!s.begun || s.finished) return s.fail("unexpected delivery data");
            if (!s.outer->Update(data, length)) return s.fail(s.outer->Error());
            return true;
        }

        bool DeliveryOpener::Finish() {
            Impl& s = *impl;
            if (s.failed) return false;
            if (!s.begun) return s.fail("delivery not started");
            if (s.finished) return true;
            if (!s.outer->Finish()) return s.fail(s.outer->Error());
            if (s.kind != "vars") {
                if (!s.inner) return s.fail("delivery too short");
                if (!s.inner->Finish()) return s.fail(s.inner->Error());
                if (s.contentWritten != s.contentSize) return s.fail("the file does not match its sealed size");
                uint8_t digest[32];
                unsigned int length = 0;
                if (EVP_DigestFinal_ex(s.hash, digest, &length) != 1 || length != 32 ||
                    CRYPTO_memcmp(digest, s.contentSha256, 32) != 0) {
                    return s.fail("the file does not match its sealed SHA-256");
                }
            }
            s.finished = true;
            return true;
        }

        const std::string& DeliveryOpener::Error() const { return impl->error; }
        const std::string& DeliveryOpener::Kind() const { return impl->kind; }
        const std::string& DeliveryOpener::ObjectId() const { return impl->objectId; }
        const std::string& DeliveryOpener::Scope() const { return impl->scope; }
        uint64_t DeliveryOpener::ContentSize() const { return impl->sealedOpened ? impl->contentSize : 0; }
        uint64_t DeliveryOpener::SignedAt() const { return impl->inner ? impl->signedAt : 0; }
        std::string& DeliveryOpener::VarsPayload() { return impl->vars; }

        // ----- variables (strict JSON reader for the delivery payload) -----

        class JsonReader {
        public:
            explicit JsonReader(const std::string& text) : s(text), i(0) {}

            void skipSpace() {
                while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i;
            }
            bool eat(char c) {
                skipSpace();
                if (i < s.size() && s[i] == c) { ++i; return true; }
                return false;
            }
            bool atEnd() { skipSpace(); return i == s.size(); }
            bool literal(const char* word) {
                skipSpace();
                size_t n = strlen(word);
                if (s.compare(i, n, word) != 0) return false;
                i += n;
                return true;
            }

            bool string(std::string& out) {
                out.clear();
                skipSpace();
                if (i >= s.size() || s[i] != '"') return false;
                ++i;
                while (i < s.size()) {
                    unsigned char c = static_cast<unsigned char>(s[i++]);
                    if (c == '"') return true;
                    if (c < 0x20) return false;
                    if (c != '\\') { out += static_cast<char>(c); continue; }
                    if (i >= s.size()) return false;
                    char e = s[i++];
                    switch (e) {
                        case '"': case '\\': case '/': out += e; break;
                        case 'b': out += '\b'; break;
                        case 'f': out += '\f'; break;
                        case 'n': out += '\n'; break;
                        case 'r': out += '\r'; break;
                        case 't': out += '\t'; break;
                        case 'u': {
                            uint32_t cp;
                            if (!hex4(cp)) return false;
                            if (cp >= 0xD800 && cp <= 0xDBFF) {
                                uint32_t low;
                                if (i + 1 >= s.size() || s[i] != '\\' || s[i + 1] != 'u') return false;
                                i += 2;
                                if (!hex4(low) || low < 0xDC00 || low > 0xDFFF) return false;
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                                return false;
                            }
                            appendUtf8(out, cp);
                            break;
                        }
                        default: return false;
                    }
                }
                return false;
            }

            bool skipValue(int depth) {
                if (depth > 32) return false;
                skipSpace();
                if (i >= s.size()) return false;
                char c = s[i];
                std::string scratch;
                if (c == '"') return string(scratch);
                if (c == '{' || c == '[') {
                    const char close = c == '{' ? '}' : ']';
                    ++i;
                    if (eat(close)) return true;
                    do {
                        if (c == '{' && (!string(scratch) || !eat(':'))) return false;
                        if (!skipValue(depth + 1)) return false;
                    } while (eat(','));
                    return eat(close);
                }
                if (literal("true") || literal("false") || literal("null")) return true;
                size_t start = i;
                if (i < s.size() && s[i] == '-') ++i;
                size_t digits = i;
                while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])) || s[i] == '.' ||
                                        s[i] == 'e' || s[i] == 'E' || s[i] == '+' || s[i] == '-')) ++i;
                return i > digits && i > start && std::isdigit(static_cast<unsigned char>(s[digits]));
            }

        private:
            const std::string& s;
            size_t i;

            bool hex4(uint32_t& out) {
                if (s.size() - i < 4) return false;
                out = 0;
                for (int k = 0; k < 4; ++k) {
                    char c = s[i++];
                    int v;
                    if (c >= '0' && c <= '9') v = c - '0';
                    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
                    else return false;
                    out = (out << 4) | static_cast<uint32_t>(v);
                }
                return true;
            }

            static void appendUtf8(std::string& out, uint32_t cp) {
                if (cp < 0x80) {
                    out += static_cast<char>(cp);
                } else if (cp < 0x800) {
                    out += static_cast<char>(0xC0 | (cp >> 6));
                    out += static_cast<char>(0x80 | (cp & 0x3F));
                } else if (cp < 0x10000) {
                    out += static_cast<char>(0xE0 | (cp >> 12));
                    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                    out += static_cast<char>(0x80 | (cp & 0x3F));
                } else {
                    out += static_cast<char>(0xF0 | (cp >> 18));
                    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
                    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                    out += static_cast<char>(0x80 | (cp & 0x3F));
                }
            }
        };

        bool OpenVariables(const std::string& json, const ContentKey* key, const std::string& appId,
                           const std::string& productId,
                           std::vector<std::pair<std::string, std::string>>& out, std::string& error) {
            out.clear();
            error.clear();
            std::vector<std::pair<std::string, std::string>> result;
            JsonReader reader(json);
            bool ok = reader.eat('[');
            if (ok && !reader.eat(']')) {
                do {
                    std::string name, enc, value, sig, field;
                    bool hasName = false, hasEnc = false, hasValue = false, hasSig = false;
                    bool encNull = true, valueNull = true, sigNull = true;
                    ok = reader.eat('{');
                    if (ok && !reader.eat('}')) {
                        do {
                            ok = reader.string(field) && reader.eat(':');
                            if (!ok) break;
                            if (field == "name") {
                                ok = !hasName && reader.string(name);
                                hasName = true;
                            } else if (field == "enc") {
                                ok = !hasEnc;
                                hasEnc = true;
                                if (ok && reader.literal("null")) encNull = true;
                                else if (ok && reader.string(enc)) encNull = false;
                                else ok = false;
                            } else if (field == "value") {
                                ok = !hasValue;
                                hasValue = true;
                                if (ok && reader.literal("null")) valueNull = true;
                                else if (ok && reader.string(value)) valueNull = false;
                                else ok = false;
                            } else if (field == "sig") {
                                ok = !hasSig;
                                hasSig = true;
                                if (ok && reader.literal("null")) sigNull = true;
                                else if (ok && reader.string(sig)) sigNull = false;
                                else ok = false;
                            } else {
                                ok = reader.skipValue(0);
                            }
                        } while (ok && reader.eat(','));
                        ok = ok && reader.eat('}');
                    }
                    if (!ok) { error = "invalid variables payload"; break; }
                    if (!hasName) { ok = false; error = "a variable has no name"; break; }
                    if (encNull) {
                        result.emplace_back(name, valueNull ? std::string() : value);
                        continue;
                    }
                    if (enc != "zk1") { ok = false; error = "variable '" + name + "' uses an unknown encoding"; break; }
                    if (!key) { ok = false; error = kNeedContentKey; break; }
                    std::vector<uint8_t> sealed;
                    std::vector<uint8_t> plain;
                    ok = !valueNull && B64uDecode(value, sealed, kMaxSealedBytes) &&
                         Unseal(key->sdkSecret, sealed.data(), sealed.size(), SealContext("var", name, productId), plain) &&
                         validUtf8(plain.data(), plain.size());
                    if (!ok) {
                        wipeVector(plain);
                        error = "cannot open variable '" + name + "' (wrong content key, or it was sealed for another name or product)";
                        break;
                    }
                    // zk1_reference.sdk_open_variable: signed by an approved
                    // member, for this app, product, name and value.
                    std::vector<uint8_t> block;
                    if (sigNull || !B64uDecode(sig, block, kMaxSignatureBlockBytes)) {
                        wipeVector(plain);
                        ok = false;
                        error = "variable '" + name + "' has no valid signature block";
                        break;
                    }
                    uint8_t digest[32];
                    uint8_t keyedHash[32];
                    SignatureBlock signer;
                    std::string reason;
                    ok = sha256(plain.data(), plain.size(), nullptr, 0, digest) &&
                         HmacSha256(key->hashKey, sizeof(key->hashKey), digest, sizeof(digest), keyedHash);
                    ok = ok && VerifySignatureBlock(block.data(), block.size(), appId, key->signPublic,
                        [&](uint64_t at) { return VariableMessage(appId, productId, name, keyedHash, at); },
                        signer, reason);
                    Wipe(digest, sizeof(digest));
                    if (ok) result.emplace_back(name, std::string(plain.begin(), plain.end()));
                    wipeVector(plain);
                    if (!ok) {
                        error = "variable '" + name + "': signature check failed: " + (reason.empty() ? std::string("HMAC-SHA256 failed") : reason);
                        break;
                    }
                } while (reader.eat(','));
                ok = ok && reader.eat(']');
                if (!ok && error.empty()) error = "invalid variables payload";
            }
            if (ok && !reader.atEnd()) {
                ok = false;
                error = "invalid variables payload";
            }
            if (!ok) {
                if (error.empty()) error = "invalid variables payload";
                for (auto& entry : result) wipeString(entry.second);
                return false;
            }
            out.swap(result);
            return true;
        }

    }  // namespace zk1

    // A download that may come back as a zk1 delivery. performRequest()
    // decides at the first body byte: X-Encryption-Key "zk1d." -> check the
    // signature (mandatory, also with SetRequireSignedResponses(false)), then
    // decrypt while streaming; anything else stays on the legacy path.
    struct VaultixClient::Zk1Download {
        enum Target { Memory, File, Variables };
        enum State { Idle, Legacy, Active, Done, Failed };

        VaultixClient& client;
        Target target;
        std::string kind;         // "file", "folder" or "vars"
        std::string name;         // the name that was asked for (seal context)
        std::string productId;    // the product asked for: seal scope; vars: the delivery's object id
        std::string outputPath;
        std::string partPath;     // "<outputPath>.vxpart" while the file is unverified
        std::unique_ptr<std::ofstream> part;
        std::vector<uint8_t> memory;
        std::vector<std::pair<std::string, std::string>> variables;
        State state = Idle;
        std::string error;
        std::string storeError;
        bool rejected = false;    // the signature check failed
        uint8_t clientSecret[32];
        bool haveClientKey = false;
        std::unique_ptr<zk1::DeliveryOpener> opener;

        // Set by performRequest() for each attempt.
        CURL* curl = nullptr;
        const std::map<std::string, std::string>* lowerHeaders = nullptr;
        std::string* legacyBuffer = nullptr;
        std::string method;
        std::string url;
        std::string nonce;

        Zk1Download(VaultixClient& owner, Target what, const std::string& deliveryKind, const std::string& assetName,
                    const std::string& product, const std::string& path = "")
            : client(owner), target(what), kind(deliveryKind), name(assetName), productId(product), outputPath(path) {}

        ~Zk1Download() {
            discard();
            zk1::Wipe(clientSecret, sizeof(clientSecret));
        }

        static std::string failure(const std::string& detail) {
            return "End-to-end encrypted download failed: " + detail;
        }

        // Drop every result and the partial file.
        void discard() {
            opener.reset();
            if (!memory.empty()) zk1::Wipe(memory.data(), memory.size());
            std::vector<uint8_t>().swap(memory);
            for (auto& entry : variables) zk1::wipeString(entry.second);
            variables.clear();
            if (part) {
                part->close();
                part.reset();
            }
            if (!partPath.empty()) {
                std::remove(partPath.c_str());
                partPath.clear();
            }
        }

        void Reset() {
            discard();
            state = Idle;
            error.clear();
            storeError.clear();
            rejected = false;
            zk1::Wipe(clientSecret, sizeof(clientSecret));
            haveClientKey = false;
            curl = nullptr;
            lowerHeaders = nullptr;
            legacyBuffer = nullptr;
        }

        bool Fail(const std::string& message) {
            if (state != Failed && error.empty()) error = message;
            state = Failed;
            discard();
            return false;
        }

        // A fresh X25519 key for this request; the value of X-Vaultix-Eph.
        bool PrepareRequest(std::string& ephHeaderValue) {
            uint8_t clientPublic[32];
            haveClientKey = zk1::X25519Generate(clientSecret, clientPublic);
            if (!haveClientKey) return Fail("Could not create a one-time request key");
            ephHeaderValue = zk1::B64uEncode(clientPublic, sizeof(clientPublic));
            return true;
        }

        bool HeaderIsDelivery() const {
            if (!lowerHeaders) return false;
            auto it = lowerHeaders->find("x-encryption-key");
            return it != lowerHeaders->end() && it->second.compare(0, 5, "zk1d.") == 0;
        }

        bool IsDelivery() const { return state == Active || state == Done || state == Failed; }
        bool Succeeded() const { return state == Done; }

        // First byte of a delivery (or its end, if it has no body).
        bool Engage() {
            state = Active;
            long status = 0;
            long redirects = 0;
            char* effectiveUrl = nullptr;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
            curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirects);
            curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effectiveUrl);
            std::string reason;
            bool verified = false;
            if (redirects > 0) {
                reason = "the request was redirected";
            } else if (nonce.empty()) {
                reason = "the request had no nonce";
            } else {
                verified = client.verifyResponseSignatureFields(
                    method, ResponseSigning::PathAndQueryFromUrl(effectiveUrl ? std::string(effectiveUrl) : url),
                    status, "zk1-stream", *lowerHeaders, nonce, reason);
            }
            if (!verified) {
                rejected = true;
                return Fail("Server response could not be verified (HTTP " + std::to_string(status) + "): " + reason);
            }
            if (status != 200) return Fail(failure("unexpected HTTP status " + std::to_string(status)));
            if (kind != "vars" && !client.HasContentKey()) return Fail(zk1::kNeedContentKey);
            // The app id is part of every signed message (from the signed login response).
            if (client.currentSession.appId.empty()) return Fail(failure("no app id in the session"));
            if (!haveClientKey) return Fail(failure("no request key"));
            opener.reset(new zk1::DeliveryOpener(clientSecret, kind));
            zk1::Wipe(clientSecret, sizeof(clientSecret));
            haveClientKey = false;
            if (kind != "vars") {
                Zk1Download* self = this;
                opener->SetFileContext(client.contentKey, client.currentSession.appId, name, productId,
                    [self](const uint8_t* data, size_t length) { return self->Store(data, length); });
            }
            auto header = lowerHeaders->find("x-encryption-key");
            if (!opener->Begin(header->second)) return Fail(failure(opener->Error()));
            if (kind == "vars" && opener->ObjectId() != productId) {
                return Fail(failure("the variables delivery is for another product"));
            }
            if (target == File) {
                partPath = outputPath + ".vxpart";
                part.reset(new std::ofstream(partPath.c_str(), std::ios::binary | std::ios::trunc));
                if (!*part) return Fail("Failed to open output file: " + partPath);
            }
            return true;
        }

        // Decrypted content (not yet verified as a whole).
        bool Store(const uint8_t* data, size_t length) {
            try {
                if (target == Memory) {
                    if (memory.capacity() == 0) {
                        uint64_t size = opener ? opener->ContentSize() : 0;
                        if (size > static_cast<uint64_t>(memory.max_size())) {
                            storeError = "the file is too large for memory";
                            return false;
                        }
                        // Exact size up front: no reallocation leaves plaintext copies behind.
                        memory.reserve(static_cast<size_t>(size));
                    }
                    memory.insert(memory.end(), data, data + length);
                    return true;
                }
                if (target == File && part) {
                    part->write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(length));
                    if (*part) return true;
                    storeError = "Failed to write output file: " + partPath;
                    return false;
                }
            } catch (const std::exception&) {
                storeError = "not enough memory for the file";
            }
            return false;
        }

        static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
            Zk1Download* self = static_cast<Zk1Download*>(userp);
            const size_t length = size * nmemb;
            try {
                if (self->state == Idle) {
                    if (self->HeaderIsDelivery()) {
                        if (!self->Engage()) return 0;
                    } else {
                        self->state = Legacy;
                    }
                }
                if (self->state == Legacy) {
                    self->legacyBuffer->append(static_cast<const char*>(contents), length);
                    return length;
                }
                if (self->state != Active) return 0;
                if (length > 0 && !self->opener->Update(static_cast<const uint8_t*>(contents), length)) {
                    self->Fail(self->storeError.empty() ? failure(self->opener->Error()) : self->storeError);
                    return 0;
                }
                return length;
            } catch (...) {
                self->Fail(failure("not enough memory"));
                return 0;
            }
        }

        // End of the body: the whole delivery must authenticate.
        bool Finish() {
            if (state != Active) return state == Done;
            try {
                if (!opener->Finish()) {
                    return Fail(storeError.empty() ? failure(opener->Error()) : storeError);
                }
                if (target == File) {
                    part->flush();
                    bool written = static_cast<bool>(*part);
                    part->close();
                    written = written && !part->fail();
                    part.reset();
                    if (!written) return Fail("Failed to write output file: " + partPath);
                    if (!replaceFile(partPath, outputPath)) return Fail("Failed to save the file to " + outputPath);
                    partPath.clear();
                } else if (target == Variables) {
                    std::string reason;
                    if (!zk1::OpenVariables(opener->VarsPayload(), client.HasContentKey() ? &client.contentKey : nullptr,
                                            client.currentSession.appId, productId, variables, reason)) {
                        return Fail(reason == zk1::kNeedContentKey ? reason : failure(reason));
                    }
                }
                if (kind != "vars") client.lastSignedAt = opener->SignedAt();
                if (kind == "file") {
                    // verified and fully decrypted: IsValidFileHash never sends its plain hash
                    try { client.verifiedZk1Files.insert(std::make_pair(productId, name)); } catch (...) {}
                }
                opener.reset();
                state = Done;
                return true;
            } catch (...) {
                return Fail(failure("not enough memory"));
            }
        }

        static bool replaceFile(const std::string& from, const std::string& to) {
#ifdef _WIN32
            return MoveFileExA(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
            return std::rename(from.c_str(), to.c_str()) == 0;
#endif
        }
    };

    // Debug output never shows credentials, keys or request bodies (audit H-client-6).
    static std::string redactHeaderForDebug(const std::string& header) {
        size_t colon = header.find(':');
        if (colon == std::string::npos) return header;
        std::string name = header.substr(0, colon);
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        static const char* const visible[] = {
            "content-type", "x-product-id", "x-vaultix-nonce", "x-vaultix-eph", "x-request-timestamp",
            "x-safety-timestamp", "x-safety-nonce", "x-safety-body-sha256", "content-length",
            "content-disposition", "x-vaultix-key-id", "x-vaultix-signed-at",
        };
        for (const char* allowed : visible) {
            if (lower == allowed) return header;
        }
        return name + ": [redacted]";
    }

    // ========== END END-TO-END ENCRYPTION ==========

    // Curl callback implementations
    size_t VaultixClient::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    // Header callback for extracting response headers
    struct HeaderCallbackData {
        std::map<std::string, std::string>* headers = nullptr;       // names as received
        std::map<std::string, std::string>* lowerHeaders = nullptr;  // lower-case names
    };

    size_t HeaderCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        HeaderCallbackData* data = (HeaderCallbackData*)userp;
        if (!data) return size * nmemb;

        std::string header((char*)contents, size * nmemb);

        // A status line starts a new response (redirect, 100 Continue): keep
        // only the headers of the final response.
        if (header.compare(0, 5, "HTTP/") == 0) {
            if (data->headers) data->headers->clear();
            if (data->lowerHeaders) data->lowerHeaders->clear();
            return size * nmemb;
        }

        // Parse header line (format: "Header-Name: value\r\n")
        size_t colonPos = header.find(':');
        if (colonPos != std::string::npos) {
            std::string headerName = header.substr(0, colonPos);
            std::string headerValue = header.substr(colonPos + 1);

            // Trim whitespace
            headerName.erase(0, headerName.find_first_not_of(" \t\r\n"));
            headerName.erase(headerName.find_last_not_of(" \t\r\n") + 1);
            headerValue.erase(0, headerValue.find_first_not_of(" \t\r\n"));
            headerValue.erase(headerValue.find_last_not_of(" \t\r\n") + 1);

            if (data->headers) (*data->headers)[headerName] = headerValue;
            if (data->lowerHeaders) {
                std::transform(headerName.begin(), headerName.end(), headerName.begin(), ::tolower);
                (*data->lowerHeaders)[headerName] = headerValue;
            }
        }

        return size * nmemb;
    }

    struct StreamCallbackData {
        std::function<void(const std::vector<uint8_t>&, size_t, size_t)> callback;
        size_t totalSize;
        size_t receivedSize;
    };

    size_t VaultixClient::StreamCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        StreamCallbackData* data = (StreamCallbackData*)userp;
        size_t realsize = size * nmemb;
        
        std::vector<uint8_t> chunk((uint8_t*)contents, (uint8_t*)contents + realsize);
        data->receivedSize += realsize;
        
        data->callback(chunk, data->receivedSize, data->totalSize);
        
        return realsize;
    }

    VaultixClient::VaultixClient(const std::string& baseUrl)
        : baseUrl(baseUrl), debugMode(false), sslVerify(true),
          certificatePinningEnabled(false),
          minTlsVersion("1.2"), requestSigningEnabled(false),
          safetySessionEnabled(false), safetyRefreshInProgress(false), safetyClientVersion("unknown"),
          requireSignedResponses(true), responseClockSkewSeconds(600), lastResponseRejected(false),
          haveContentKey(false), lastSignedAt(0) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        currentSession.isValid = false;
        zk1::WipeContentKey(contentKey);
    }

    VaultixClient::~VaultixClient() {
        std::fill(safetyPrivateKey.begin(), safetyPrivateKey.end(), 0);
        safetyPrivateKey.clear();
        ClearContentKey();
        curl_global_cleanup();
    }

    bool VaultixClient::SetContentKey(const std::string& vxk) {
        zk1::ContentKey key;
        if (!zk1::ContentKeyFromSdkKey(vxk, key)) {
            zk1::WipeContentKey(key);
            lastError = "Invalid content key: use the vxk_ key from App Settings (96 characters)";
            return false;
        }
        ClearContentKey();
        contentKey = key;
        haveContentKey = true;
        zk1::WipeContentKey(key);
        return true;
    }

    void VaultixClient::ClearContentKey() {
        zk1::WipeContentKey(contentKey);
        haveContentKey = false;
        verifiedZk1Files.clear();
    }

    std::string VaultixClient::GetContentKeyFingerprint() const {
        uint8_t publicKey[32];
        if (!HasContentKey() || !zk1::X25519Public(contentKey.sdkSecret, publicKey)) return "";
        return zk1::Fingerprint(publicKey, contentKey.signPublic);
    }

    uint64_t VaultixClient::GetLastSignedAt() const { return lastSignedAt; }

    std::string VaultixClient::performRequest(const std::string& endpoint,
                                           const std::string& method,
                                           const std::string& postData,
                                           std::map<std::string, std::string> headers,
                                           std::map<std::string, std::string>* responseHeaders,
                                           Zk1Download* zk1) {
        CURL* curl;
        CURLcode res;
        std::string readBuffer;
        lastResponseRejected = false;
        if (zk1) zk1->Reset();

        curl = curl_easy_init();
        if(curl) {
            std::string url = baseUrl + endpoint;

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            if (zk1) {
                // Legacy bodies still end up in readBuffer; a zk1 delivery is
                // decrypted by the callback as it arrives.
                zk1->curl = curl;
                zk1->legacyBuffer = &readBuffer;
                zk1->url = url;
                zk1->method = (method == "POST" || method == "PUT" || method == "DELETE") ? method : "GET";
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, Zk1Download::WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, zk1);
            } else {
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            }
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
            
            // Force HTTP/2
            curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);

            // SSL configuration
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, sslVerify ? 1L : 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, sslVerify ? 2L : 0L);

            // Enforce minimum TLS version
            if (minTlsVersion == "1.3") {
                curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3);
            } else if (minTlsVersion == "1.2") {
                curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
            }

            // Enable certificate pinning if configured
            if (certificatePinningEnabled && !pinnedCertificates.empty()) {
                // Store pinning data in a struct for the callback
                struct PinningData {
                    std::vector<std::string>* pins;
                    bool* debugMode;
                    std::string* lastError;
                };
                static PinningData pinData;
                pinData.pins = &pinnedCertificates;
                pinData.debugMode = &debugMode;
                pinData.lastError = &lastError;

                curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslContextCallback);
                curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, &pinData);
            }

            // Always capture response headers so Safety can distinguish a
            // heartbeat deadline from a key/certificate rotation deadline.
            std::map<std::string, std::string> internalResponseHeaders;
            std::map<std::string, std::string>* capturedHeaders =
                responseHeaders ? responseHeaders : &internalResponseHeaders;
            capturedHeaders->clear();
            std::map<std::string, std::string> lowerCaseResponseHeaders;
            HeaderCallbackData headerCallbackData;
            headerCallbackData.headers = capturedHeaders;
            headerCallbackData.lowerHeaders = &lowerCaseResponseHeaders;
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headerCallbackData);
            if (zk1) zk1->lowerHeaders = &lowerCaseResponseHeaders;

            // Set headers
            struct curl_slist* headerList = nullptr;
            headerList = curl_slist_append(headerList, "Content-Type: application/json");

            // Fresh nonce per request: Vaultix signs the response over it, so
            // a response can only ever be valid for this one request. zk1
            // deliveries are always verified, so downloads always send one.
            std::string responseNonce;
            if (requireSignedResponses || zk1) {
                responseNonce = ResponseSigning::GenerateNonce();
                if (responseNonce.empty()) {
                    curl_slist_free_all(headerList);
                    curl_easy_cleanup(curl);
                    lastError = "Could not create a request nonce";
                    if (zk1) zk1->Fail(lastError);
                    return "";
                }
                std::string nonceHeader = "X-Vaultix-Nonce: " + responseNonce;
                headerList = curl_slist_append(headerList, nonceHeader.c_str());
            }

            // End-to-end encryption: a fresh one-time X25519 key per request.
            if (zk1) {
                zk1->nonce = responseNonce;
                std::string ephemeralKey;
                if (!zk1->PrepareRequest(ephemeralKey)) {
                    curl_slist_free_all(headerList);
                    curl_easy_cleanup(curl);
                    lastError = zk1->error;
                    return "";
                }
                std::string ephemeralHeader = "X-Vaultix-Eph: " + ephemeralKey;
                headerList = curl_slist_append(headerList, ephemeralHeader.c_str());
            }

            // Add request signing headers if enabled
            std::string timestamp;
            if (requestSigningEnabled && !requestSigningKey.empty()) {
                // Generate timestamp
                auto now = std::chrono::system_clock::now();
                auto timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
                timestamp = std::to_string(timestamp_ms);

                // Sign the request
                std::string signature = signRequest(method, endpoint, postData, timestamp);

                std::string timestampHeader = "X-Request-Timestamp: " + timestamp;
                std::string signatureHeader = "X-Request-Signature: " + signature;
                headerList = curl_slist_append(headerList, timestampHeader.c_str());
                headerList = curl_slist_append(headerList, signatureHeader.c_str());

                if (debugMode) {
                    std::cout << "[DEBUG] Request signing enabled - Timestamp: " << timestamp << std::endl;
                }
            }

            // Add Authorization header - prefer session token over API key
            // Safety proof-of-possession is separate from legacy HMAC signing.
            // A fresh Ed25519 key and Vaultix-issued certificate chain are bound
            // to the authenticated session.
            if (safetySessionEnabled && currentSession.isValid && !currentSession.sessionToken.empty()) {
                auto safetyNow = std::chrono::system_clock::now();
                auto safetyTimestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    safetyNow.time_since_epoch()).count();
                std::string safetyTimestamp = std::to_string(safetyTimestampMs);
                unsigned char nonceBytes[24];
                if (RAND_bytes(nonceBytes, sizeof(nonceBytes)) != 1) {
                    curl_slist_free_all(headerList);
                    curl_easy_cleanup(curl);
                    lastError = "Safety could not create a request nonce";
                    return "";
                }
                std::ostringstream nonceStream;
                for (unsigned char byte : nonceBytes) {
                    nonceStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                std::string safetyNonce = nonceStream.str();
                unsigned char bodyDigest[SHA256_DIGEST_LENGTH];
                SHA256(reinterpret_cast<const unsigned char*>(postData.data()), postData.size(), bodyDigest);
                std::ostringstream bodyHashStream;
                for (unsigned char byte : bodyDigest) {
                    bodyHashStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                std::string bodyHash = bodyHashStream.str();
                std::string sessionJti = ExtractJTIFromToken(currentSession.sessionToken);
                std::string canonicalProof = method + "\n" + endpoint + "\n" + bodyHash + "\n" +
                    sessionJti + "\n" + safetyTimestamp + "\n" + safetyNonce;
                std::string safetySignature = signSafetyMessage(canonicalProof);
                if (sessionJti.empty() || safetySignature.empty()) {
                    curl_slist_free_all(headerList);
                    curl_easy_cleanup(curl);
                    lastError = "Safety could not sign the request";
                    return "";
                }
                std::vector<std::string> safetyHeaders = {
                    "X-Safety-Timestamp: " + safetyTimestamp,
                    "X-Safety-Nonce: " + safetyNonce,
                    "X-Safety-Body-SHA256: " + bodyHash,
                    "X-Safety-Signature: " + safetySignature,
                    "X-Safety-Certificate: " + safetyCertificate,
                    "X-Safety-Certificate-Chain: " + safetyCertificateChain,
                };
                for (const auto& safetyHeader : safetyHeaders) {
                    headerList = curl_slist_append(headerList, safetyHeader.c_str());
                }
            }

            if (currentSession.isValid && !currentSession.sessionToken.empty()) {
                // Use session token for authenticated requests
                std::string authHeader = "Authorization: Bearer " + currentSession.sessionToken;
                headerList = curl_slist_append(headerList, authHeader.c_str());
            } else if (!apiKey.empty()) {
                // Use API key only for session creation
                std::string apiKeyHeader = "X-API-Key: " + apiKey;
                headerList = curl_slist_append(headerList, apiKeyHeader.c_str());
            }

            for (const auto& header : headers) {
                std::string headerStr = header.first + ": " + header.second;
                headerList = curl_slist_append(headerList, headerStr.c_str());
            }

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);

            // Set method and data
            if (method == "POST") {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
            } else if (method == "PUT") {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
            } else if (method == "DELETE") {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            }

            // Debug output (no credentials, keys or request bodies)
            if (debugMode) {
                std::cout << "[DEBUG] " << method << " " << url << std::endl;
                if (!postData.empty()) {
                    std::cout << "[DEBUG] Data: " << postData.size() << " bytes (not shown)" << std::endl;
                }
                // Debug headers
                struct curl_slist* debugHeader = headerList;
                while (debugHeader) {
                    std::cout << "[DEBUG] Header: " << redactHeaderForDebug(debugHeader->data) << std::endl;
                    debugHeader = debugHeader->next;
                }
            }

            res = curl_easy_perform(curl);

            // zk1 delivery: the signature was checked and the body decrypted
            // while it streamed, so the buffered-body handling below does not
            // apply. A delivery without a body is engaged here and fails.
            if (zk1 && zk1->state == Zk1Download::Idle && zk1->HeaderIsDelivery()) {
                zk1->Engage();
            }
            if (zk1 && zk1->IsDelivery()) {
                if (zk1->state == Zk1Download::Active) {
                    if (res != CURLE_OK) {
                        zk1->Fail("Curl error: " + std::string(curl_easy_strerror(res)));
                    } else {
                        zk1->Finish();
                    }
                }
                lastResponseRejected = zk1->rejected;
                if (zk1->Succeeded()) {
                    lastError.clear();
                } else {
                    lastError = zk1->error;
                    capturedHeaders->clear();
                }
                if (debugMode) {
                    if (zk1->Succeeded()) {
                        std::cout << "[DEBUG] End-to-end encrypted " << zk1->kind << " delivery verified and decrypted" << std::endl;
                    } else {
                        std::cout << "[ERROR] " << lastError << std::endl;
                    }
                }
                zk1->curl = nullptr;
                zk1->lowerHeaders = nullptr;
                zk1->legacyBuffer = nullptr;
                curl_slist_free_all(headerList);
                curl_easy_cleanup(curl);
                return "";
            }
            if (zk1) {
                zk1->curl = nullptr;
                zk1->lowerHeaders = nullptr;
                zk1->legacyBuffer = nullptr;
            }

            if (res != CURLE_OK) {
                lastError = "Curl error: " + std::string(curl_easy_strerror(res));
                if (debugMode) {
                    std::cout << "[ERROR] " << lastError << std::endl;
                }
            }

            long response_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (debugMode) {
                std::cout << "[DEBUG] Response Code: " << response_code << std::endl;
                std::cout << "[DEBUG] Response size: " << readBuffer.size() << " bytes" << std::endl;
            }

            // Verify that the response really comes from Vaultix and answers
            // exactly this request, before anything in it is used (status codes
            // and error bodies included).
            if (requireSignedResponses) {
                bool verified = false;
                std::string reason;
                if (res == CURLE_OK) {
                    long redirects = 0;
                    curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirects);
                    char* effectiveUrl = nullptr;
                    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effectiveUrl);
                    // The method curl actually sent for this method string.
                    std::string sentMethod = (method == "POST" || method == "PUT" || method == "DELETE") ? method : "GET";
                    if (redirects > 0) {
                        reason = "the request was redirected";
                    } else {
                        verified = verifyResponseSignature(
                            sentMethod,
                            ResponseSigning::PathAndQueryFromUrl(effectiveUrl ? std::string(effectiveUrl) : url),
                            response_code, readBuffer, lowerCaseResponseHeaders, responseNonce, reason);
                    }
                    if (!verified) {
                        lastError = "Server response could not be verified (HTTP " +
                            std::to_string(response_code) + "): " + reason;
                        lastResponseRejected = true;
                    }
                }
                // On a transfer error lastError already holds the curl error.
                if (!verified) {
                    if (debugMode) {
                        std::cout << "[ERROR] " << lastError << std::endl;
                    }
                    capturedHeaders->clear();
                    readBuffer.clear();
                    curl_slist_free_all(headerList);
                    curl_easy_cleanup(curl);
                    return "";
                }
                if (debugMode) {
                    std::cout << "[DEBUG] Response signature verified" << std::endl;
                }
            }

            if (response_code == 428 && safetySessionEnabled &&
                !safetyRefreshInProgress && endpoint != "/security/refresh") {
                bool heartbeatRequired = false;
                for (const auto& header : *capturedHeaders) {
                    std::string lowerKey = header.first;
                    std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
                    if (lowerKey == "x-safety-heartbeat") {
                        heartbeatRequired = true;
                        break;
                    }
                }
                curl_slist_free_all(headerList);
                curl_easy_cleanup(curl);
                safetyRefreshInProgress = true;
                bool recovered = heartbeatRequired
                    ? performSafetyHeartbeat()
                    : refreshSafetyAttestation();
                if (!recovered) {
                    safetyRefreshInProgress = false;
                    if (lastError.empty()) {
                        lastError = heartbeatRequired
                            ? "Safety heartbeat failed"
                            : "Safety re-attestation failed";
                    }
                    return "";
                }
                // Retry exactly once with the same body and caller headers.
                std::string retryResponse = performRequest(
                    endpoint, method, postData, headers, responseHeaders, zk1);
                safetyRefreshInProgress = false;
                return retryResponse;
            }

            // Check for HTTP error status codes
            if (response_code >= 400) {
                lastError = "HTTP Error " + std::to_string(response_code) + ": " + readBuffer;
                
                // Check for X-Debug-Info header (Developer Mode)
                if (responseHeaders) {
                    auto debugInfoIt = responseHeaders->find("X-Debug-Info");
                    if (debugInfoIt == responseHeaders->end()) {
                        // Try case-insensitive search
                        for (const auto& header : *responseHeaders) {
                            std::string lowerKey = header.first;
                            std::transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
                            if (lowerKey == "x-debug-info") {
                                lastError += " [Debug: " + header.second + "]";
                                break;
                            }
                        }
                    } else {
                        lastError += " [Debug: " + debugInfoIt->second + "]";
                    }
                }
                
                if (debugMode) {
                    std::cout << "[ERROR] " << lastError << std::endl;
                }
                readBuffer.clear(); // Clear response on error
            }

            curl_slist_free_all(headerList);
            curl_easy_cleanup(curl);
        }

        return readBuffer;
    }

    std::string VaultixClient::getHWID() {
        std::string hwid;
        
#ifdef _WIN32
        // Windows implementation using WMI
        HRESULT hres;
        
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            return "HWID_ERROR_INIT";
        }
        
        hres = CoInitializeSecurity(
            NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_CONNECT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE, NULL
        );
        
        IWbemLocator *pLoc = NULL;
        hres = CoCreateInstance(
            CLSID_WbemLocator, 0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID *) &pLoc
        );
        
        if (FAILED(hres)) {
            CoUninitialize();
            return "HWID_ERROR_CREATE";
        }
        
        IWbemServices *pSvc = NULL;
        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            NULL, NULL, 0, NULL, 0, 0, &pSvc
        );
        
        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return "HWID_ERROR_CONNECT";
        }
        
        hres = CoSetProxyBlanket(
            pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE
        );
        
        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return "HWID_ERROR_PROXY";
        }
        
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT SerialNumber FROM Win32_BaseBoard"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL, &pEnumerator
        );
        
        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return "HWID_ERROR_QUERY";
        }
        
        IWbemClassObject *pclsObj = NULL;
        ULONG uReturn = 0;
        
        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;
            
            VARIANT vtProp;
            hr = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR) {
                _bstr_t bstr(vtProp.bstrVal);
                hwid = (char*)bstr;
                break;
            }
            VariantClear(&vtProp);
            pclsObj->Release();
        }
        
        pSvc->Release();
        pLoc->Release();
        pEnumerator->Release();
        CoUninitialize();
#else
        // Linux implementation using system info
        struct utsname unameData;
        if (uname(&unameData) == 0) {
            hwid = std::string(unameData.nodename) + "_" + std::string(unameData.machine);
        }
        
        // Try to get MAC address
        struct ifaddrs *ifap, *ifa;
        if (getifaddrs(&ifap) == 0) {
            for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_PACKET) {
                    struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                    if (s->sll_halen == 6) {
                        std::stringstream ss;
                        for (int i = 0; i < 6; i++) {
                            if (i > 0) ss << ":";
                            ss << std::hex << std::setfill('0') << std::setw(2) << (int)s->sll_addr[i];
                        }
                        hwid += "_" + ss.str();
                        break;
                    }
                }
            }
            freeifaddrs(ifap);
        }
#endif
        
        if (hwid.empty()) {
            hwid = "HWID_FALLBACK_" + std::to_string(std::hash<std::string>{}("fallback"));
        }
        
        return hwid;
    }


    // NEW AUTHENTICATION METHODS
    std::string VaultixClient::signSafetyMessage(const std::string& message) {
        if (safetyPrivateKey.size() != 32) return "";
        EVP_PKEY* key = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, safetyPrivateKey.data(), safetyPrivateKey.size());
        if (!key) return "";
        EVP_MD_CTX* context = EVP_MD_CTX_new();
        size_t signatureLength = 64;
        std::vector<unsigned char> signature(signatureLength);
        bool ok = context &&
            EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1 &&
            EVP_DigestSign(context, signature.data(), &signatureLength,
                           reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1;
        if (context) EVP_MD_CTX_free(context);
        EVP_PKEY_free(key);
        if (!ok) return "";
        return base64_encode(signature.data(), static_cast<unsigned int>(signatureLength));
    }

    std::string VaultixClient::hashCurrentExecutable() {
        std::string path;
#ifdef _WIN32
        std::vector<char> pathBuffer(32768);
        DWORD length = GetModuleFileNameA(nullptr, pathBuffer.data(), static_cast<DWORD>(pathBuffer.size()));
        if (length == 0 || length >= pathBuffer.size()) {
            lastError = "Safety could not resolve the running client executable";
            return "";
        }
        path.assign(pathBuffer.data(), length);
#else
        std::vector<char> pathBuffer(4096);
        ssize_t length = readlink("/proc/self/exe", pathBuffer.data(), pathBuffer.size() - 1);
        if (length <= 0) {
            lastError = "Safety could not resolve /proc/self/exe";
            return "";
        }
        path.assign(pathBuffer.data(), static_cast<size_t>(length));
#endif
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            lastError = "Safety could not open the running client executable";
            return "";
        }
        SHA256_CTX context;
        SHA256_Init(&context);
        char buffer[64 * 1024];
        while (file.good()) {
            file.read(buffer, sizeof(buffer));
            if (file.gcount() > 0) SHA256_Update(&context, buffer, static_cast<size_t>(file.gcount()));
        }
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256_Final(digest, &context);
        std::ostringstream result;
        for (unsigned char byte : digest) {
            result << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return result.str();
    }

    bool VaultixClient::validateSafetyCertificateChain(
        const std::string& leafCertificate, const std::string& rootCertificate) {
        std::vector<uint8_t> leafBytes = base64_decode(leafCertificate);
        std::vector<uint8_t> rootBytes = base64_decode(rootCertificate);
        if (leafBytes.empty() || rootBytes.empty() || safetyPublicKey.size() != 32) return false;
        const unsigned char* leafPointer = leafBytes.data();
        const unsigned char* rootPointer = rootBytes.data();
        X509* leaf = d2i_X509(nullptr, &leafPointer, static_cast<long>(leafBytes.size()));
        X509* root = d2i_X509(nullptr, &rootPointer, static_cast<long>(rootBytes.size()));
        if (!leaf || !root) {
            if (leaf) X509_free(leaf);
            if (root) X509_free(root);
            return false;
        }
        EVP_PKEY* rootKey = X509_get_pubkey(root);
        EVP_PKEY* leafKey = X509_get_pubkey(leaf);
        bool valid = rootKey && leafKey &&
            X509_verify(root, rootKey) == 1 && X509_verify(leaf, rootKey) == 1 &&
            X509_cmp_current_time(X509_get0_notBefore(leaf)) <= 0 &&
            X509_cmp_current_time(X509_get0_notAfter(leaf)) >= 0;
        unsigned char rawPublicKey[32];
        size_t rawLength = sizeof(rawPublicKey);
        valid = valid && EVP_PKEY_get_raw_public_key(leafKey, rawPublicKey, &rawLength) == 1 &&
            rawLength == safetyPublicKey.size() &&
            CRYPTO_memcmp(rawPublicKey, safetyPublicKey.data(), rawLength) == 0;
        if (rootKey) EVP_PKEY_free(rootKey);
        if (leafKey) EVP_PKEY_free(leafKey);
        X509_free(leaf);
        X509_free(root);
        return valid;
    }

    bool VaultixClient::prepareSafetyAttestation(std::string& attestationToken) {
        attestationToken.clear();
        safetySessionEnabled = false;
        std::fill(safetyPrivateKey.begin(), safetyPrivateKey.end(), 0);
        safetyPrivateKey.clear();
        safetyPublicKey.clear();
        safetyPublicKeyDer.clear();
        safetyCertificate.clear();
        safetyCertificateChain.clear();

        EVP_PKEY_CTX* keyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        EVP_PKEY* key = nullptr;
        if (!keyContext || EVP_PKEY_keygen_init(keyContext) != 1 || EVP_PKEY_keygen(keyContext, &key) != 1) {
            if (keyContext) EVP_PKEY_CTX_free(keyContext);
            lastError = "Safety could not generate an ephemeral Ed25519 key";
            return false;
        }
        EVP_PKEY_CTX_free(keyContext);
        safetyPrivateKey.resize(32);
        safetyPublicKey.resize(32);
        size_t privateLength = safetyPrivateKey.size();
        size_t publicLength = safetyPublicKey.size();
        if (EVP_PKEY_get_raw_private_key(key, safetyPrivateKey.data(), &privateLength) != 1 ||
            EVP_PKEY_get_raw_public_key(key, safetyPublicKey.data(), &publicLength) != 1) {
            EVP_PKEY_free(key);
            lastError = "Safety could not export the ephemeral key";
            return false;
        }
        unsigned char* der = nullptr;
        int derLength = i2d_PUBKEY(key, &der);
        EVP_PKEY_free(key);
        if (derLength <= 0 || !der) {
            lastError = "Safety could not encode the ephemeral public key";
            return false;
        }
        safetyPublicKeyDer = base64_encode(der, static_cast<unsigned int>(derLength));
        OPENSSL_free(der);

        std::string challengeBody = "{\"ephemeralPublicKey\":\"" + jsonEscape(safetyPublicKeyDer) +
            "\",\"clientVersion\":\"" + jsonEscape(safetyClientVersion) + "\"}";
        std::map<std::string, std::string> safetyAuthHeaders;
        std::string activeApiKey = currentSession.appApiKey.empty() ? apiKey : currentSession.appApiKey;
        if (currentSession.isValid && !activeApiKey.empty()) safetyAuthHeaders["X-API-Key"] = activeApiKey;
        std::string challengeResponse = performRequest(
            "/security/challenge", "POST", challengeBody, safetyAuthHeaders);
        if (challengeResponse.empty()) return false;
        SimpleJSON challengeJson;
        if (!challengeJson.parse(challengeResponse)) {
            lastError = "Safety challenge response is invalid";
            return false;
        }
        if (!challengeJson.getBool("enabled", false)) {
            std::fill(safetyPrivateKey.begin(), safetyPrivateKey.end(), 0);
            safetyPrivateKey.clear();
            safetyPublicKey.clear();
            safetyPublicKeyDer.clear();
            return true;
        }
        std::string challengeId = challengeJson.get("challengeId", "");
        std::string nonce = challengeJson.get("nonce", "");
        std::string appId = challengeJson.get("appId", "");
        std::string challengeRoot = challengeJson.get("rootCertificate", "");
        if (challengeId.empty() || nonce.empty() || appId.empty() || challengeRoot.empty()) {
            lastError = "Safety challenge is missing required bindings";
            return false;
        }
        std::string executableHash = hashCurrentExecutable();
        if (executableHash.empty()) return false;
        std::string canonical = "vaultix-safety-v1\n" + challengeId + "\n" + nonce + "\n" +
            appId + "\n" + executableHash + "\n" + safetyClientVersion + "\n" + safetyPublicKeyDer;
        std::string signature = signSafetyMessage(canonical);
        if (signature.empty()) {
            lastError = "Safety could not sign the attestation";
            return false;
        }
        std::string attestBody = "{\"challengeId\":\"" + jsonEscape(challengeId) +
            "\",\"clientHash\":\"" + executableHash +
            "\",\"clientVersion\":\"" + jsonEscape(safetyClientVersion) +
            "\",\"ephemeralPublicKey\":\"" + jsonEscape(safetyPublicKeyDer) +
            "\",\"signature\":\"" + jsonEscape(signature) + "\"}";
        std::string attestResponse = performRequest(
            "/security/attest", "POST", attestBody, safetyAuthHeaders);
        if (attestResponse.empty()) return false;
        SimpleJSON attestJson;
        if (!attestJson.parse(attestResponse)) {
            lastError = "Safety attestation response is invalid";
            return false;
        }
        attestationToken = attestJson.get("attestationToken", "");
        safetyCertificate = attestJson.get("leafCertificate", "");
        safetyCertificateChain = attestJson.get("rootCertificate", "");
        if (attestationToken.empty() || safetyCertificateChain != challengeRoot ||
            !validateSafetyCertificateChain(safetyCertificate, safetyCertificateChain)) {
            lastError = "Safety certificate chain validation failed";
            return false;
        }
        return true;
    }


    bool VaultixClient::refreshSafetyAttestation() {
        if (!currentSession.isValid || !safetySessionEnabled) return false;

        const bool oldEnabled = safetySessionEnabled;
        std::vector<uint8_t> oldPrivate = safetyPrivateKey;
        std::vector<uint8_t> oldPublic = safetyPublicKey;
        std::string oldPublicDer = safetyPublicKeyDer;
        std::string oldCertificate = safetyCertificate;
        std::string oldChain = safetyCertificateChain;

        std::string replacementToken;
        if (!prepareSafetyAttestation(replacementToken) || replacementToken.empty()) {
            safetySessionEnabled = oldEnabled;
            safetyPrivateKey = oldPrivate;
            safetyPublicKey = oldPublic;
            safetyPublicKeyDer = oldPublicDer;
            safetyCertificate = oldCertificate;
            safetyCertificateChain = oldChain;
            return false;
        }

        std::vector<uint8_t> newPrivate = safetyPrivateKey;
        std::vector<uint8_t> newPublic = safetyPublicKey;
        std::string newPublicDer = safetyPublicKeyDer;
        std::string newCertificate = safetyCertificate;
        std::string newChain = safetyCertificateChain;

        // The refresh request must still be signed by the old certified key.
        safetySessionEnabled = oldEnabled;
        safetyPrivateKey = oldPrivate;
        safetyPublicKey = oldPublic;
        safetyPublicKeyDer = oldPublicDer;
        safetyCertificate = oldCertificate;
        safetyCertificateChain = oldChain;

        std::string body = "{\"safetyAttestationToken\":\"" +
            jsonEscape(replacementToken) + "\"}";
        std::string response = performRequest("/security/refresh", "POST", body);
        if (response.empty()) return false;
        SimpleJSON responseJson;
        if (!responseJson.parse(response) || !responseJson.getBool("safetyEnabled", false)) {
            lastError = "Safety key rotation response is invalid";
            return false;
        }

        safetyPrivateKey = newPrivate;
        safetyPublicKey = newPublic;
        safetyPublicKeyDer = newPublicDer;
        safetyCertificate = responseJson.get("safetyCertificate", "");
        safetyCertificateChain = responseJson.get("safetyCertificateChain", "");
        if (safetyCertificate != newCertificate || safetyCertificateChain != newChain ||
            !validateSafetyCertificateChain(safetyCertificate, safetyCertificateChain)) {
            safetySessionEnabled = false;
            lastError = "Safety key rotation certificate validation failed";
            return false;
        }
        safetySessionEnabled = true;
        std::fill(oldPrivate.begin(), oldPrivate.end(), 0);
        return true;
    }
    bool VaultixClient::performSafetyHeartbeat() {
        if (!currentSession.isValid || !safetySessionEnabled ||
            safetyPrivateKey.empty() || safetyPublicKeyDer.empty()) {
            lastError = "Safety heartbeat requires an active certified session";
            return false;
        }

        std::string challengeResponse = performRequest(
            "/security/heartbeat/challenge", "POST", "{}");
        if (challengeResponse.empty()) return false;
        SimpleJSON challengeJson;
        if (!challengeJson.parse(challengeResponse) ||
            challengeJson.get("protocol", "") != "vaultix-safety-heartbeat-v1") {
            lastError = "Safety heartbeat challenge is invalid";
            return false;
        }

        std::string challengeId = challengeJson.get("challengeId", "");
        std::string nonce = challengeJson.get("nonce", "");
        std::string appId = challengeJson.get("appId", "");
        std::string sessionJti = ExtractJTIFromToken(currentSession.sessionToken);
        if (challengeId.empty() || nonce.empty() || sessionJti.empty() ||
            appId.empty() || appId != currentSession.appId) {
            lastError = "Safety heartbeat challenge binding is invalid";
            return false;
        }

        // Re-open and hash the running executable for every heartbeat. The
        // server nonce and session JTI make this result unusable in any other
        // heartbeat or session.
        std::string executableHash = hashCurrentExecutable();
        if (executableHash.empty()) return false;
        std::string canonical = "vaultix-safety-heartbeat-v1\n" +
            challengeId + "\n" + nonce + "\n" + appId + "\n" +
            sessionJti + "\n" + executableHash + "\n" + safetyPublicKeyDer;
        std::string signature = signSafetyMessage(canonical);
        if (signature.empty()) {
            lastError = "Safety could not sign the heartbeat";
            return false;
        }

        std::string body = "{\"challengeId\":\"" + jsonEscape(challengeId) +
            "\",\"clientHash\":\"" + executableHash +
            "\",\"signature\":\"" + jsonEscape(signature) + "\"}";
        std::string response = performRequest("/security/heartbeat", "POST", body);
        if (response.empty()) return false;
        SimpleJSON responseJson;
        if (!responseJson.parse(response) || !responseJson.getBool("ok", false)) {
            lastError = "Safety heartbeat response is invalid";
            return false;
        }
        return true;
    }



    bool VaultixClient::AuthenticateWithUsername(const std::string& username, const std::string& password) {
        try {
            // Get HWID
            std::string hwid = getHWID();
            
            std::string safetyToken;
            if (!prepareSafetyAttestation(safetyToken)) return false;

            // Create JSON request with HWID and the one-use Safety grant.
            std::string jsonString = "{\"username\":\"" + jsonEscape(username) + "\",\"password\":\"" + jsonEscape(password) + "\",\"hwid\":\"" + jsonEscape(hwid) + "\"";
            if (!safetyToken.empty()) jsonString += ",\"safetyAttestationToken\":\"" + jsonEscape(safetyToken) + "\"";
            jsonString += "}";
            
            // Call new authentication endpoint with response headers to capture debug info
            std::map<std::string, std::string> responseHeaders;
            std::string response = performRequest("/app_auth/login", "POST", jsonString, {}, &responseHeaders);
            
            if (response.empty()) {
                // Check if we have debug info from server
                if (!lastError.empty()) {
                    // lastError already contains debug info from performRequest
                    return false;
                }
                lastError = "Empty response from server";
                return false;
            }
        
            SimpleJSON responseJson;
            if (!responseJson.parse(response)) {
                lastError = "Failed to parse authentication response";
                return false;
            }
            
            // Extract token and user info
            std::string accessToken = responseJson.get("access_token", "");
            if (accessToken.empty()) {
                lastError = "No access token received";
                return false;
            }

            bool responseSafetyEnabled = responseJson.getBool("safetyEnabled", false);
            if (responseSafetyEnabled) {
                std::string responseLeaf = responseJson.get("safetyCertificate", "");
                std::string responseRoot = responseJson.get("safetyCertificateChain", "");
                if (responseLeaf != safetyCertificate || responseRoot != safetyCertificateChain ||
                    !validateSafetyCertificateChain(responseLeaf, responseRoot)) {
                    lastError = "Login returned an invalid Safety certificate chain";
                    return false;
                }
                safetySessionEnabled = true;
            } else {
                safetySessionEnabled = false;
                std::fill(safetyPrivateKey.begin(), safetyPrivateKey.end(), 0);
                safetyPrivateKey.clear();
                safetyPublicKey.clear();
                safetyCertificate.clear();
                safetyCertificateChain.clear();
            }
            
            // Initialize session
            currentSession.isValid = true;
            currentSession.sessionToken = accessToken;
            currentSession.sessionId = responseJson.get("sessionId", "");
            currentSession.appId = responseJson.get("appId", "");
            currentSession.tokenExpiry = responseJson.get("expiresAt", "");
            currentSession.hwid = hwid;
            
            // Set app user details
            currentSession.appUser.id = responseJson.get("appUserId", "");
            currentSession.appUser.appId = currentSession.appId;
            currentSession.appUser.username = username;
            
            // Parse subscriptions array (simplified - just get the string and store it)
            // In production, you'd want proper JSON array parsing
            std::string subsStr = responseJson.get("subscriptions", "[]");
            // For now, just store empty - proper parsing would require a JSON library
            currentSession.appUser.subscriptions.clear();
            
            // Store API key in session before clearing (needed for operations like clear_autologin)
            currentSession.appApiKey = apiKey;
            
            // Clear API key from memory after successful auth
            ClearApiKey();

            // Save persistent token if provided (auto-login feature)
            std::string persistentToken = responseJson.get("persistentToken", "");
            if (!persistentToken.empty()) {
                // Use the API key from session (saved before clearing)
                std::string apiKeyToUse = currentSession.appApiKey.empty() ? apiKey : currentSession.appApiKey;
                SavePersistentToken(persistentToken, apiKeyToUse);
                if (debugMode) {
                    std::cout << "[DEBUG] Persistent auth token saved for auto-login" << std::endl;
                }
            }

            if (debugMode) {
                std::cout << "[DEBUG] Authenticated successfully as user: " << username << std::endl;
                std::cout << "[DEBUG] Token expires at: " << currentSession.tokenExpiry << std::endl;
                std::cout << "[DEBUG] App ID: " << currentSession.appId << std::endl;
            }

            return true;
            
        } catch (const std::exception& e) {
            lastError = "Authentication failed: " + std::string(e.what());
            return false;
        }
    }

    bool VaultixClient::AuthenticateWithKey(const std::string& userKey) {
        try {
            // Get HWID
            std::string hwid = getHWID();
            
            std::string safetyToken;
            if (!prepareSafetyAttestation(safetyToken)) return false;

            std::string jsonString = "{\"key\":\"" + jsonEscape(userKey) + "\",\"hwid\":\"" + jsonEscape(hwid) + "\"";
            if (!safetyToken.empty()) jsonString += ",\"safetyAttestationToken\":\"" + jsonEscape(safetyToken) + "\"";
            jsonString += "}";
            
            // Call authentication endpoint with response headers to capture debug info
            std::map<std::string, std::string> responseHeaders;
            std::string response = performRequest("/app_auth/login_key", "POST", jsonString, {}, &responseHeaders);
            
            if (response.empty()) {
                // Check if we have debug info from server
                if (!lastError.empty()) {
                    // lastError already contains debug info from performRequest
                    return false;
                }
                lastError = "Empty response from server";
                return false;
            }
            
            SimpleJSON responseJson;
            if (!responseJson.parse(response)) {
                lastError = "Failed to parse authentication response";
                return false;
            }
            
            std::string accessToken = responseJson.get("access_token", "");
            if (accessToken.empty()) {
                lastError = "No access token received";
                return false;
            }

            bool responseSafetyEnabled = responseJson.getBool("safetyEnabled", false);
            if (responseSafetyEnabled) {
                std::string responseLeaf = responseJson.get("safetyCertificate", "");
                std::string responseRoot = responseJson.get("safetyCertificateChain", "");
                if (responseLeaf != safetyCertificate || responseRoot != safetyCertificateChain ||
                    !validateSafetyCertificateChain(responseLeaf, responseRoot)) {
                    lastError = "Login returned an invalid Safety certificate chain";
                    return false;
                }
                safetySessionEnabled = true;
            } else {
                safetySessionEnabled = false;
                std::fill(safetyPrivateKey.begin(), safetyPrivateKey.end(), 0);
                safetyPrivateKey.clear();
                safetyPublicKey.clear();
                safetyCertificate.clear();
                safetyCertificateChain.clear();
            }
            
            // Initialize session
            currentSession.isValid = true;
            currentSession.sessionToken = accessToken;
            currentSession.sessionId = responseJson.get("sessionId", "");
            currentSession.appId = responseJson.get("appId", "");
            currentSession.tokenExpiry = responseJson.get("expiresAt", "");
            currentSession.hwid = hwid;
            
            // Set app user details
            currentSession.appUser.id = responseJson.get("appUserId", "");
            currentSession.appUser.appId = currentSession.appId;
            currentSession.appUser.key = userKey;
            
            // Parse subscriptions (simplified)
            currentSession.appUser.subscriptions.clear();

            // Store API key in session before clearing (needed for operations like clear_autologin)
            currentSession.appApiKey = apiKey;

            // Clear sensitive data
            ClearApiKey();

            // Save persistent token if provided (auto-login feature)
            std::string persistentToken = responseJson.get("persistentToken", "");
            if (!persistentToken.empty()) {
                // Use the API key from session (saved before clearing)
                std::string apiKeyToUse = currentSession.appApiKey.empty() ? apiKey : currentSession.appApiKey;
                SavePersistentToken(persistentToken, apiKeyToUse);
                if (debugMode) {
                    std::cout << "[DEBUG] Persistent auth token saved for auto-login" << std::endl;
                }
            }

            if (debugMode) {
                std::cout << "[DEBUG] Authenticated with key successfully" << std::endl;
                std::cout << "[DEBUG] Token expires at: " << currentSession.tokenExpiry << std::endl;
            }

            return true;
            
        } catch (const std::exception& e) {
            lastError = "Key authentication failed: " + std::string(e.what());
            return false;
        }
    }

    bool VaultixClient::IsTokenExpired() const {
        if (!currentSession.isValid || currentSession.tokenExpiry.empty()) {
            return true;
        }
        
        // Simple check - in production you'd want proper ISO timestamp parsing
        // For now, just return false and let server validate
        return false;
    }

    bool VaultixClient::RefreshToken() {
        // Re-authenticate using stored credentials
        if (!currentSession.appUser.username.empty()) {
            // User authenticated with username/password
            // Cannot auto-refresh without password
            lastError = "Password re-entry required after token expiration";
            return false;
        } else if (!currentSession.appUser.key.empty()) {
            // User authenticated with key - can auto-refresh
            return AuthenticateWithKey(currentSession.appUser.key);
        }
        
        lastError = "No stored credentials for refresh";
        return false;
    }

    bool VaultixClient::HasProductAccess(const std::string& productId) const {
        if (!currentSession.isValid) {
            return false;
        }

        if (currentSession.appUser.subscriptions.empty()) {
            return true;
        }

        for (const auto& subId : currentSession.appUser.subscriptions) {
            if (subId == productId) {
                return true;
            }
        }

        return false;
    }

    // (Removed deprecated VerifySession)

    // AUTO-LOGIN IMPLEMENTATION

    std::string VaultixClient::GetPersistentTokenPath() {
#ifdef _WIN32
        // Windows: %APPDATA%/Vaultix/auth_token.dat
        char* appdata = getenv("APPDATA");
        if (!appdata) {
            return "";
        }
        std::string path = std::string(appdata) + "\\Vaultix";

        // Create directory if it doesn't exist
        CreateDirectoryA(path.c_str(), NULL);

        return path + "\\auth_token.dat";
#else
        // Linux/Mac: ~/.vaultix/auth_token.dat
        char* home = getenv("HOME");
        if (!home) {
            return "";
        }
        std::string path = std::string(home) + "/.vaultix";

        // Create directory if it doesn't exist
        mkdir(path.c_str(), 0700);

        return path + "/auth_token.dat";
#endif
    }

    // Generate random garbage/padding bytes
    std::vector<uint8_t> VaultixClient::GenerateGarbage(size_t minSize, size_t maxSize) {
        std::vector<uint8_t> garbage;
        size_t sizeRange = maxSize - minSize + 1;
        size_t size = minSize + (rand() % sizeRange);
        garbage.resize(size);
        
        // Fill with pseudo-random data (not cryptographically secure, but good enough for obfuscation)
        for (size_t i = 0; i < size; i++) {
            garbage[i] = static_cast<uint8_t>(rand() % 256);
        }
        return garbage;
    }

    // Get obfuscated app identifier from API key (hash-based)
    std::string VaultixClient::GetAppIdentifier(const std::string& appApiKey) {
        if (appApiKey.empty()) {
            return "";
        }
        
        // Simple hash-based identifier (not cryptographically secure, just for obfuscation)
        unsigned long hash = 5381;
        for (size_t i = 0; i < appApiKey.length(); i++) {
            hash = ((hash << 5) + hash) + static_cast<unsigned char>(appApiKey[i]);
        }
        
        // Convert to hex string (obfuscated)
        std::stringstream ss;
        ss << std::hex << hash;
        return ss.str();
    }

    // Obfuscate string by adding garbage around it
    std::string VaultixClient::ObfuscateString(const std::string& input) {
        // Generate garbage before
        std::vector<uint8_t> garbageBefore = GenerateGarbage(32, 128);
        // Generate garbage after
        std::vector<uint8_t> garbageAfter = GenerateGarbage(32, 128);
        
        // Create obfuscated string: [garbage][size][data][garbage]
        std::string obfuscated;
        
        // Add garbage before
        obfuscated.append(reinterpret_cast<const char*>(garbageBefore.data()), garbageBefore.size());
        
        // Add size marker (4 bytes, but obfuscated)
        uint32_t dataSize = static_cast<uint32_t>(input.size());
        uint32_t obfuscatedSize = dataSize ^ 0xA5A5A5A5;  // XOR with magic number
        obfuscated.append(reinterpret_cast<const char*>(&obfuscatedSize), sizeof(obfuscatedSize));
        
        // Add actual data
        obfuscated.append(input);
        
        // Add garbage after
        obfuscated.append(reinterpret_cast<const char*>(garbageAfter.data()), garbageAfter.size());
        
        return obfuscated;
    }

    // Deobfuscate string by removing garbage
    std::string VaultixClient::DeobfuscateString(const std::string& obfuscated) {
        if (obfuscated.size() < sizeof(uint32_t) + 64) {  // Minimum: size marker + some garbage
            return "";
        }
        
        // Skip garbage before (assume at least 32 bytes)
        size_t offset = 32 + (rand() % 96);  // Variable offset to make it harder
        if (offset + sizeof(uint32_t) >= obfuscated.size()) {
            offset = 32;  // Fallback to minimum
        }
        
        // Try to find size marker
        for (size_t i = 0; i < 100 && (i + sizeof(uint32_t)) < obfuscated.size(); i++) {
            uint32_t obfuscatedSize;
            memcpy(&obfuscatedSize, obfuscated.data() + i, sizeof(uint32_t));
            uint32_t dataSize = obfuscatedSize ^ 0xA5A5A5A5;  // XOR to get original size
            
            // Check if size is reasonable (between 10 and 500 bytes for tokens)
            if (dataSize >= 10 && dataSize <= 500) {
                size_t dataStart = i + sizeof(uint32_t);
                if (dataStart + dataSize <= obfuscated.size()) {
                    return obfuscated.substr(dataStart, dataSize);
                }
            }
        }
        
        return "";
    }

    bool VaultixClient::SavePersistentToken(const std::string& token, const std::string& appApiKey) {
        if (token.empty() || appApiKey.empty()) {
            return false;
        }

        std::string tokenPath = GetPersistentTokenPath();
        if (tokenPath.empty()) {
            if (debugMode) {
                std::cout << "[DEBUG] Failed to get persistent token path" << std::endl;
            }
            return false;
        }

        // Get app identifier (obfuscated)
        std::string appId = GetAppIdentifier(appApiKey);
        if (appId.empty()) {
            return false;
        }

        // Read existing tokens (if any)
        std::map<std::string, std::string> tokens;
        std::ifstream readFile(tokenPath, std::ios::binary);
        if (readFile.is_open()) {
            std::string fileContent((std::istreambuf_iterator<char>(readFile)), std::istreambuf_iterator<char>());
            readFile.close();
            
            // Parse existing tokens (simple format: each entry is obfuscated)
            // Format: [garbage][appId][garbage][token][garbage]...
            size_t pos = 0;
            while (pos < fileContent.size()) {
                // Try to find app identifier (after some garbage)
                size_t searchLimit = (pos + 200 < fileContent.size()) ? (pos + 200) : fileContent.size();
                for (size_t i = pos; i < searchLimit; i++) {
                    if (fileContent.substr(i, appId.length()) == appId) {
                        // Found app ID, skip it and garbage, then extract token
                        size_t tokenStart = i + appId.length() + 32;  // Skip appId and garbage
                        std::string obfuscatedEntry = fileContent.substr(pos, (i - pos) + 500);  // Approximate
                        std::string extractedToken = DeobfuscateString(obfuscatedEntry);
                        if (!extractedToken.empty()) {
                            tokens[appId] = extractedToken;
                        }
                        pos = i + 500;
                        break;
                    }
                }
                pos += 200;
            }
        }

        // Update token for this app
        tokens[appId] = token;

        // Write all tokens back with obfuscation
        std::ofstream file(tokenPath, std::ios::binary);
        if (!file.is_open()) {
            if (debugMode) {
                std::cout << "[DEBUG] Failed to open token file for writing: " << tokenPath << std::endl;
            }
            return false;
        }

        // Write each token entry with heavy obfuscation
        for (const auto& entry : tokens) {
            // Add garbage before app identifier
            std::vector<uint8_t> garbage1 = GenerateGarbage(64, 256);
            file.write(reinterpret_cast<const char*>(garbage1.data()), garbage1.size());
            
            // Write app identifier (somewhat obfuscated)
            file.write(entry.first.c_str(), entry.first.length());
            
            // Add garbage between identifier and token
            std::vector<uint8_t> garbage2 = GenerateGarbage(32, 128);
            file.write(reinterpret_cast<const char*>(garbage2.data()), garbage2.size());
            
            // Write obfuscated token
            std::string obfuscatedToken = ObfuscateString(entry.second);
            file.write(obfuscatedToken.c_str(), obfuscatedToken.length());
            
            // Add garbage after token
            std::vector<uint8_t> garbage3 = GenerateGarbage(64, 256);
            file.write(reinterpret_cast<const char*>(garbage3.data()), garbage3.size());
        }

        file.close();

        if (debugMode) {
            std::cout << "[DEBUG] Persistent token saved to: " << tokenPath << std::endl;
        }

        return true;
    }

    std::string VaultixClient::LoadPersistentToken(const std::string& appApiKey) {
        if (appApiKey.empty()) {
            return "";
        }

        std::string tokenPath = GetPersistentTokenPath();
        if (tokenPath.empty()) {
            return "";
        }

        std::ifstream file(tokenPath, std::ios::binary);
        if (!file.is_open()) {
            return "";
        }

        // Read entire file
        std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        if (fileContent.empty()) {
            return "";
        }

        // Get app identifier
        std::string appId = GetAppIdentifier(appApiKey);
        if (appId.empty()) {
            return "";
        }

        // Search for app identifier in file (hidden among garbage)
        size_t pos = 0;
        while (pos < fileContent.size()) {
            // Look for app identifier
            size_t found = fileContent.find(appId, pos);
            if (found == std::string::npos) {
                break;  // Not found
            }

            // Found app identifier, now try to extract token after it
            // Skip appId and garbage, then try to deobfuscate
            size_t tokenAreaStart = found;
            size_t maxEnd = found + 2000;
            size_t tokenAreaEnd = (maxEnd < fileContent.size()) ? maxEnd : fileContent.size();  // Look in next 2000 bytes
            std::string tokenArea = fileContent.substr(tokenAreaStart, tokenAreaEnd - tokenAreaStart);
            
            // Try multiple offsets to find the token
            size_t maxOffset = (tokenArea.length() < 500) ? tokenArea.length() : 500;
            for (size_t offset = appId.length() + 32; offset < maxOffset; offset++) {
                std::string candidate = tokenArea.substr(offset);
                std::string extractedToken = DeobfuscateString(candidate);
                if (!extractedToken.empty() && extractedToken.length() >= 10) {
                    if (debugMode) {
                        std::cout << "[DEBUG] Persistent token loaded from: " << tokenPath << std::endl;
                    }
                    return extractedToken;
                }
            }

            pos = found + 1;  // Continue searching
        }

        return "";
    }

    bool VaultixClient::DeletePersistentToken(const std::string& appApiKey) {
        if (appApiKey.empty()) {
            return false;
        }

        std::string tokenPath = GetPersistentTokenPath();
        if (tokenPath.empty()) {
            return false;
        }

        // Get app identifier
        std::string appId = GetAppIdentifier(appApiKey);
        if (appId.empty()) {
            return false;
        }

        // Read all tokens
        std::map<std::string, std::string> tokens;
        std::ifstream readFile(tokenPath, std::ios::binary);
        if (readFile.is_open()) {
            std::string fileContent((std::istreambuf_iterator<char>(readFile)), std::istreambuf_iterator<char>());
            readFile.close();
            
            // Parse all tokens
            size_t pos = 0;
            while (pos < fileContent.size()) {
                // Try to find any app identifier
                size_t searchLimit = (pos + 200 < fileContent.size()) ? (pos + 200) : fileContent.size();
                for (size_t i = pos; i < searchLimit; i++) {
                    // Look for potential identifiers (hex strings)
                    if (i + 8 < fileContent.size()) {
                        std::string candidate = fileContent.substr(i, 8);
                        // Check if it looks like an identifier (hex chars)
                        bool isHex = true;
                        for (char c : candidate) {
                            if (!std::isxdigit(c)) {
                                isHex = false;
                                break;
                            }
                        }
                        if (isHex) {
                            size_t tokenStart = i + candidate.length() + 32;
                            std::string obfuscatedEntry = fileContent.substr(pos, (i - pos) + 500);
                            std::string extractedToken = DeobfuscateString(obfuscatedEntry);
                            if (!extractedToken.empty()) {
                                tokens[candidate] = extractedToken;
                            }
                            pos = i + 500;
                            break;
                        }
                    }
                }
                pos += 200;
            }
        }

        // Remove token for this app
        tokens.erase(appId);

        // If no tokens left, delete file
        if (tokens.empty()) {
#ifdef _WIN32
            return DeleteFileA(tokenPath.c_str()) != 0;
#else
            return unlink(tokenPath.c_str()) == 0;
#endif
        }

        // Write remaining tokens back
        std::ofstream file(tokenPath, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Write each token entry with obfuscation
        for (const auto& entry : tokens) {
            std::vector<uint8_t> garbage1 = GenerateGarbage(64, 256);
            file.write(reinterpret_cast<const char*>(garbage1.data()), garbage1.size());
            
            file.write(entry.first.c_str(), entry.first.length());
            
            std::vector<uint8_t> garbage2 = GenerateGarbage(32, 128);
            file.write(reinterpret_cast<const char*>(garbage2.data()), garbage2.size());
            
            std::string obfuscatedToken = ObfuscateString(entry.second);
            file.write(obfuscatedToken.c_str(), obfuscatedToken.length());
            
            std::vector<uint8_t> garbage3 = GenerateGarbage(64, 256);
            file.write(reinterpret_cast<const char*>(garbage3.data()), garbage3.size());
        }

        file.close();
        return true;
    }

    bool VaultixClient::TryAutoLogin() {
        try {
            // Get API key to identify which token to load
            std::string apiKeyToUse = currentSession.appApiKey.empty() ? apiKey : currentSession.appApiKey;
            if (apiKeyToUse.empty()) {
                if (debugMode) {
                    std::cout << "[DEBUG] No API key available for token lookup" << std::endl;
                }
                return false;
            }

            // Load persistent token from file for this specific app
            std::string persistentToken = LoadPersistentToken(apiKeyToUse);
            if (persistentToken.empty()) {
                if (debugMode) {
                    std::cout << "[DEBUG] No persistent token found for this app" << std::endl;
                }
                return false;
            }

            // Get HWID
            std::string hwid = getHWID();

            std::string safetyToken;
            if (!prepareSafetyAttestation(safetyToken)) return false;

            std::string jsonString = "{\"token\":\"" + jsonEscape(persistentToken) + "\",\"hwid\":\"" + jsonEscape(hwid) + "\"";
            if (!safetyToken.empty()) jsonString += ",\"safetyAttestationToken\":\"" + jsonEscape(safetyToken) + "\"";
            jsonString += "}";

            // Call auto-login endpoint with response headers to capture debug info
            std::map<std::string, std::string> responseHeaders;
            std::string response = performRequest("/app_auth/autologin", "POST", jsonString, {}, &responseHeaders);

            if (response.empty()) {
                // Check if we have debug info from server
                if (lastError.empty()) {
                    lastError = "Empty response from server";
                }
                // An unverifiable response says nothing about the saved token; keep it.
                if (!lastResponseRejected) {
                    DeletePersistentToken(apiKeyToUse);  // Delete invalid token
                }
                return false;
            }

            SimpleJSON responseJson;
            if (!responseJson.parse(response)) {
                lastError = "Failed to parse auto-login response";
                DeletePersistentToken(apiKeyToUse);  // Delete invalid token
                return false;
            }

            std::string accessToken = responseJson.get("access_token", "");
            if (accessToken.empty()) {
                lastError = "No access token received";
                DeletePersistentToken(apiKeyToUse);  // Delete invalid token
                return false;
            }

            bool responseSafetyEnabled = responseJson.getBool("safetyEnabled", false);
            if (responseSafetyEnabled) {
                std::string responseLeaf = responseJson.get("safetyCertificate", "");
                std::string responseRoot = responseJson.get("safetyCertificateChain", "");
                if (responseLeaf != safetyCertificate || responseRoot != safetyCertificateChain ||
                    !validateSafetyCertificateChain(responseLeaf, responseRoot)) {
                    lastError = "Login returned an invalid Safety certificate chain";
                    return false;
                }
                safetySessionEnabled = true;
            } else {
                safetySessionEnabled = false;
                std::fill(safetyPrivateKey.begin(), safetyPrivateKey.end(), 0);
                safetyPrivateKey.clear();
                safetyPublicKey.clear();
                safetyCertificate.clear();
                safetyCertificateChain.clear();
            }

            // Initialize session
            currentSession.isValid = true;
            currentSession.sessionToken = accessToken;
            currentSession.sessionId = responseJson.get("sessionId", "");
            currentSession.appId = responseJson.get("appId", "");
            currentSession.tokenExpiry = responseJson.get("expiresAt", "");
            currentSession.hwid = hwid;

            // Set app user details
            currentSession.appUser.id = responseJson.get("appUserId", "");
            currentSession.appUser.appId = currentSession.appId;

            // Parse subscriptions (simplified)
            currentSession.appUser.subscriptions.clear();

            // Store API key in session before clearing (needed for operations like clear_autologin)
            // Note: For auto-login, we might not have the API key, so try to get it from current session or apiKey
            if (currentSession.appApiKey.empty() && !apiKey.empty()) {
                currentSession.appApiKey = apiKey;
            }

            // Clear sensitive data
            ClearApiKey();

            if (debugMode) {
                std::cout << "[DEBUG] Auto-login successful" << std::endl;
                std::cout << "[DEBUG] Session ID: " << currentSession.sessionId << std::endl;
                std::cout << "[DEBUG] Token expires at: " << currentSession.tokenExpiry << std::endl;
            }

            return true;

        } catch (const std::exception& e) {
            lastError = "Auto-login failed: " + std::string(e.what());
            std::string apiKeyToUse = currentSession.appApiKey.empty() ? apiKey : currentSession.appApiKey;
            if (!apiKeyToUse.empty()) {
                DeletePersistentToken(apiKeyToUse);  // Delete invalid token on error
            }
            return false;
        }
    }

    void VaultixClient::EndSession() {
        if (currentSession.isValid) {
            // No payload needed - session ID is extracted from the Bearer token
            std::string payload = "";

            std::string response = performRequest("/app_auth/logout", "POST", payload);

            if (!response.empty()) {
                SimpleJSON logoutJson;
                if (logoutJson.parse(response)) {
                    // The logout endpoint returns {"message": "...", "sessionId": "..."}
                    std::string message = logoutJson.get("message", "");
                    if (message.find("successfully") == std::string::npos) {
                        // If message doesn't contain "successfully", something went wrong
                        lastError = message.empty() ? "Failed to terminate session" : message;
                    }
                }
            }

            if (debugMode) {
                if (!response.empty()) {
                    std::cout << "[DEBUG] Logout response: " << response << std::endl;
                } else {
                    std::cout << "[DEBUG] Logout request sent";
                    if (!currentSession.sessionId.empty()) {
                        std::cout << " for session " << currentSession.sessionId;
                    }
                    std::cout << std::endl;
                }
            }
        }

        // Clear session data regardless of logout success
        currentSession.isValid = false;
        currentSession.sessionToken.clear();
        currentSession.sessionId.clear();
        safetySessionEnabled = false;
        std::fill(safetyPrivateKey.begin(), safetyPrivateKey.end(), 0);
        safetyPrivateKey.clear();
        safetyPublicKey.clear();
        safetyCertificate.clear();
        safetyCertificateChain.clear();
        currentSession.hwid.clear();
        currentSession.appId.clear();
        currentSession.tokenExpiry.clear();
        // Clear API key from session
        if (!currentSession.appApiKey.empty()) {
            std::fill(currentSession.appApiKey.begin(), currentSession.appApiKey.end(), 0);
        }
        currentSession.appApiKey.clear();
        currentSession.appUser = AppUser{};
        verifiedZk1Files.clear();

        // NOTE: Does NOT delete persistent token - use ClearAutoLoginToken() for that
    }

    void VaultixClient::ClearAutoLoginToken() {
        // Get API key to identify which token to clear
        std::string apiKeyToUse = currentSession.appApiKey.empty() ? apiKey : currentSession.appApiKey;
        if (apiKeyToUse.empty()) {
            if (debugMode) {
                std::cout << "[DEBUG] No API key available for token lookup" << std::endl;
            }
            return;
        }

        // Step 1: Load the persistent token before deleting it
        std::string persistentToken = LoadPersistentToken(apiKeyToUse);

        // Step 2: If token exists, notify server to revoke it
        if (!persistentToken.empty()) {
            try {
                std::string hwid = getHWID();

                // Build JSON payload
                std::string payload = "{\"token\":\"" + persistentToken + "\",\"hwid\":\"" + hwid + "\"}";

                if (debugMode) {
                    std::cout << "[DEBUG] Notifying server to revoke auto-login token..." << std::endl;
                }

                // Call server endpoint to revoke token
                // Use stored API key from session (apiKey is cleared after auth)
                std::map<std::string, std::string> headers;
                std::string apiKeyToUse = currentSession.appApiKey.empty() ? apiKey : currentSession.appApiKey;
                headers["X-API-Key"] = apiKeyToUse;
                headers["Content-Type"] = "application/json";

                if (debugMode) {
                    std::cout << "[DEBUG] Using API key from session: " << (apiKeyToUse.empty() ? "EMPTY" : "set (not shown)") << std::endl;
                }

                std::string response = performRequest("/app_auth/clear_autologin", "POST", payload, headers);

                if (debugMode) {
                    std::cout << "[DEBUG] Server notified successfully: " << response << std::endl;
                }
            } catch (const std::exception& e) {
                // Don't fail if server notification fails - still clear local token
                if (debugMode) {
                    std::cout << "[DEBUG] Failed to notify server (will still clear local token): " << e.what() << std::endl;
                }
            }
        }

        // Step 3: Delete local token for this app (always, even if server call failed)
        bool deleted = DeletePersistentToken(apiKeyToUse);

        if (debugMode) {
            if (deleted) {
                std::cout << "[DEBUG] Auto-login token cleared successfully" << std::endl;
                std::cout << "[DEBUG] User will need to enter credentials on next login" << std::endl;
            } else {
                std::cout << "[DEBUG] No auto-login token found to clear" << std::endl;
            }
        }
    }

    FileInfo VaultixClient::GetFileInfo(const std::string& productId, const std::string& fileName) {
        FileInfo file;
        
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return file;
        }
        
        // Check token expiration
        if (IsTokenExpired()) {
            if (!RefreshToken()) {
                lastError = "Token expired and refresh failed";
                return file;
            }
        }
        
        try {
            std::map<std::string, std::string> headers;
            headers["X-Product-ID"] = productId;
            
            // URL encode the filename
            std::string encodedFileName = urlEncode(fileName);
            std::string response = performRequest("/files/info/" + encodedFileName + "?productId=" + productId, "GET", "", headers);
            
            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response from server";
                return file;
            }
            
            SimpleJSON responseJson;
            if (!responseJson.parse(response)) {
                lastError = "Failed to parse JSON response";
                return file;
            }
            
            file.id = responseJson.get("id", "");
            file.name = responseJson.get("name", "");
            file.appId = responseJson.get("appId", "");
            file.size = std::stoull(responseJson.get("size", "0"));
            file.encrypted = responseJson.getBool("encrypted", true);
            file.encryptionKey = responseJson.get("encryptionKey", "");
            file.encryptionIV = responseJson.get("encryptionIV", "");
            file.downloads = std::stoi(responseJson.get("downloads", "0"));
            file.uploadedAt = responseJson.get("uploadedAt", "");
            
        } catch (const std::exception& e) {
            lastError = "Exception during file info retrieval: " + std::string(e.what());
        }
        
        return file;
    }

    // ========== NETWORK OBFUSCATION FUNCTIONS ==========

    std::string VaultixClient::ExtractJTIFromToken(const std::string& jwtToken) {
        // JWT format: header.payload.signature
        // We need to decode the payload (middle part) to extract JTI

        try {
            // Split token by '.'
            size_t firstDot = jwtToken.find('.');
            if (firstDot == std::string::npos) {
                return "";
            }

            size_t secondDot = jwtToken.find('.', firstDot + 1);
            if (secondDot == std::string::npos) {
                return "";
            }

            // Extract payload (base64-encoded JSON)
            std::string payloadB64 = jwtToken.substr(firstDot + 1, secondDot - firstDot - 1);

            // Decode base64 payload
            std::vector<uint8_t> payloadBytes = base64_decode(payloadB64);
            std::string payloadJson(payloadBytes.begin(), payloadBytes.end());

            // Simple JSON parsing to extract "jti" field
            size_t jtiPos = payloadJson.find("\"jti\"");
            if (jtiPos == std::string::npos) {
                return "";
            }

            // Find the value after "jti":"
            size_t colonPos = payloadJson.find(':', jtiPos);
            if (colonPos == std::string::npos) {
                return "";
            }

            size_t quoteStart = payloadJson.find('"', colonPos);
            if (quoteStart == std::string::npos) {
                return "";
            }

            size_t quoteEnd = payloadJson.find('"', quoteStart + 1);
            if (quoteEnd == std::string::npos) {
                return "";
            }

            std::string jti = payloadJson.substr(quoteStart + 1, quoteEnd - quoteStart - 1);


            return jti;

        } catch (const std::exception& e) {
            if (debugMode) {
                std::cout << "[ERROR] Failed to extract JTI: " << e.what() << std::endl;
            }
            return "";
        }
    }

    std::string VaultixClient::DecryptHeaderValue(const std::string& encryptedValue, const std::string& sessionJTI) {
        // Derive transport key from session JTI (same as Python server)
        // HMAC-SHA256(jti[:32], "file_metadata_encryption")

        try {
            // Pad/truncate JTI to 32 bytes
            std::string jti = sessionJTI;
            if (jti.length() < 32) {
                jti.resize(32, '\0');
            } else if (jti.length() > 32) {
                jti = jti.substr(0, 32);
            }

            // Compute HMAC-SHA256 to derive transport key
            const char* salt = "file_metadata_encryption";
            unsigned char transport_key[32];
            unsigned int hmac_len = 0;

            HMAC(EVP_sha256(),
                 jti.c_str(), 32,
                 reinterpret_cast<const unsigned char*>(salt), strlen(salt),
                 transport_key, &hmac_len);


            // Now decrypt the header value using Fernet with transport_key
            // The header value is a Fernet-encrypted string

            std::vector<uint8_t> encrypted_data(encryptedValue.begin(), encryptedValue.end());

            // Use transport key as Fernet key (32 bytes padded key string)
            std::string transport_key_str(reinterpret_cast<const char*>(transport_key), 32);

            // Decrypt using DecryptData (it handles Fernet format)
            std::vector<uint8_t> decrypted = DecryptData(encrypted_data, transport_key_str, "");

            if (decrypted.empty()) {
                if (debugMode) {
                    std::cout << "[ERROR] Failed to decrypt header value" << std::endl;
                }
                return "";
            }

            std::string result(decrypted.begin(), decrypted.end());

            if (debugMode) {
                std::cout << "[DEBUG] Header value decrypted (not shown)" << std::endl;
            }

            return result;

        } catch (const std::exception& e) {
            if (debugMode) {
                std::cout << "[ERROR] Exception in DecryptHeaderValue: " << e.what() << std::endl;
            }
            return "";
        }
    }

    // ========== END NETWORK OBFUSCATION FUNCTIONS ==========


    std::vector<uint8_t> VaultixClient::DecryptData(const std::vector<uint8_t>& encryptedData,
                                                  const std::string& key,
                                                  const std::string& iv) {
        std::vector<uint8_t> decryptedData;

        try {
            if (debugMode) {
                std::cout << "[DEBUG] DecryptData: Input size = " << encryptedData.size() << " bytes" << std::endl;
                std::cout << "[DEBUG] Starting AES-256-GCM decryption..." << std::endl;
            }

            // Server sends: SALT(16) + IV(12) + TAG(16) + CIPHERTEXT (total 44+ bytes header)
            // Legacy format: IV(12) + TAG(16) + CIPHERTEXT (28+ bytes)
            // Detect format based on size
            bool hasEmbeddedSalt = (encryptedData.size() >= 44);
            
            std::vector<uint8_t> salt;
            std::vector<uint8_t> iv_bytes;
            std::vector<uint8_t> tag;
            std::vector<uint8_t> ciphertext;
            
            if (hasEmbeddedSalt) {
                // New format: extract SALT(16) + IV(12) + TAG(16) + CIPHERTEXT
                if (debugMode) {
                    std::cout << "[DEBUG] Detected NEW encryption format with embedded salt" << std::endl;
                }
                
                salt.assign(encryptedData.begin(), encryptedData.begin() + 16);
                iv_bytes.assign(encryptedData.begin() + 16, encryptedData.begin() + 28);
                tag.assign(encryptedData.begin() + 28, encryptedData.begin() + 44);
                ciphertext.assign(encryptedData.begin() + 44, encryptedData.end());
            } else if (encryptedData.size() >= 28) {
                // Legacy format: IV(12) + TAG(16) + CIPHERTEXT (use fixed salt)
                if (debugMode) {
                    std::cout << "[DEBUG] Detected LEGACY encryption format" << std::endl;
                }
                
                // LEGACY_ENCRYPTION_SALT = b'vaultix_salt_2024' (17 bytes - matches server)
                salt = {'v', 'a', 'u', 'l', 't', 'i', 'x', '_', 's', 'a', 'l', 't', '_', '2', '0', '2', '4'};
                iv_bytes.assign(encryptedData.begin(), encryptedData.begin() + 12);
                tag.assign(encryptedData.begin() + 12, encryptedData.begin() + 28);
                ciphertext.assign(encryptedData.begin() + 28, encryptedData.end());
            } else {
                lastError = "Invalid encrypted data size for AES-GCM";
                return decryptedData;
            }

            if (debugMode) {
                std::cout << "[DEBUG] Salt size: " << salt.size() << " bytes" << std::endl;
                std::cout << "[DEBUG] IV size: " << iv_bytes.size() << " bytes" << std::endl;
                std::cout << "[DEBUG] Tag size: " << tag.size() << " bytes" << std::endl;
                std::cout << "[DEBUG] Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;
            }

            // Derive encryption key from provided key using PBKDF2 (same as server)
            std::vector<uint8_t> derived_key(32);
            
            if (PKCS5_PBKDF2_HMAC(key.c_str(), key.length(),
                                 salt.data(), salt.size(),
                                 100000,  // Same iterations as server
                                 EVP_sha256(),
                                 32, derived_key.data()) != 1) {
                lastError = "Failed to derive encryption key";
                return decryptedData;
            }
               
            if (debugMode) {
                std::cout << "[DEBUG] PBKDF2 key derivation successful" << std::endl;
            }

            // Set up AES-GCM decryption
            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                lastError = "Failed to create cipher context";
                return decryptedData;
            }

            // Initialize AES-256-GCM decryption (first call - no key/IV yet)
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
                lastError = "Failed to initialize AES-GCM cipher";
                EVP_CIPHER_CTX_free(ctx);
                return decryptedData;
            }
            if (debugMode) {
                std::cout << "[DEBUG] GCM cipher initialized" << std::endl;
            }

            // Set the IV length AFTER initializing the cipher
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
                lastError = "Failed to set IV length";
                EVP_CIPHER_CTX_free(ctx);
                return decryptedData;
            }
            if (debugMode) {
                std::cout << "[DEBUG] IV length set to 12 bytes" << std::endl;
            }

               // Initialize with key and IV (second call)
               if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, derived_key.data(), iv_bytes.data()) != 1) {
                   lastError = "Failed to set key and IV";
                   EVP_CIPHER_CTX_free(ctx);
                   return decryptedData;
               }
            if (debugMode) {
                std::cout << "[DEBUG] Key and IV set" << std::endl;
            }

               // Set the authentication tag BEFORE decryption
               if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
                   lastError = "Failed to set authentication tag";
                   EVP_CIPHER_CTX_free(ctx);
                   return decryptedData;
               }
            if (debugMode) {
                std::cout << "[DEBUG] Authentication tag set" << std::endl;
            }

            // Decrypt the ciphertext
            decryptedData.resize(ciphertext.size());
            int len;
            int decryptedLen;

            if (EVP_DecryptUpdate(ctx, decryptedData.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
                lastError = "Failed to decrypt data";
                EVP_CIPHER_CTX_free(ctx);
                return decryptedData;
            }
            decryptedLen = len;

               // Finalize decryption (verifies authentication tag)
               if (EVP_DecryptFinal_ex(ctx, decryptedData.data() + len, &len) != 1) {
                   // Print OpenSSL errors for debugging
                   if (debugMode) {
                       std::cout << "[ERROR] GCM decryption failed. OpenSSL errors:" << std::endl;
                       ERR_print_errors_fp(stdout);
                       
                       // Also try to get specific error codes
                       unsigned long error = ERR_get_error();
                       if (error != 0) {
                           std::cout << "[ERROR] OpenSSL error code: " << std::hex << error << std::dec << std::endl;
                           char error_buf[256];
                           ERR_error_string_n(error, error_buf, sizeof(error_buf));
                           std::cout << "[ERROR] OpenSSL error string: " << error_buf << std::endl;
                       } else {
                           std::cout << "[ERROR] No OpenSSL errors found" << std::endl;
                       }
                   }
                   lastError = "Failed to finalize decryption (authentication failed)";
                   EVP_CIPHER_CTX_free(ctx);
                   return decryptedData;
               }
            decryptedLen += len;

            // Resize to actual decrypted length
            decryptedData.resize(decryptedLen);

            EVP_CIPHER_CTX_free(ctx);

            if (debugMode) {
                std::cout << "[DEBUG] Decryption successful: " << decryptedLen << " bytes" << std::endl;
            }

        } catch (const std::exception& e) {
            lastError = "Exception during decryption: " + std::string(e.what());
            return std::vector<uint8_t>();
        }

        return decryptedData;
    }

    // ===== NEW FILE OPERATIONS WITH PRODUCT ID (NEW STRUCTURE) =====

    std::vector<FileInfo> VaultixClient::GetFileList(const std::string& productId) {
        std::vector<FileInfo> files;
        
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return files;
        }
        
        // Check token expiration
        if (IsTokenExpired()) {
            if (!RefreshToken()) {
                lastError = "Token expired and refresh failed";
                return files;
            }
        }
        
        try {
            std::map<std::string, std::string> headers;
            headers["X-Product-ID"] = productId;
            
            std::string response = performRequest("/files?productId=" + productId, "GET", "", headers);

            if (debugMode) {
                std::cout << "[DEBUG] Received file list for product: " << productId << std::endl;
            }

            // TODO: Parse JSON array properly - would need a proper JSON library
            // For now return empty list

        } catch (const std::exception& e) {
            lastError = "Exception during file list retrieval: " + std::string(e.what());
        }
        
        return files;
    }

    bool VaultixClient::DownloadFile(const std::string& productId, const std::string& fileName, const std::string& outputPath) {
        lastSignedAt = 0;
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return false;
        }
        
        // Check token expiration
        if (IsTokenExpired()) {
            if (!RefreshToken()) {
                lastError = "Token expired and refresh failed";
            return false;
            }
        }
        
        try {
            std::map<std::string, std::string> headers;
            headers["X-Product-ID"] = productId;
            
            // URL encode the filename
            std::string encodedFileName = urlEncode(fileName);
            // Get response headers to extract encryption info
            std::map<std::string, std::string> responseHeaders;
            Zk1Download zk1(*this, Zk1Download::File, "file", fileName, productId, outputPath);
            std::string response = performRequest("/files/download/" + encodedFileName + "?productId=" + productId, "GET", "", headers, &responseHeaders, &zk1);

            // End-to-end encrypted: already verified, decrypted and saved (or nothing saved).
            if (zk1.IsDelivery()) {
                if (debugMode && zk1.Succeeded()) {
                    std::cout << "[DEBUG] Downloaded file: " << fileName << " from product: " << productId << std::endl;
                    std::cout << "[DEBUG] Saved to: " << outputPath << std::endl;
                }
                return zk1.Succeeded();
            }

            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response when downloading file";
                return false;
            }

            // Extract encryption key from headers (case-insensitive)
            std::string encryptionKey = "";
            for (const auto& header : responseHeaders) {
                std::string key = header.first;
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                if (key == "x-encryption-key") {
                    encryptionKey = header.second;
                    break;
                }
            }

            if (encryptionKey.empty()) {
                lastError = "Missing encryption key in response headers";
                return false;
            }

            if (debugMode) {
                std::cout << "[DEBUG] Encryption key received (not shown)" << std::endl;
            }

            // Use the full key as provided (don't strip enc_key_ prefix)
            std::string cleanKey = encryptionKey;
            
            // Convert response to bytes (contains IV + TAG + CIPHERTEXT for AES-GCM)
            std::vector<uint8_t> encryptedData(response.begin(), response.end());
            
            // Decrypt the data using AES-GCM (IV is embedded in the data)
            std::vector<uint8_t> decryptedData = DecryptData(encryptedData, cleanKey, "");
            
            if (decryptedData.empty()) {
                lastError = "Failed to decrypt file: " + GetLastError();
                return false;
            }
            
            // Save decrypted data to file
            std::ofstream outFile(outputPath, std::ios::binary);
            if (!outFile) {
                lastError = "Failed to open output file: " + outputPath;
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
            outFile.close();
            
            if (debugMode) {
                std::cout << "[DEBUG] Downloaded file: " << fileName << " from product: " << productId << std::endl;
                std::cout << "[DEBUG] Saved to: " << outputPath << std::endl;
            }
            
            return true;
            
        } catch (const std::exception& e) {
            lastError = "Exception during file download: " + std::string(e.what());
            return false;
        }
    }

    std::vector<uint8_t> VaultixClient::DownloadFileToMemory(const std::string& productId, const std::string& fileName) {
        std::vector<uint8_t> data;
        lastSignedAt = 0;
        
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return data;
        }
        
        // Check token expiration
        if (IsTokenExpired()) {
            if (!RefreshToken()) {
                lastError = "Token expired and refresh failed";
                return data;
            }
        }
        
        try {
            std::map<std::string, std::string> headers;
            headers["X-Product-ID"] = productId;
            
            // URL encode the filename
            std::string encodedFileName = urlEncode(fileName);
            
            // Get response headers to extract encryption info
            std::map<std::string, std::string> responseHeaders;
            Zk1Download zk1(*this, Zk1Download::Memory, "file", fileName, productId);
            std::string response = performRequest("/files/download/" + encodedFileName + "?productId=" + productId, "GET", "", headers, &responseHeaders, &zk1);

            // End-to-end encrypted: verified and decrypted in memory, or nothing.
            if (zk1.IsDelivery()) {
                if (zk1.Succeeded()) data.swap(zk1.memory);
                return data;
            }

            if (!response.empty()) {
                // Extract encryption key from headers (case-insensitive)
                std::string encryptionKey = "";
                for (const auto& header : responseHeaders) {
                    std::string key = header.first;
                    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                    if (key == "x-encryption-key") {
                        encryptionKey = header.second;
                        break;
                    }
                }
                
                if (!encryptionKey.empty()) {
                    // Use the full key as provided (don't strip enc_key_ prefix)
                    std::string cleanKey = encryptionKey;
                    
                    // Convert response to bytes (contains IV + TAG + CIPHERTEXT for AES-GCM)
                    std::vector<uint8_t> encryptedData(response.begin(), response.end());
                    
                    // Decrypt the data using AES-GCM (IV is embedded in the data)
                    std::vector<uint8_t> decryptedData = DecryptData(encryptedData, cleanKey, "");
                    
                    if (!decryptedData.empty()) {
                        data = decryptedData;
                    } else {
                        lastError = "Failed to decrypt file: " + GetLastError();
                    }
                } else {
                    // Vaultix always encrypts downloads. Never hand out a body
                    // that arrived without encryption headers.
                    lastError = "Missing encryption key in response headers; refusing unencrypted file data";
                }
            }
            
        } catch (const std::exception& e) {
            lastError = "Exception during file download: " + std::string(e.what());
        }
        
        return data;
    }

    bool VaultixClient::StreamFile(const std::string& productId, const std::string& fileName,
                                 std::function<void(const std::vector<uint8_t>&, size_t, size_t)> callback) {
        lastSignedAt = 0;
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return false;
        }
        
        try {
            // For simplicity, we'll download to memory and then stream in chunks
            std::vector<uint8_t> data = DownloadFileToMemory(productId, fileName);
            
            if (data.empty()) {
                return false;
            }
            
            // Stream in 4KB chunks
            const size_t chunkSize = 4096;
            size_t totalSize = data.size();
            size_t processed = 0;
            
            while (processed < totalSize) {
                size_t currentChunkSize = (chunkSize < (totalSize - processed)) ? chunkSize : (totalSize - processed);
                std::vector<uint8_t> chunk(data.begin() + processed, data.begin() + processed + currentChunkSize);
                
                processed += currentChunkSize;
                callback(chunk, processed, totalSize);
            }
            
            return true;
            
        } catch (const std::exception& e) {
            lastError = "Exception during file streaming: " + std::string(e.what());
            return false;
        }
    }

    bool VaultixClient::IsValidFileHash(const std::string& productId, const std::string& fileName, const std::string& filePath) {
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return false;
        }
        
        // Check token expiration
        if (IsTokenExpired()) {
            if (!RefreshToken()) {
                lastError = "Token expired and refresh failed";
                return false;
            }
        }
        
        try {
            // Read the file and calculate SHA256 hash
            std::ifstream file(filePath, std::ios::binary);
            if (!file.is_open()) {
                lastError = "Failed to open file: " + filePath;
                return false;
            }
            
            // Calculate SHA256 hash
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            
            char buffer[8192];
            while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
                SHA256_Update(&sha256, buffer, file.gcount());
            }
            
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_Final(hash, &sha256);
            
            // Convert hash to hex string
            std::stringstream ss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
            }
            std::string fileHash = ss.str();
            
            file.close();
            
            if (debugMode) {
                std::cout << "[DEBUG] Calculated file hash: " << fileHash << std::endl;
            }
            
            // Send hash to server for verification
            std::map<std::string, std::string> headers;
            headers["X-Product-ID"] = productId;
            
            // Create JSON request (escape strings for JSON)
            const std::string requestStart = "{\"productId\":\"" + jsonEscape(productId) +
                                             "\",\"fileName\":\"" + jsonEscape(fileName) + "\",";
            const std::string plainRequest = requestStart + "\"hash\":\"" + jsonEscape(fileHash) + "\"}";
            // End-to-end encryption: Vaultix stores only the keyed hash
            // HMAC(kh, SHA-256) of zk1 files (docs/E2EE_FORMAT.md section 5).
            // Files of apps without it answer "plain_hash_required": then
            // once more with the plain SHA-256, unless this client already
            // received the file as a verified zk1 delivery (a server asking
            // for its plain hash would learn what end-to-end encryption hides).
            bool keyed = HasContentKey();
            std::string jsonString = plainRequest;
            if (keyed) {
                uint8_t keyedHash[32];
                if (!zk1::HmacSha256(contentKey.hashKey, sizeof(contentKey.hashKey), hash, sizeof(hash), keyedHash)) {
                    lastError = "Could not compute the keyed file hash";
                    return false;
                }
                static const char* hexDigits = "0123456789abcdef";
                std::string keyedHex;
                for (uint8_t byte : keyedHash) {
                    keyedHex += hexDigits[byte >> 4];
                    keyedHex += hexDigits[byte & 0x0F];
                }
                jsonString = requestStart + "\"keyedHash\":\"" + keyedHex + "\"}";
            }
            
            for (int attempt = 0; ; ++attempt) {
                std::string response = performRequest("/files/verify-hash", "POST", jsonString, headers);
                
                if (response.empty()) {
                    if (!lastResponseRejected) lastError = "Empty response from server";
                    return false;
                }
                
                SimpleJSON responseJson;
                if (!responseJson.parse(response)) {
                    lastError = "Failed to parse verification response";
                    return false;
                }
                
                bool isValid = responseJson.getBool("valid", false);
                if (!isValid && keyed && attempt == 0 && responseJson.get("code") == "plain_hash_required") {
                    if (verifiedZk1Files.count(std::make_pair(productId, fileName))) {
                        lastError = "verify-hash: the server asked for the plain hash of an end-to-end encrypted file";
                        if (debugMode) {
                            std::cout << "[ERROR] " << lastError << std::endl;
                        }
                        return false;
                    }
                    if (debugMode) {
                        std::cout << "[DEBUG] Not an end-to-end encrypted file: checking the plain hash" << std::endl;
                    }
                    jsonString = plainRequest;
                    continue;
                }
                
                if (debugMode) {
                    std::cout << "[DEBUG] Hash verification result: " << (isValid ? "VALID" : "INVALID")
                              << (keyed && attempt == 0 ? " (keyed hash)" : "") << std::endl;
                }
                
                return isValid;
            }
            
        } catch (const std::exception& e) {
            lastError = "Exception during hash verification: " + std::string(e.what());
            return false;
        }
    }

    // ===== END NEW FILE OPERATIONS =====

    // ===== USER PRODUCTS =====

    std::vector<std::map<std::string, std::string>> VaultixClient::GetUserProducts() {
        std::vector<std::map<std::string, std::string>> products;
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return products;
        }
        if (IsTokenExpired()) {
            if (!RefreshToken()) {
                lastError = "Token expired and refresh failed";
                return products;
            }
        }
        try {
            std::map<std::string, std::string> headers;
            std::string response = performRequest("/products", "GET", "", headers);
            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response from server";
                return products;
            }
            if (debugMode) {
                std::cout << "[DEBUG] GetUserProducts response: " << response << std::endl;
            }
            if (response.front() == '[' && response.back() == ']') {
                // Remove outer array brackets
                response = response.substr(1, response.length() - 2);

                // Manual JSON array parsing
                size_t pos = 0;
                int braceCount = 0;
                size_t objStart = 0;
                bool inString = false;

                for (size_t i = 0; i < response.length(); i++) {
                    char c = response[i];

                    // Track if we're inside a string
                    if (c == '"' && (i == 0 || response[i-1] != '\\')) {
                        inString = !inString;
                    }

                    if (!inString) {
                        if (c == '{') {
                            if (braceCount == 0) {
                                objStart = i;
                            }
                            braceCount++;
                        } else if (c == '}') {
                            braceCount--;
                            if (braceCount == 0) {
                                // Found complete object
                                std::string productJson = response.substr(objStart, i - objStart + 1);

                                SimpleJSON productParser;
                                if (productParser.parse(productJson)) {
                                    std::map<std::string, std::string> product;
                                    product["id"] = productParser.get("id");
                                    product["name"] = productParser.get("name");
                                    product["description"] = productParser.get("description");
                                    product["appId"] = productParser.get("appId");
                                    product["status"] = productParser.get("status");
                                    product["fileCount"] = productParser.get("fileCount");
                                    product["subscriptionsCount"] = productParser.get("subscriptionsCount");
                                    products.push_back(product);
                                }
                            }
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            lastError = "Exception during product retrieval: " + std::string(e.what());
        }
        return products;
    }
    
    SubscriptionInfo VaultixClient::GetUserSubscriptionByProduct(const std::string& productId) {
        SubscriptionInfo subscription;
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return subscription;
        }
        if (IsTokenExpired()) {
            if (!RefreshToken()) {
                lastError = "Token expired and refresh failed";
                return subscription;
            }
        }
        
        try {
            std::map<std::string, std::string> headers;
            std::string endpoint = "/products/" + urlEncode(productId) + "/user-subscription";
            std::string response = performRequest(endpoint, "GET", "", headers);
            
            if (response.empty()) {
                // Check if it was a 404 (expected when no subscription exists)
                std::string error = lastError;
                if (error.find("HTTP Error 404") != std::string::npos) {
                    if (debugMode) {
                        std::cout << "[DEBUG] No subscription found for product: " << productId << std::endl;
                    }
                    lastError = "No subscription found for this product";
                    return subscription;
                }
                // For other errors, keep the original error message
                if (error.empty()) {
                    lastError = "Empty response from server";
                }
                return subscription;
            }
            
            if (debugMode) {
                std::cout << "[DEBUG] GetUserSubscriptionByProduct response: " << response << std::endl;
            }
            
            SimpleJSON parser;
            if (parser.parse(response)) {
                subscription.subscriptionId = parser.get("subscriptionId");
                subscription.appUserId = parser.get("appUserId");
                subscription.productId = parser.get("productId");
                subscription.status = parser.get("status");
                subscription.expiresAt = parser.get("expiresAt");
                subscription.isPaused = (parser.get("isPaused") == "true");
                subscription.pausedAt = parser.get("pausedAt");
                subscription.pausedUntil = parser.get("pausedUntil");
                subscription.downloads = std::stoi(parser.get("downloads", "0"));
                subscription.createdAt = parser.get("createdAt");
                subscription.updatedAt = parser.get("updatedAt");
            } else {
                lastError = "Failed to parse subscription response";
            }
            
        } catch (const std::exception& e) {
            lastError = "Exception during subscription retrieval: " + std::string(e.what());
        }
        
        return subscription;
    }
    
    // ===== END USER PRODUCTS =====

    // ===== PRODUCT VARIABLES =====
    std::vector<std::pair<std::string, std::string>> VaultixClient::GetProductVariables(const std::string& productId) {
        std::vector<std::pair<std::string, std::string>> vars;
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return vars;
        }
        if (IsTokenExpired()) {
            if (!RefreshToken()) {
                lastError = "Token expired and refresh failed";
                return vars;
            }
        }
        try {
            std::string appId = currentSession.appId;
            if (appId.empty()) {
                lastError = "Missing appId in session";
                return vars;
            }
            std::map<std::string, std::string> headers;
            std::string endpoint = "/apps/" + urlEncode(appId) + "/products/" + urlEncode(productId) + "/variables";
            Zk1Download zk1(*this, Zk1Download::Variables, "vars", "", productId);
            std::string response = performRequest(endpoint, "GET", "", headers, nullptr, &zk1);

            // End-to-end encrypted delivery: all values opened, or an empty list.
            if (zk1.IsDelivery()) {
                if (zk1.Succeeded()) vars.swap(zk1.variables);
                if (debugMode && zk1.Succeeded()) {
                    std::cout << "[DEBUG] GetProductVariables: " << vars.size() << " variables (values not shown)" << std::endl;
                }
                return vars;
            }

            if (response.empty()) {
                return vars;
            }
            if (debugMode) {
                std::cout << "[DEBUG] GetProductVariables response: " << response.size() << " bytes (values not shown)" << std::endl;
            }
            // Very simple parsing for array of objects with name/value
            // Expect format: [{"name":"X","value":"Y"}, ...]
            if (response.front() == '[' && response.back() == ']') {
                size_t pos = 0;
                while ((pos = response.find("\"name\"", pos)) != std::string::npos) {
                    size_t colon = response.find(':', pos);
                    size_t quote1 = response.find('"', colon + 1);
                    size_t quote2 = response.find('"', quote1 + 1);
                    std::string name = response.substr(quote1 + 1, quote2 - quote1 - 1);
                    size_t vpos = response.find("\"value\"", quote2);
                    if (vpos == std::string::npos) break;
                    size_t vcolon = response.find(':', vpos);
                    size_t vq1 = response.find('"', vcolon + 1);
                    size_t vq2 = response.find('"', vq1 + 1);
                    // A non-string value used to send this loop back to the
                    // start forever (audit H-client-6).
                    if (vq1 == std::string::npos || vq2 == std::string::npos || vq2 < pos) break;
                    std::string value = response.substr(vq1 + 1, vq2 - vq1 - 1);
                    vars.emplace_back(name, value);
                    pos = vq2 + 1;
                }
            }
        } catch (const std::exception& e) {
            lastError = "Exception during GetProductVariables: " + std::string(e.what());
        }
        return vars;
    }

    bool VaultixClient::DecryptFile(const std::string& inputPath, 
                                  const std::string& outputPath,
                                  const std::string& key,
                                  const std::string& iv) {
        try {
            std::ifstream inputFile(inputPath, std::ios::binary);
            if (!inputFile.is_open()) {
                lastError = "Failed to open input file: " + inputPath;
                return false;
            }
            
            std::vector<uint8_t> encryptedData((std::istreambuf_iterator<char>(inputFile)),
                                              std::istreambuf_iterator<char>());
            inputFile.close();
            
            std::vector<uint8_t> decryptedData = DecryptData(encryptedData, key, iv);
            
            if (decryptedData.empty()) {
                return false;
            }
            
            std::ofstream outputFile(outputPath, std::ios::binary);
            if (!outputFile.is_open()) {
                lastError = "Failed to open output file: " + outputPath;
                return false;
            }
            
            outputFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
            outputFile.close();
            
            return true;
            
        } catch (const std::exception& e) {
            lastError = "Exception during file decryption: " + std::string(e.what());
            return false;
        }
    }

    // Folder Operations
    std::vector<FolderInfo> VaultixClient::GetFolderList(const std::string& productId) {
        std::vector<FolderInfo> folders;
        
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return folders;
        }

        try {
            // Make API call to get folders
            std::string response;
            
            response = performRequest("/folders?productId=" + productId, "GET");
            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response from server";
                return folders;
            }
            
            // Parse JSON response (simplified - you might want to use a proper JSON library)
            // For now, return empty list - implement JSON parsing as needed
            if (debugMode) {
                std::cout << "[DEBUG] Folder list response: " << response.size() << " bytes" << std::endl;
            }
            
        } catch (const std::exception& e) {
            lastError = "Exception getting folder list: " + std::string(e.what());
        }
        
        return folders;
    }

    FolderInfo VaultixClient::GetFolderInfo(const std::string& productId, const std::string& folderName) {
        FolderInfo folder;
        
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return folder;
        }

        try {
            // Make API call to get folder info by name
            std::string response;
            
            std::string encodedFolderName = urlEncode(folderName);
            response = performRequest("/folders/info/" + encodedFolderName + "?productId=" + productId, "GET");
            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response from server";
                return folder;
            }
            
            if (debugMode) {
                std::cout << "[DEBUG] Folder info response: " << response.size() << " bytes (contains keys, not shown)" << std::endl;
            }
            
            // Parse JSON response and populate folder struct
            try {
                // Simple JSON parsing - extract the folder ID
                size_t idStart = response.find("\"id\":\"");
                if (idStart != std::string::npos) {
                    idStart += 6; // Skip past "id":"
                    size_t idEnd = response.find("\"", idStart);
                    if (idEnd != std::string::npos) {
                        folder.id = response.substr(idStart, idEnd - idStart);
                    }
                }
                
                // Extract folder name
                size_t nameStart = response.find("\"name\":\"");
                if (nameStart != std::string::npos) {
                    nameStart += 8; // Skip past "name":"
                    size_t nameEnd = response.find("\"", nameStart);
                    if (nameEnd != std::string::npos) {
                        folder.name = response.substr(nameStart, nameEnd - nameStart);
                    }
                }
                
                // Extract appId
                size_t appIdStart = response.find("\"appId\":\"");
                if (appIdStart != std::string::npos) {
                    appIdStart += 9; // Skip past "appId":"
                    size_t appIdEnd = response.find("\"", appIdStart);
                    if (appIdEnd != std::string::npos) {
                        folder.appId = response.substr(appIdStart, appIdEnd - appIdStart);
                    }
                }
                
                // Extract totalSize (as string, we'll parse the number part)
                size_t sizeStart = response.find("\"totalSize\":\"");
                if (sizeStart != std::string::npos) {
                    sizeStart += 13; // Skip past "totalSize":"
                    size_t sizeEnd = response.find("\"", sizeStart);
                    if (sizeEnd != std::string::npos) {
                        std::string sizeStr = response.substr(sizeStart, sizeEnd - sizeStart);
                        // Parse size like "25.5 MB" - extract the number part
                        size_t spacePos = sizeStr.find(" ");
                        if (spacePos != std::string::npos) {
                            std::string numStr = sizeStr.substr(0, spacePos);
                            folder.totalSize = static_cast<size_t>(std::stod(numStr) * 1024 * 1024); // Convert MB to bytes
                        }
                    }
                }
                
                // Extract fileCount
                size_t fileCountStart = response.find("\"fileCount\":");
                if (fileCountStart != std::string::npos) {
                    fileCountStart += 12; // Skip past "fileCount":"
                    size_t fileCountEnd = response.find(",", fileCountStart);
                    if (fileCountEnd == std::string::npos) fileCountEnd = response.find("}", fileCountStart);
                    if (fileCountEnd != std::string::npos) {
                        std::string countStr = response.substr(fileCountStart, fileCountEnd - fileCountStart);
                        folder.fileCount = std::stoi(countStr);
                    }
                }
                
                if (debugMode) {
                    std::cout << "[DEBUG] Parsed folder - ID: " << folder.id << ", Name: " << folder.name << std::endl;
                }
                
            } catch (const std::exception& e) {
                if (debugMode) {
                    std::cout << "[DEBUG] JSON parsing error: " << e.what() << std::endl;
                }
            }
            
        } catch (const std::exception& e) {
            lastError = "Exception getting folder info: " + std::string(e.what());
        }
        
        return folder;
    }

    bool VaultixClient::DownloadFolder(const std::string& productId, const std::string& folderName, const std::string& outputPath) {
        lastSignedAt = 0;
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return false;
        }

        try {
            // First get folder info to get the folder ID
            FolderInfo folder = GetFolderInfo(productId, folderName);
            if (folder.id.empty()) {
                lastError = "Folder not found: " + folderName;
                return false;
            }
            
            // Download folder using folder ID
            std::string response;
            std::string encodedFolderName = urlEncode(folderName);
            
            // Set up headers (same as file download)
            std::map<std::string, std::string> headers;
            headers["X-Product-ID"] = productId;
            
            // Get response headers to extract encryption info
            std::map<std::string, std::string> responseHeaders;
            Zk1Download zk1(*this, Zk1Download::File, "folder", folderName, productId, outputPath);
            response = performRequest("/folders/download/" + encodedFolderName + "?productId=" + productId, "GET", "", headers, &responseHeaders, &zk1);

            // End-to-end encrypted: the verified ZIP is saved as before, or nothing is.
            if (zk1.IsDelivery()) {
                if (debugMode && zk1.Succeeded()) {
                    std::cout << "[DEBUG] Saved decrypted folder to: " << outputPath << std::endl;
                }
                return zk1.Succeeded();
            }

            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response from server";
                return false;
            }

            if (debugMode) {
                std::cout << "[DEBUG] Downloaded folder: " << folderName << " from product: " << productId << std::endl;
                std::cout << "[DEBUG] Response size: " << response.size() << " bytes" << std::endl;
                std::cout << "[DEBUG] Response headers received: " << responseHeaders.size() << " headers" << std::endl;
                for (const auto& header : responseHeaders) {
                    std::cout << "[DEBUG] Header: " << redactHeaderForDebug(header.first + ": " + header.second) << std::endl;
                }
            }
            
            // Check if we have encryption headers (case-insensitive)
            std::string encryptionKey = "";
            std::string encryptionIV = "";
            
            // Look for encryption headers with different cases
            for (const auto& header : responseHeaders) {
                std::string key = header.first;
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                
                if (key == "x-encryption-key") {
                    encryptionKey = header.second;
                } else if (key == "x-encryption-iv") {
                    encryptionIV = header.second;
                }
            }
            
            // Vaultix always encrypts downloads. Never save a body that arrived
            // without an encryption key (the IV is embedded in the data).
            if (encryptionKey.empty()) {
                lastError = "Missing encryption key in response headers; refusing unencrypted folder data";
                return false;
            }

            if (debugMode) {
                std::cout << "[DEBUG] Encryption key received (not shown)" << std::endl;
            }

            // Convert response to bytes (contains SALT + IV + TAG + CIPHERTEXT for AES-GCM)
            std::vector<uint8_t> encryptedData(response.begin(), response.end());

            // Decrypt the data using AES-GCM (IV is embedded in the data)
            std::vector<uint8_t> decryptedData = DecryptData(encryptedData, encryptionKey, "");

            if (decryptedData.empty()) {
                lastError = "Failed to decrypt folder: " + GetLastError();
                return false;
            }

            // Save decrypted data to file
            std::ofstream outFile(outputPath, std::ios::binary);
            if (!outFile) {
                lastError = "Failed to open output file: " + outputPath;
                return false;
            }

            outFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
            outFile.close();

            if (debugMode) {
                std::cout << "[DEBUG] Saved decrypted folder to: " << outputPath << std::endl;
            }

            return true;
            
        } catch (const std::exception& e) {
            lastError = "Exception during folder download: " + std::string(e.what());
            return false;
        }
    }

    std::vector<uint8_t> VaultixClient::DownloadFolderToMemory(const std::string& productId, const std::string& folderName) {
        std::vector<uint8_t> folderData;
        lastSignedAt = 0;
        
        if (!currentSession.isValid) {
            lastError = "No valid session";
            return folderData;
        }

        try {
            // First get folder info to get the folder ID
            FolderInfo folder = GetFolderInfo(productId, folderName);
            if (folder.id.empty()) {
                lastError = "Folder not found: " + folderName;
                return folderData;
            }
            
            // Download folder using folder ID
            std::string response;
            std::string encodedFolderName = urlEncode(folderName);
            
            std::map<std::string, std::string> responseHeaders;
            Zk1Download zk1(*this, Zk1Download::Memory, "folder", folderName, productId);
            response = performRequest("/folders/download/" + encodedFolderName + "?productId=" + productId, "GET", "", {}, &responseHeaders, &zk1);

            // End-to-end encrypted: verified and decrypted in memory, or nothing.
            if (zk1.IsDelivery()) {
                if (zk1.Succeeded()) folderData.swap(zk1.memory);
                return folderData;
            }

            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response from server";
                return folderData;
            }

            if (debugMode) {
                std::cout << "[DEBUG] Downloaded folder to memory: " << folderName << " from product: " << productId << std::endl;
            }

            // The archive is AES-GCM encrypted; decrypt it like DownloadFolder()
            // and never return a body that arrived without an encryption key.
            std::string encryptionKey;
            for (const auto& header : responseHeaders) {
                std::string key = header.first;
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                if (key == "x-encryption-key") {
                    encryptionKey = header.second;
                }
            }
            if (encryptionKey.empty()) {
                lastError = "Missing encryption key in response headers; refusing unencrypted folder data";
                return folderData;
            }
            std::vector<uint8_t> encryptedData(response.begin(), response.end());
            folderData = DecryptData(encryptedData, encryptionKey, "");
            if (folderData.empty()) {
                lastError = "Failed to decrypt folder: " + GetLastError();
            }
            
        } catch (const std::exception& e) {
            lastError = "Exception during folder download: " + std::string(e.what());
        }
        
        return folderData;
    }

    // ========== SECURITY HELPER FUNCTIONS ==========

    std::string VaultixClient::signRequest(const std::string& method, const std::string& endpoint,
                                          const std::string& body, const std::string& timestamp) {
        // Create signature string: METHOD|ENDPOINT|BODY|TIMESTAMP
        std::string toSign = method + "|" + endpoint + "|" + body + "|" + timestamp;

        // Sign using HMAC-SHA256
        unsigned char digest[32];
        unsigned int digest_len = 0;

        HMAC(EVP_sha256(),
             requestSigningKey.c_str(), requestSigningKey.length(),
             reinterpret_cast<const unsigned char*>(toSign.c_str()), toSign.length(),
             digest, &digest_len);

        // Convert to hex string
        std::stringstream ss;
        for (unsigned int i = 0; i < digest_len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
        }

        return ss.str();
    }

    // SSL certificate verify callback for certificate pinning
    // Note: This uses a static pointer to access pinning data (not thread-safe, but works for single-threaded use)
    static int sslVerifyCallback(int preverify_ok, X509_STORE_CTX* ctx) {

        // Get the certificate chain depth
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        
        // Only check the peer certificate (depth 0)
        if (depth != 0) {
            return preverify_ok; // Allow intermediate certificates through
        }

        // If no pinning data is set, use default verification
        if (!g_currentPinData || !g_currentPinData->pins || g_currentPinData->pins->empty()) {
            return preverify_ok;
        }

        // Get the certificate being verified
        X509* cert = X509_STORE_CTX_get_current_cert(ctx);
        if (!cert) {
            return preverify_ok;
        }

        // Get the public key
        EVP_PKEY* pubkey = X509_get_pubkey(cert);
        if (!pubkey) {
            return preverify_ok;
        }

        // Compute SHA-256 hash of the public key
        unsigned char hash[SHA256_DIGEST_LENGTH];
        unsigned char* der = nullptr;
        int der_len = i2d_PUBKEY(pubkey, &der);

        if (der_len > 0) {
            SHA256(der, der_len, hash);

            // Convert hash to hex string
            std::stringstream ss;
            for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[j]);
            }
            std::string certHash = ss.str();

            if (*g_currentPinData->debugMode) {
                std::cout << "[DEBUG] Certificate hash: " << certHash << std::endl;
            }

            // Check if this hash matches any of our pins
            for (const auto& pin : *g_currentPinData->pins) {
                if (certHash == pin) {
                    if (*g_currentPinData->debugMode) {
                        std::cout << "[DEBUG] Certificate pin matched!" << std::endl;
                    }
                    OPENSSL_free(der);
                    EVP_PKEY_free(pubkey);
                    return 1; // Pin matched, allow connection
                }
            }

            OPENSSL_free(der);
        }

        EVP_PKEY_free(pubkey);

        // If we get here, no pin matched
        *g_currentPinData->lastError = "Certificate pinning failed - no matching certificate found";
        if (*g_currentPinData->debugMode) {
            std::cout << "[ERROR] " << *g_currentPinData->lastError << std::endl;
        }
        return 0; // Fail verification
    }

    CURLcode VaultixClient::sslContextCallback(CURL* curl, void* sslctx, void* parm) {
        // Certificate pinning implementation using SSL verify callback
        PinningData* pinData = static_cast<PinningData*>(parm);
        SSL_CTX* ctx = static_cast<SSL_CTX*>(sslctx);

        // Set up certificate verification callback for certificate pinning
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, sslVerifyCallback);
        
        // Store pinning data in global static variable for the verify callback to access
        // Note: This is not thread-safe, but works for the single-threaded use case
        g_currentPinData = pinData;
        
        return CURLE_OK;
    }

    bool VaultixClient::verifyCertificatePin(const std::string& certHash) {
        for (const auto& pin : pinnedCertificates) {
            if (pin == certHash) {
                return true;
            }
        }
        return false;
    }

    // ========== END SECURITY HELPER FUNCTIONS ==========

    bool VaultixClient::GetProductStatus(const std::string& productId, ProductStatusInfo& statusInfo) {
        statusInfo = ProductStatusInfo{};

        try {
            std::string endpoint = "/api/products/" + productId + "/status";
            std::string response = performRequest(endpoint, "GET");

            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response when fetching product status";
                return false;
            }

            std::string statusObject = ExtractJsonObjectValue(response, "status");
            if (statusObject.empty()) {
                statusInfo.hasStatus = false;
                return true;
            }

            statusInfo.hasStatus = true;
            statusInfo.name = ExtractJsonStringValue(statusObject, "name");
            statusInfo.color = ExtractJsonStringValue(statusObject, "color");
            statusInfo.action = ExtractJsonStringValue(statusObject, "action");

            return true;
        } catch (const std::exception& ex) {
            lastError = "Failed to fetch product status: " + std::string(ex.what());
            return false;
        }
    }

    bool VaultixClient::GetProductNews(const std::string& productId, ProductNewsInfo& newsInfo) {
        newsInfo = ProductNewsInfo{};

        try {
            std::string endpoint = "/api/products/" + productId + "/news";
            std::string response = performRequest(endpoint, "GET");

            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response when fetching product news";
                return false;
            }

            std::string newsObject = ExtractJsonObjectValue(response, "news");
            if (newsObject.empty()) {
                newsInfo.hasNews = false;
                return true;
            }

            newsInfo.hasNews = true;
            newsInfo.headline = ExtractJsonStringValue(newsObject, "headline");
            newsInfo.content = ExtractJsonStringValue(newsObject, "content");
            newsInfo.updatedAt = ExtractJsonStringValue(newsObject, "updatedAt");

            return true;
        } catch (const std::exception& ex) {
            lastError = "Failed to fetch product news: " + std::string(ex.what());
            return false;
        }
    }

    bool VaultixClient::GetAccountInfo(AccountInfo& accountInfo) {
        accountInfo = AccountInfo{};

        if (!currentSession.isValid) {
            lastError = "No valid session";
            return false;
        }
        if (IsTokenExpired()) {
            if (!RefreshToken()) {
                lastError = "Token expired and refresh failed";
                return false;
            }
        }

        try {
            // No identity in the request: the server derives the user from the
            // session token, so this can only ever return your own info.
            std::string response = performRequest("/me", "GET");

            if (response.empty()) {
                if (!lastResponseRejected) lastError = "Empty response when fetching account info";
                return false;
            }

            // Both fields may legitimately be null/empty (no display name set,
            // or no note written by the app owner).
            accountInfo.username = ExtractJsonStringValue(response, "username");
            accountInfo.note = ExtractJsonStringValue(response, "note");

            return true;
        } catch (const std::exception& ex) {
            lastError = "Failed to fetch account info: " + std::string(ex.what());
            return false;
        }
    }

} // namespace Vaultix
