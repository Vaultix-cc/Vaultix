#include "VaultixSDK.hpp"
#include <curl/curl.h>
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
#include <cstdio>

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
        
        bool parse(const std::string& json) {
            // Very basic JSON parsing - only for simple key-value pairs
            std::string cleanJson = json;
            
            // Remove whitespace and braces
            cleanJson.erase(std::remove_if(cleanJson.begin(), cleanJson.end(), ::isspace), cleanJson.end());
            if (cleanJson.front() == '{') cleanJson = cleanJson.substr(1);
            if (cleanJson.back() == '}') cleanJson = cleanJson.substr(0, cleanJson.length() - 1);
            
            // Parse key-value pairs
            std::stringstream ss(cleanJson);
            std::string pair;
            
            while (std::getline(ss, pair, ',')) {
                size_t colonPos = pair.find(':');
                if (colonPos != std::string::npos) {
                    std::string key = pair.substr(0, colonPos);
                    std::string value = pair.substr(colonPos + 1);
                    
                    // Remove quotes
                    if (key.front() == '"') key = key.substr(1);
                    if (key.back() == '"') key = key.substr(0, key.length() - 1);
                    if (value.front() == '"') value = value.substr(1);
                    if (value.back() == '"') value = value.substr(0, value.length() - 1);
                    
                    data[key] = value;
                }
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

    // Curl callback implementations
    size_t VaultixClient::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    // Header callback for extracting response headers
    struct HeaderCallbackData {
        std::map<std::string, std::string>* headers;
    };

    size_t HeaderCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        HeaderCallbackData* data = (HeaderCallbackData*)userp;
        if (!data || !data->headers) return size * nmemb;

        std::string header((char*)contents, size * nmemb);

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

            (*data->headers)[headerName] = headerValue;
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
          minTlsVersion("1.2"), requestSigningEnabled(false) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        currentSession.isValid = false;
    }

    VaultixClient::~VaultixClient() {
        curl_global_cleanup();
    }

    std::string VaultixClient::performRequest(const std::string& endpoint,
                                           const std::string& method,
                                           const std::string& postData,
                                           std::map<std::string, std::string> headers,
                                           std::map<std::string, std::string>* responseHeaders) {
        CURL* curl;
        CURLcode res;
        std::string readBuffer;

        curl = curl_easy_init();
        if(curl) {
            std::string url = baseUrl + endpoint;

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
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

            // Setup header callback if responseHeaders is provided
            HeaderCallbackData headerCallbackData;
            if (responseHeaders) {
                headerCallbackData.headers = responseHeaders;
                curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
                curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headerCallbackData);
            }

            // Set headers
            struct curl_slist* headerList = nullptr;
            headerList = curl_slist_append(headerList, "Content-Type: application/json");

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

            // Debug output
            if (debugMode) {
                std::cout << "[DEBUG] " << method << " " << url << std::endl;
                if (!postData.empty()) {
                    std::cout << "[DEBUG] Data: " << postData << std::endl;
                }
                // Debug headers
                struct curl_slist* debugHeader = headerList;
                while (debugHeader) {
                    std::cout << "[DEBUG] Header: " << debugHeader->data << std::endl;
                    debugHeader = debugHeader->next;
                }
            }

            res = curl_easy_perform(curl);

            if (res != CURLE_OK) {
                lastError = "Curl error: " + std::string(curl_easy_strerror(res));
                if (debugMode) {
                    std::cout << "[ERROR] " << lastError << std::endl;
                }
            }

            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (debugMode) {
                std::cout << "[DEBUG] Response Code: " << response_code << std::endl;
                std::cout << "[DEBUG] Response size: " << readBuffer.size() << " bytes" << std::endl;
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

    bool VaultixClient::AuthenticateWithUsername(const std::string& username, const std::string& password) {
        try {
            // Get HWID
            std::string hwid = getHWID();
            
            // Create JSON request with HWID
            std::string jsonString = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"hwid\":\"" + hwid + "\"}";
            
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
            
            // Create JSON request with HWID
            std::string jsonString = "{\"key\":\"" + userKey + "\",\"hwid\":\"" + hwid + "\"}";
            
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

            // Create JSON request with token and HWID
            std::string jsonString = "{\"token\":\"" + persistentToken + "\",\"hwid\":\"" + hwid + "\"}";

            // Call auto-login endpoint with response headers to capture debug info
            std::map<std::string, std::string> responseHeaders;
            std::string response = performRequest("/app_auth/autologin", "POST", jsonString, {}, &responseHeaders);

            if (response.empty()) {
                // Check if we have debug info from server
                if (lastError.empty()) {
                    lastError = "Empty response from server";
                }
                DeletePersistentToken(apiKeyToUse);  // Delete invalid token
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
        currentSession.hwid.clear();
        currentSession.appId.clear();
        currentSession.tokenExpiry.clear();
        // Clear API key from session
        if (!currentSession.appApiKey.empty()) {
            std::fill(currentSession.appApiKey.begin(), currentSession.appApiKey.end(), 0);
        }
        currentSession.appApiKey.clear();
        currentSession.appUser = AppUser{};

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
                    std::cout << "[DEBUG] Using API key from session: " << (apiKeyToUse.empty() ? "EMPTY" : apiKeyToUse.substr(0, 10) + "...") << std::endl;
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
                lastError = "Empty response from server";
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

            if (debugMode) {
                std::cout << "[DEBUG] Extracted JTI: " << jti << std::endl;
            }

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

            if (debugMode) {
                std::cout << "[DEBUG] Transport key (first 16 bytes): ";
                for (size_t i = 0; i < 16; i++) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)transport_key[i] << " ";
                }
                std::cout << std::dec << std::endl;
            }

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
                std::cout << "[DEBUG] Decrypted header value: " << result.substr(0, 20) << "..." << std::endl;
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
                std::cout << "[DEBUG] Key: " << key << std::endl;
                std::cout << "[DEBUG] Starting AES-256-GCM decryption..." << std::endl;
            }

            // For AES-256-GCM, the encrypted data contains: IV(12) + TAG(16) + CIPHERTEXT
            if (encryptedData.size() < 28) {  // IV(12) + TAG(16) = 28 bytes minimum
                lastError = "Invalid encrypted data size for AES-GCM";
                return decryptedData;
            }

            // Extract IV, tag, and ciphertext from the encrypted data
            std::vector<uint8_t> iv_bytes(encryptedData.begin(), encryptedData.begin() + 12);
            std::vector<uint8_t> tag(encryptedData.begin() + 12, encryptedData.begin() + 28);
            std::vector<uint8_t> ciphertext(encryptedData.begin() + 28, encryptedData.end());

            if (debugMode) {
                std::cout << "[DEBUG] IV size: " << iv_bytes.size() << " bytes" << std::endl;
                std::cout << "[DEBUG] Tag size: " << tag.size() << " bytes" << std::endl;
                std::cout << "[DEBUG] Ciphertext size: " << ciphertext.size() << " bytes" << std::endl;
            }

            // Derive encryption key from provided key using PBKDF2 (same as server)
            std::vector<uint8_t> salt = {'v', 'a', 'u', 'l', 't', 'i', 'x', '_', 's', 'a', 'l', 't', '_', '2', '0', '2', '4'};
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
            std::string response = performRequest("/files/download/" + encodedFileName + "?productId=" + productId, "GET", "", headers, &responseHeaders);
            
            if (response.empty()) {
                lastError = "Empty response when downloading file";
                return false;
            }
            
            // Extract encryption key from headers (IV is embedded in AES-GCM data)
            std::string encryptionKey = responseHeaders["x-encryption-key"];
            
            if (encryptionKey.empty()) {
                lastError = "Missing encryption key in response headers";
                return false;
            }
            
            if (debugMode) {
                std::cout << "[DEBUG] Encryption Key: " << encryptionKey << std::endl;
            }
            
            // Use the full key as provided (don't strip enc_key_ prefix)
            std::string cleanKey = encryptionKey;
            
            if (debugMode) {
                std::cout << "[DEBUG] Clean Key: " << cleanKey << std::endl;
            }
            
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
            std::string response = performRequest("/files/download/" + encodedFileName + "?productId=" + productId, "GET", "", headers, &responseHeaders);
            
            if (!response.empty()) {
                // Extract encryption key from headers (IV is embedded in AES-GCM data)
                std::string encryptionKey = responseHeaders["x-encryption-key"];
                
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
                    // If no encryption info, use raw data
                    data.assign(response.begin(), response.end());
                }
            }
            
        } catch (const std::exception& e) {
            lastError = "Exception during file download: " + std::string(e.what());
        }
        
        return data;
    }

    bool VaultixClient::StreamFile(const std::string& productId, const std::string& fileName,
                                 std::function<void(const std::vector<uint8_t>&, size_t, size_t)> callback) {
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
            std::string jsonString = "{\"productId\":\"" + jsonEscape(productId) + 
                                    "\",\"fileName\":\"" + jsonEscape(fileName) + 
                                    "\",\"hash\":\"" + jsonEscape(fileHash) + "\"}";
            
            std::string response = performRequest("/files/verify-hash", "POST", jsonString, headers);
            
            if (response.empty()) {
                lastError = "Empty response from server";
                return false;
            }
            
            SimpleJSON responseJson;
            if (!responseJson.parse(response)) {
                lastError = "Failed to parse verification response";
                return false;
            }
            
            bool isValid = responseJson.getBool("valid", false);
            
            if (debugMode) {
                std::cout << "[DEBUG] Hash verification result: " << (isValid ? "VALID" : "INVALID") << std::endl;
            }
            
            return isValid;
            
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
                lastError = "Empty response from server";
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
            std::string response = performRequest(endpoint, "GET", "", headers);
            if (response.empty()) {
                return vars;
            }
            if (debugMode) {
                std::cout << "[DEBUG] GetProductVariables response: " << response << std::endl;
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
                lastError = "Empty response from server";
                return folders;
            }
            
            // Parse JSON response (simplified - you might want to use a proper JSON library)
            // For now, return empty list - implement JSON parsing as needed
            if (debugMode) {
                std::cout << "[DEBUG] Folder list response: " << response << std::endl;
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
                lastError = "Empty response from server";
                return folder;
            }
            
            if (debugMode) {
                std::cout << "[DEBUG] Folder info response: " << response << std::endl;
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
            response = performRequest("/folders/download/" + encodedFolderName + "?productId=" + productId, "GET", "", headers, &responseHeaders);
            if (response.empty()) {
                lastError = "Empty response from server";
                return false;
            }
            
            if (debugMode) {
                std::cout << "[DEBUG] Downloaded folder: " << folderName << " from product: " << productId << std::endl;
                std::cout << "[DEBUG] Response size: " << response.size() << " bytes" << std::endl;
                std::cout << "[DEBUG] Response headers received: " << responseHeaders.size() << " headers" << std::endl;
                for (const auto& header : responseHeaders) {
                    std::cout << "[DEBUG] Header: " << header.first << " = " << header.second << std::endl;
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
            
            if (!encryptionKey.empty() && !encryptionIV.empty()) {
                
                if (debugMode) {
                    std::cout << "[DEBUG] Encryption Key: " << encryptionKey << std::endl;
                    std::cout << "[DEBUG] Encryption IV: " << encryptionIV << std::endl;
                }
                
                // Convert response to bytes (contains IV + TAG + CIPHERTEXT for AES-GCM)
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
                
            } else {
                // If no encryption info, save raw data
                if (debugMode) {
                    std::cout << "[DEBUG] No encryption headers found - saving raw data" << std::endl;
                    std::cout << "[DEBUG] Encryption Key found: " << (encryptionKey.empty() ? "NO" : "YES") << std::endl;
                    std::cout << "[DEBUG] Encryption IV found: " << (encryptionIV.empty() ? "NO" : "YES") << std::endl;
                }
                
                std::ofstream file(outputPath, std::ios::binary);
                if (!file.is_open()) {
                    lastError = "Failed to create output file: " + outputPath;
                    return false;
                }
                
                file.write(response.c_str(), response.size());
                file.close();
                
                if (debugMode) {
                    std::cout << "[DEBUG] Saved raw folder to: " << outputPath << std::endl;
                }
            }
            
            return true;
            
        } catch (const std::exception& e) {
            lastError = "Exception during folder download: " + std::string(e.what());
            return false;
        }
    }

    std::vector<uint8_t> VaultixClient::DownloadFolderToMemory(const std::string& productId, const std::string& folderName) {
        std::vector<uint8_t> folderData;
        
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
            
            response = performRequest("/folders/download/" + encodedFolderName + "?productId=" + productId, "GET");
            if (response.empty()) {
                lastError = "Empty response from server";
                return folderData;
            }
            
            if (debugMode) {
                std::cout << "[DEBUG] Downloaded folder to memory: " << folderName << " from product: " << productId << std::endl;
            }
            
            // Convert response to bytes
            folderData.assign(response.begin(), response.end());
            
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
                lastError = "Empty response when fetching product status";
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
                lastError = "Empty response when fetching product news";
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

} // namespace Vaultix
