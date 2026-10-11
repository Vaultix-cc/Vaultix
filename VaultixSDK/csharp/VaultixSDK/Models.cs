namespace Vaultix.SDK
{
    /// <summary>
    /// Represents a file stored in the Vaultix system
    /// </summary>
    public class FileInfo
    {
        /// <summary>File ID</summary>
        public string Id { get; set; } = string.Empty;
        /// <summary>File name</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>ID of the app the file belongs to</summary>
        public string AppId { get; set; } = string.Empty;
        /// <summary>Size in bytes</summary>
        public long Size { get; set; }
        /// <summary>Whether the file is stored encrypted</summary>
        public bool Encrypted { get; set; }
        /// <summary>Server-held key of a file without end-to-end encryption (empty for end-to-end encrypted files)</summary>
        public string? EncryptionKey { get; set; }
        /// <summary>Server-held IV of a file without end-to-end encryption</summary>
        public string? EncryptionIV { get; set; }
        /// <summary>"zk1" for an end-to-end encrypted file, otherwise null</summary>
        public string? Enc { get; set; }
        /// <summary>Download count</summary>
        public int Downloads { get; set; }
        /// <summary>Upload time as sent by the server</summary>
        public string UploadedAt { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents a folder stored in the Vaultix system
    /// </summary>
    public class FolderInfo
    {
        /// <summary>Folder ID</summary>
        public string Id { get; set; } = string.Empty;
        /// <summary>Folder name</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>ID of the app the folder belongs to</summary>
        public string AppId { get; set; } = string.Empty;
        /// <summary>Total size in bytes (the server sends a rounded, formatted size)</summary>
        public long TotalSize { get; set; }
        /// <summary>Number of files in the folder</summary>
        public int FileCount { get; set; }
        /// <summary>Download count</summary>
        public int Downloads { get; set; }
        /// <summary>Upload time as sent by the server</summary>
        public string UploadedAt { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents an authenticated user within an application
    /// </summary>
    public class AppUser
    {
        /// <summary>App user ID</summary>
        public string Id { get; set; } = string.Empty;
        /// <summary>App ID</summary>
        public string AppId { get; set; } = string.Empty;
        /// <summary>Username (username/password login), otherwise null</summary>
        public string? Username { get; set; }
        /// <summary>License key (key login), otherwise null</summary>
        public string? Key { get; set; }
        /// <summary>Product IDs the user had a subscription to at login</summary>
        public List<string> Subscriptions { get; set; } = new();
    }

    /// <summary>
    /// Represents a user's subscription to a product
    /// </summary>
    public class SubscriptionInfo
    {
        /// <summary>Subscription ID (empty if there is none)</summary>
        public string SubscriptionId { get; set; } = string.Empty;
        /// <summary>App user ID</summary>
        public string AppUserId { get; set; } = string.Empty;
        /// <summary>Product ID</summary>
        public string ProductId { get; set; } = string.Empty;
        /// <summary>"active", "paused" or "expired"</summary>
        public string Status { get; set; } = string.Empty;
        /// <summary>Expiry time, null for a lifetime subscription</summary>
        public string? ExpiresAt { get; set; }
        /// <summary>Whether the subscription is paused</summary>
        public bool IsPaused { get; set; }
        /// <summary>When it was paused</summary>
        public string? PausedAt { get; set; }
        /// <summary>Until when it is paused</summary>
        public string? PausedUntil { get; set; }
        /// <summary>Download count</summary>
        public int Downloads { get; set; }
        /// <summary>Creation time</summary>
        public string CreatedAt { get; set; } = string.Empty;
        /// <summary>Last update time</summary>
        public string UpdatedAt { get; set; } = string.Empty;

        /// <summary>
        /// Checks if the subscription is active (not paused, not expired)
        /// </summary>
        public bool IsActive => !IsPaused && (string.IsNullOrEmpty(ExpiresAt) || Status == "active");

        /// <summary>
        /// Checks if the subscription is lifetime (no expiration)
        /// </summary>
        public bool IsLifetime => string.IsNullOrEmpty(ExpiresAt);
    }

    /// <summary>
    /// Represents an active session with the Vaultix API
    /// </summary>
    public class Session
    {
        /// <summary>Hardware ID sent at login</summary>
        public string Hwid { get; set; } = string.Empty;
        /// <summary>Session token (Bearer)</summary>
        public string SessionToken { get; set; } = string.Empty;
        /// <summary>Session ID</summary>
        public string SessionId { get; set; } = string.Empty;
        /// <summary>Whether the client is signed in</summary>
        public bool IsValid { get; set; }
        /// <summary>App ID (part of every end-to-end encryption signature check)</summary>
        public string AppId { get; set; } = string.Empty;
        /// <summary>The signed-in user</summary>
        public AppUser AppUser { get; set; } = new();
        /// <summary>Token expiry as sent by the server</summary>
        public string? TokenExpiry { get; set; }
        /// <summary>App API key used for this session</summary>
        public string AppApiKey { get; set; } = string.Empty;
    }

    /// <summary>
    /// Product status information
    /// </summary>
    public class ProductStatusInfo
    {
        /// <summary>Whether the product has a status set</summary>
        public bool HasStatus { get; set; }
        /// <summary>Status name</summary>
        public string Name { get; set; } = string.Empty;
        /// <summary>Status color</summary>
        public string Color { get; set; } = string.Empty;
        /// <summary>Action text for the status</summary>
        public string Action { get; set; } = string.Empty;
    }

    /// <summary>
    /// Cosmetic profile of the signed-in user (display strings only)
    /// </summary>
    public class AccountInfo
    {
        /// <summary>Display name in key mode, username in username/password mode</summary>
        public string Username { get; set; } = string.Empty;
        /// <summary>Free-text note the app owner set on this user</summary>
        public string Note { get; set; } = string.Empty;
    }

    /// <summary>
    /// Product news/announcement information
    /// </summary>
    public class ProductNewsInfo
    {
        /// <summary>Whether the product has news</summary>
        public bool HasNews { get; set; }
        /// <summary>Headline</summary>
        public string Headline { get; set; } = string.Empty;
        /// <summary>Content</summary>
        public string Content { get; set; } = string.Empty;
        /// <summary>Last update time</summary>
        public string UpdatedAt { get; set; } = string.Empty;
    }
}
