package com.vaultix.sdk;

/**
 * Represents a file stored in the Vaultix system
 */
public class FileInfo {
    private String id = "";
    private String name = "";
    private String appId = "";
    private long size = 0;
    private boolean encrypted = false;
    private String encryptionKey;
    private String encryptionIv;
    private int downloads = 0;
    private String uploadedAt = "";

    public FileInfo() {}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getAppId() { return appId; }
    public void setAppId(String appId) { this.appId = appId; }

    public long getSize() { return size; }
    public void setSize(long size) { this.size = size; }

    public boolean isEncrypted() { return encrypted; }
    public void setEncrypted(boolean encrypted) { this.encrypted = encrypted; }

    public String getEncryptionKey() { return encryptionKey; }
    public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }

    public String getEncryptionIv() { return encryptionIv; }
    public void setEncryptionIv(String encryptionIv) { this.encryptionIv = encryptionIv; }

    public int getDownloads() { return downloads; }
    public void setDownloads(int downloads) { this.downloads = downloads; }

    public String getUploadedAt() { return uploadedAt; }
    public void setUploadedAt(String uploadedAt) { this.uploadedAt = uploadedAt; }
}
