package com.vaultix.sdk;

/**
 * Represents a folder stored in the Vaultix system
 */
public class FolderInfo {
    private String id = "";
    private String name = "";
    private String appId = "";
    private long totalSize = 0;
    private int fileCount = 0;
    private int downloads = 0;
    private String uploadedAt = "";

    public FolderInfo() {}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getAppId() { return appId; }
    public void setAppId(String appId) { this.appId = appId; }

    public long getTotalSize() { return totalSize; }
    public void setTotalSize(long totalSize) { this.totalSize = totalSize; }

    public int getFileCount() { return fileCount; }
    public void setFileCount(int fileCount) { this.fileCount = fileCount; }

    public int getDownloads() { return downloads; }
    public void setDownloads(int downloads) { this.downloads = downloads; }

    public String getUploadedAt() { return uploadedAt; }
    public void setUploadedAt(String uploadedAt) { this.uploadedAt = uploadedAt; }
}
