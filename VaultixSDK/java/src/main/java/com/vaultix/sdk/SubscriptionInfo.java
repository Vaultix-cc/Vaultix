package com.vaultix.sdk;

/**
 * Represents a user's subscription to a product
 */
public class SubscriptionInfo {
    private String subscriptionId = "";
    private String appUserId = "";
    private String productId = "";
    private String status = "";
    private String expiresAt;
    private boolean isPaused = false;
    private String pausedAt;
    private String pausedUntil;
    private int downloads = 0;
    private String createdAt = "";
    private String updatedAt = "";

    public SubscriptionInfo() {}

    public String getSubscriptionId() { return subscriptionId; }
    public void setSubscriptionId(String subscriptionId) { this.subscriptionId = subscriptionId; }

    public String getAppUserId() { return appUserId; }
    public void setAppUserId(String appUserId) { this.appUserId = appUserId; }

    public String getProductId() { return productId; }
    public void setProductId(String productId) { this.productId = productId; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getExpiresAt() { return expiresAt; }
    public void setExpiresAt(String expiresAt) { this.expiresAt = expiresAt; }

    public boolean isPaused() { return isPaused; }
    public void setPaused(boolean paused) { isPaused = paused; }

    public String getPausedAt() { return pausedAt; }
    public void setPausedAt(String pausedAt) { this.pausedAt = pausedAt; }

    public String getPausedUntil() { return pausedUntil; }
    public void setPausedUntil(String pausedUntil) { this.pausedUntil = pausedUntil; }

    public int getDownloads() { return downloads; }
    public void setDownloads(int downloads) { this.downloads = downloads; }

    public String getCreatedAt() { return createdAt; }
    public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }

    public String getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(String updatedAt) { this.updatedAt = updatedAt; }

    /**
     * Check if the subscription is active (not paused, not expired)
     */
    public boolean isActive() {
        return !isPaused && (expiresAt == null || "active".equals(status));
    }

    /**
     * Check if the subscription is lifetime (no expiration)
     */
    public boolean isLifetime() {
        return expiresAt == null || expiresAt.isEmpty();
    }
}
