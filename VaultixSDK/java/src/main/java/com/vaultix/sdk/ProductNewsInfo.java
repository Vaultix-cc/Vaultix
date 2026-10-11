package com.vaultix.sdk;

/**
 * Product news/announcement information
 */
public class ProductNewsInfo {
    private boolean hasNews = false;
    private String headline = "";
    private String content = "";
    private String updatedAt = "";

    public ProductNewsInfo() {}

    public boolean hasNews() { return hasNews; }
    public void setHasNews(boolean hasNews) { this.hasNews = hasNews; }

    public String getHeadline() { return headline; }
    public void setHeadline(String headline) { this.headline = headline; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public String getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(String updatedAt) { this.updatedAt = updatedAt; }
}
