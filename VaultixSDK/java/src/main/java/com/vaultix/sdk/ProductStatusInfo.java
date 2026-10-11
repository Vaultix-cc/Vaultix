package com.vaultix.sdk;

/**
 * Product status information
 */
public class ProductStatusInfo {
    private boolean hasStatus = false;
    private String name = "";
    private String color = "";
    private String action = "";

    public ProductStatusInfo() {}

    public boolean hasStatus() { return hasStatus; }
    public void setHasStatus(boolean hasStatus) { this.hasStatus = hasStatus; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getColor() { return color; }
    public void setColor(String color) { this.color = color; }

    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
}
