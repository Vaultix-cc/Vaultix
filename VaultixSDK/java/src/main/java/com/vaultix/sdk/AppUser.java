package com.vaultix.sdk;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents an authenticated user within an application
 */
public class AppUser {
    private String id = "";
    private String appId = "";
    private String username;
    private String key;
    private List<String> subscriptions = new ArrayList<>();

    public AppUser() {}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getAppId() { return appId; }
    public void setAppId(String appId) { this.appId = appId; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getKey() { return key; }
    public void setKey(String key) { this.key = key; }

    public List<String> getSubscriptions() { return subscriptions; }
    public void setSubscriptions(List<String> subscriptions) { this.subscriptions = subscriptions; }
}
