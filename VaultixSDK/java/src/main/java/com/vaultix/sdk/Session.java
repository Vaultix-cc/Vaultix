package com.vaultix.sdk;

/**
 * Represents an active session with the Vaultix API
 */
public class Session {
    private String hwid = "";
    private String sessionToken = "";
    private String sessionId = "";
    private boolean isValid = false;
    private String appId = "";
    private AppUser appUser = new AppUser();
    private String tokenExpiry;
    private String appApiKey = "";

    public Session() {}

    public String getHwid() { return hwid; }
    public void setHwid(String hwid) { this.hwid = hwid; }

    public String getSessionToken() { return sessionToken; }
    public void setSessionToken(String sessionToken) { this.sessionToken = sessionToken; }

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }

    public boolean isValid() { return isValid; }
    public void setValid(boolean valid) { isValid = valid; }

    public String getAppId() { return appId; }
    public void setAppId(String appId) { this.appId = appId; }

    public AppUser getAppUser() { return appUser; }
    public void setAppUser(AppUser appUser) { this.appUser = appUser; }

    public String getTokenExpiry() { return tokenExpiry; }
    public void setTokenExpiry(String tokenExpiry) { this.tokenExpiry = tokenExpiry; }

    public String getAppApiKey() { return appApiKey; }
    public void setAppApiKey(String appApiKey) { this.appApiKey = appApiKey; }
}
