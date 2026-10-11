package com.vaultix.sdk;

/**
 * Cosmetic profile of whoever the session is logged in as (GET /me). Display
 * strings only: no key, email, HWID or ids.
 */
public class AccountInfo {
    private String username = "";
    private String note = "";

    public AccountInfo() {}

    /** Display name in key mode, username in username/password mode; "" if none. */
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username == null ? "" : username; }

    /** Free-text note the app owner set on this user; "" if none. */
    public String getNote() { return note; }
    public void setNote(String note) { this.note = note == null ? "" : note; }
}
