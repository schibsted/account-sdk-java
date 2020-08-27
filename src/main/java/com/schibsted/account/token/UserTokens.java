/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.token;

/**
 * Grouping of all user tokens issued on successful user authentication.
 */
public class UserTokens {
    private AccessToken accessToken;
    private RefreshToken refreshToken;
    private IDToken idToken;

    public UserTokens(IDToken idToken, AccessToken accessToken, RefreshToken refreshToken) {
        if (accessToken == null) {
            throw new IllegalArgumentException("accessToken may not be null");
        }
        this.idToken = idToken;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    public IDToken getIDToken() {
        return idToken;
    }
}
