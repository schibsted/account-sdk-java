/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.token;

import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import static java.time.temporal.ChronoUnit.SECONDS;


/**
 * Representation of an access token.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-1.4">OAuth 2.0, section 1.4</a>
 */
public class AccessToken extends Token {
    /**
     * Scope of the token.
     */
    private final Set<String> scope;
    /**
     * Expiration time of the token.
     */
    private final Instant expiresAt;

    public AccessToken(String token, Collection<String> scope, long expiresIn) {
        super(token);

        this.scope = new HashSet<>();
        if (scope != null) {
            this.scope.addAll(scope);
        }
        this.expiresAt = Instant.now().plus(expiresIn, SECONDS);
    }

    public String getToken() {
        return token;
    }

    public Set<String> getScope() {
        return scope;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    @Override
    public String toString() {
        return String.format("{token=%s, scope=%s, expires=%s}",
            token,
            String.join(" ", scope),
            expiresAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(token, scope, expiresAt);
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof AccessToken)) {
            return false;
        }
        AccessToken accessToken = (AccessToken) other;
        return Objects.equals(token, accessToken.token) &&
            Objects.equals(scope, accessToken.scope) &&
            Objects.equals(expiresAt, accessToken.expiresAt);
    }
}
