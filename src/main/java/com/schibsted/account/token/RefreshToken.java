/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.token;

import java.util.Objects;

/**
 * Representation of a refresh token.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-1.5">OAuth 2.0, section 1.5</a>
 */
public class RefreshToken extends Token {
    public RefreshToken(String token) {
        super(token);
    }

    @Override
    public String toString() {
        return String.format("{token=%s}", token);
    }

    @Override
    public int hashCode() {
        return Objects.hash(token);
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof RefreshToken)) {
            return false;
        }
        RefreshToken refreshToken = (RefreshToken) other;
        return Objects.equals(token, refreshToken.token);
    }
}
