/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.token;

import java.time.Instant;
import java.util.Objects;

/**
 * Representation of an ID Token.
 *
 * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect 1.0, section 2</a>
 */
public class IDToken {

    /**
     * Identifier for the issuer of the ID Token, corresponds to the JWT claim "iss".
     */
    private final String issuer;
    /**
     * Identifier for the user associated with the token, corresponds to the JWT claim "sub".
     */
    private final String subject;
    /**
     * Time when the user authentication happened, corresponds to the claim "auth_time".
     */
    private final Instant authTime;
    /**
     * "Authentication Context Class Reference", corresponds to the claim "acr".
     */
    private final String acr;
    /**
     * Issue time of the token, corresponds to the JWT claim "iat".
     */
    private final Instant issuedAt;
    /**
     * Expiration time of the token, corresponds to the JWT claim "exp".
     */
    private final Instant expiresAt;

    public IDToken(String issuer, String subject, Instant authTime, String acr, Instant issuedAt, Instant expiresAt) {
        this.issuer = issuer;
        this.subject = subject;
        this.authTime = authTime;
        this.acr = acr;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubject() {
        return subject;
    }

    public Instant getAuthTime() {
        return authTime;
    }

    public String getAcr() {
        return acr;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    @Override
    public String toString() {
        return String.format(
            "{issuer=%s, subject=%s, issued=%s, expires=%s, auth_time=%s, acr=%s}",
            issuer, subject, issuedAt, expiresAt, authTime, acr
        );
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuer, subject, issuedAt, expiresAt, authTime, acr);
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof IDToken)) {
            return false;
        }
        IDToken idToken = (IDToken) other;
        return Objects.equals(issuer, idToken.issuer) &&
            Objects.equals(subject, idToken.subject) &&
            Objects.equals(issuedAt, idToken.issuedAt) &&
            Objects.equals(expiresAt, idToken.expiresAt) &&
            Objects.equals(authTime, idToken.authTime) &&
            Objects.equals(acr, idToken.acr);
    }
}
