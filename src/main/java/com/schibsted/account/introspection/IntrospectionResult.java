/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.jwt.JWTClaimsSet;
import com.schibsted.account.util.Helpers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Instant;
import java.util.*;

/**
 * The authorization data associated with an introspected access token.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7662">OAuth 2.0 Token Introspection</a>
 */
public class IntrospectionResult {
    private static final Logger logger = LoggerFactory.getLogger(IntrospectionResult.class);

    /**
     * Whether the token is active (not expired, signed with a known key, allowed to be introspected, etc.).
     */
    private final boolean active;
    /**
     * Intended audience of the token, corresponds to the JWT claim "aud".
     */
    private final List<String> audience;
    /**
     * Scopes associated with the token.
     */
    private final Set<String> scope;
    /**
     * Identifier for the issuer of the token, corresponds to the JWT claim "iss".
     */
    private final String issuer;
    /**
     * Identifier for the client that requested the token.
     */
    private final String client;
    /**
     * Identifier for the user associated with the token, corresponds to the JWT claim "sub".
     */
    private final String subject;
    /**
     * Expiration time of the token, corresponds to the JWT claim "exp".
     */
    private final Instant expiresAt;
    /**
     * Issue time of the token, corresponds to the JWT claim "iat".
     */
    private final Instant issuedAt;

    public IntrospectionResult(boolean active, JWTClaimsSet claims) {
        this.active = active;
        this.audience = claims.getAudience();
        this.issuer = claims.getIssuer();
        this.subject = claims.getSubject();
        this.issuedAt = Helpers.toInstant(claims.getIssueTime());
        this.expiresAt = Helpers.toInstant(claims.getExpirationTime());

        String scopeValues = getStringClaim("scope", claims);
        this.scope = new HashSet<>();
        if (scopeValues != null) {
            this.scope.addAll(Arrays.asList(scopeValues.split(" ")));
        }

        String client = getStringClaim("client_id", claims);
        if (client == null) {
            // Try fall-back to 'azp' claims
            client = getStringClaim("azp", claims);
        }
        this.client = client;
    }

    public static IntrospectionResult inactive() {
        return new IntrospectionResult(false, new JWTClaimsSet.Builder().build());
    }

    private String getStringClaim(String name, JWTClaimsSet claims) {
        try {
            return claims.getStringClaim(name);
        } catch (ParseException e) {
            logger.debug("Could not parse '{}' from claims '{}'", name, claims.toString());
            return null;
        }
    }

    public boolean isActive() {
        return active;
    }

    public List<String> getAudience() {
        return audience;
    }

    public Set<String> getScope() {
        return scope;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubject() {
        return subject;
    }

    public String getClient() {
        return client;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (!(other instanceof IntrospectionResult)) {
            return false;
        }
        IntrospectionResult i = (IntrospectionResult) other;
        return active == i.active &&
            Objects.equals(audience, i.audience) &&
            Objects.equals(scope, i.scope) &&
            Objects.equals(issuer, i.issuer) &&
            Objects.equals(client, i.client) &&
            Objects.equals(expiresAt, i.expiresAt) &&
            Objects.equals(issuedAt, i.issuedAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            active,
            audience,
            scope,
            issuer,
            client,
            expiresAt,
            issuedAt);
    }

    @Override
    public String toString() {
        if (!active) {
            return "{active=false}";
        }

        return String.format("{active=true, aud=[%s], scope=%s, iss=%s, client=%s, exp=%s, iat=%s}",
            String.join(",", audience),
            String.join(" ", scope),
            issuer,
            client,
            expiresAt,
            issuedAt);
    }
}
