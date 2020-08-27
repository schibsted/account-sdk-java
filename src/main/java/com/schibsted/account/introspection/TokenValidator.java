/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.schibsted.account.util.Helpers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;

/**
 * {@code TokenValidator} validates a token, using a list of introspection methods (ordered by priority).
 */
public class TokenValidator {
    private static final Logger logger = LoggerFactory.getLogger(TokenValidator.class);
    private final List<TokenIntrospector> introspectors;

    /**
     * Constructor.
     *
     * @param introspectors introspection methods, in priority order.
     */
    public TokenValidator(List<TokenIntrospector> introspectors) {
        if (introspectors == null || introspectors.isEmpty()) {
            throw new IllegalArgumentException("introspectors may not be null or empty");
        }
        this.introspectors = introspectors;
    }

    /**
     * Validate a token, verifying it has the correct audience and contains all required scopes.
     * The token will be introspected with the configured introspection methods first, which validates token expiration,
     * etc., before being validated against any additional audience and scope restrictions.
     *
     * @param token            token to validate
     * @param expectedIssuer   expected issuer identifier
     * @param requiredScopes   all required scopes, or null
     * @param requiredAudience expected identifier for the token audience, or null
     * @return the authorization data of the token
     * @throws InvalidTokenException if the token did not fulfill all requirements: invalid signature, missing required
     *                               scope, missing required audience
     */
    public IntrospectionResult validateAccessToken(String token, String expectedIssuer, Collection<String> requiredScopes, String requiredAudience) {
        if (expectedIssuer == null || expectedIssuer.isEmpty()) {
            throw new IllegalArgumentException("expectedIssuer may not be null or empty");
        }

        IntrospectionResult introspectionResult = null;
        for (TokenIntrospector introspector : introspectors) {
            introspectionResult = introspector.introspectToken(token);
            if (introspectionResult != null) {
                // We've successfully introspected the token, no need to continue trying
                break;
            }
        }

        if (introspectionResult == null) {
            throw new InvalidTokenException.IntrospectionFailed();
        }

        if (!introspectionResult.isActive()) {
            return introspectionResult;
        }

        if (!Helpers.compareIssuer(expectedIssuer, introspectionResult.getIssuer())) {
            logger.error("Incorrect issuer. Expected: '{}', actual: '{}'", expectedIssuer, introspectionResult.getIssuer());
            throw new InvalidTokenException.IncorrectIssuer();
        }

        if (requiredScopes != null && !introspectionResult.getScope().containsAll(requiredScopes)) {
            logger.error("Missing required scopes. Required: '{}', actual: '{}'",
                requiredScopes, introspectionResult.getScope());
            throw new InvalidTokenException.MissingRequiredScopes();
        }

        if (requiredAudience != null &&
            !requiredAudience.isEmpty() &&
            !introspectionResult.getAudience().contains(requiredAudience)) {
            logger.error("Missing required audience: '{}'", requiredAudience);
            throw new InvalidTokenException.MissingRequiredAudience();
        }

        return introspectionResult;
    }
}
