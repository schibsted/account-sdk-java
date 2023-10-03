/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.jwt.JWTClaimsSet;
import com.schibsted.account.ClientCredentials;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.text.ParseException;

/**
 * {@code TokenIntrospectorRemote} validates a JWT token via a token introspection request.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7662">OAuth 2.0 Token Introspection</a>
 */
public class TokenIntrospectorRemote implements TokenIntrospector {
    private static final Logger logger = LoggerFactory.getLogger(TokenIntrospectorRemote.class);

    private final URI introspectionEndpoint;
    private final ClientCredentials clientCredentials;


    /**
     * Constructor.
     *
     * @param introspectionEndpoint URL of the token introspection endpoint
     * @param clientCredentials     credentials for the OAuth client used in the introspection request
     */
    public TokenIntrospectorRemote(URI introspectionEndpoint, ClientCredentials clientCredentials) {
        this.introspectionEndpoint = introspectionEndpoint;
        this.clientCredentials = clientCredentials;
    }

    /**
     * {@inheritDoc}
     * Introspects the token by making a token introspection request.
     */
    @Override
    public IntrospectionResult introspectToken(String token) {
        HttpResponse<String> response;
        try {
            response = Unirest.post(introspectionEndpoint.toString())
                .basicAuth(clientCredentials.getClientID(), clientCredentials.getClientSecret())
                .field("token", token)
                .field("token_type_hint", "access_token")
                .asString();
        } catch (UnirestException e) {
            logger.error("Http error: '{}'", e.getMessage());
            return null;
        }

        if (response.getStatus() != 200) {
            logger.error("Http error, status code {} != 200", response.getStatus());
            return null;
        }

        try {
            String body = response.getBody();
            JWTClaimsSet claims = JWTClaimsSet.parse(body != null ? body : "");
            boolean active = false;
            if (claims.getBooleanClaim("active") != null) {
                active = claims.getBooleanClaim("active");
            } else {
                logger.warn("Introspection response is missing 'active' key");
            }
            return new IntrospectionResult(active, claims);
        } catch (ParseException e) {
            logger.error("Parse error: '{}'", e.getMessage());
            return null;
        }
    }
}
