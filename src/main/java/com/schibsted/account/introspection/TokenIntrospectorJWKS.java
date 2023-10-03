/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.schibsted.account.nimbus.UnirestResourceRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.text.ParseException;

/**
 * {@code TokenIntrospectorJWKS} validates a JWT token with keys from a JWKS fetched from a URL.
 */
public class TokenIntrospectorJWKS implements TokenIntrospector {
    private static final Logger logger = LoggerFactory.getLogger(TokenIntrospectorJWKS.class);

    private final DefaultJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

    public TokenIntrospectorJWKS(URL jwksEndpoint) {
        JWSKeySelector<SimpleSecurityContext> keySelector = new JWSVerificationKeySelector<>(
            JWSAlgorithm.RS256,
            JWKSourceBuilder.<SimpleSecurityContext>create(jwksEndpoint, new UnirestResourceRetriever())
                .build()
        );
        jwtProcessor.setJWSKeySelector(keySelector);
    }

    /**
     * {@inheritDoc}
     * Tries to verify the token as a signed JWT (JWS) with public keys from a JWKS fetched remotely.
     */
    @Override
    public IntrospectionResult introspectToken(String token) {
        SignedJWT jws;
        try {
            jws = SignedJWT.parse(token);
        } catch (ParseException e) {
            logger.debug("Local JWT introspection failed: Token is not a JWT");
            return null;
        }

        try {
            // FIXME: may want to override handling of 'exp' so that we're in control of the clock
            JWTClaimsSet claims = jwtProcessor.process(jws, null);
            return new IntrospectionResult(true, claims);
        } catch (BadJWTException e) {
            // verification error of the claims in the token, which won't change with any other introspection method,
            // for example an expired token so we can safely say the token is inactive
            logger.debug("Local JWT introspection failed: '{}'", e.getMessage());
            return IntrospectionResult.inactive();
        } catch (JOSEException | BadJOSEException e) {
            logger.debug("Local JWT introspection failed: '{}'", e.getMessage());
            return null;
        }
    }
}
