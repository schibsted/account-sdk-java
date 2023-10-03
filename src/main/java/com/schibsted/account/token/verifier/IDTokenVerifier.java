/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.token.verifier;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.schibsted.account.util.Helpers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Additional checks of claims in an ID Token.
 */
public class IDTokenVerifier extends DefaultJWTClaimsVerifier<IDTokenSecurityContext> {

    public IDTokenVerifier() {
        super(null, REQUIRED_CLAIMS);
    }


    private static final Set<String> REQUIRED_CLAIMS =
        new HashSet<String>(Arrays.asList("exp", "aud"));
    private static final Logger logger = LoggerFactory.getLogger(IDTokenVerifier.class);

    /**
     * {@inheritDoc}
     * Validates the issuer, audience and 'nonce' of the ID Token.
     *
     * @param claimsSet claims from the ID Token to validate
     * @param context   data to validate the ID Token claims against
     * @throws BadJWTException if the ID Token claims are invalid
     */
    @Override
    public void verify(JWTClaimsSet claimsSet, IDTokenSecurityContext context) throws BadJWTException {
        super.verify(claimsSet, context);

        IDTokenClaimsSet claims;
        try {
            claims = new IDTokenClaimsSet(claimsSet);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            throw new BadJWTException("The ID Token could not be parsed");
        }

        if (!Helpers.compareIssuer(context.getIssuer(), claims.getIssuer().getValue())) {
            logger.error("Incorrect issuer. Expected: '{}', actual: '{}'", context.getIssuer(), claims.getIssuer().getValue());
            throw new BadJWTException("Unexpected issuer of the ID Token");
        }

        if (!claims.getAudience().contains(new Audience(context.getClientId()))) {
            logger.error("ID Token was not issued to this client: '{}' not in '{}'", context.getClientId(), claims.getAudience());
            throw new BadJWTException("ID Token was not issued to this client");
        }

        if (context.getNonce() != null && claims.getNonce() == null) {
            logger.error("Missing expected nonce in ID Token");
            throw new BadJWTException("Missing nonce in ID Token");
        }

        String nonceFromIdToken = claims.getNonce() != null ? claims.getNonce().getValue() : null;
        if (!Objects.equals(context.getNonce(), nonceFromIdToken)) {
            logger.error("Unexpected nonce: expected '{}', actual '{}'", context.getNonce(), claims.getNonce().getValue());
            throw new BadJWTException(String.format("Unexpected nonce: '%s' != '%s'", context.getNonce(), claims.getNonce().getValue()));
        }
    }
}
