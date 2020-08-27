/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.token.verifier;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.schibsted.account.testutil.TokenHelper;
import org.junit.Test;

import java.util.Collections;

public class IDTokenVerifierTest {
    private IDTokenClaimsSet claims = new IDTokenClaimsSet(
        new Issuer("test_issuer"),
        new Subject("test_user"),
        Collections.singletonList(new Audience("test_client")),
        TokenHelper.now(),
        TokenHelper.later(10)
    );

    private JWTClaimsSet getIDTokenClaims() throws ParseException {
        claims.setNonce(new Nonce("test_nonce"));
        return claims.toJWTClaimsSet();
    }

    @Test
    public void verifyShouldAcceptValidIDToken() throws Exception {
        JWTClaimsSet claims = getIDTokenClaims();
        IDTokenSecurityContext idTokenContext = new IDTokenSecurityContext(claims.getIssuer(), claims.getAudience().get(0), "test_nonce");
        new IDTokenVerifier().verify(claims, idTokenContext);
    }

    @Test(expected = BadJWTException.class)
    public void verifyShouldRejectWrongIssuer() throws Exception {
        IDTokenSecurityContext idTokenContext = new IDTokenSecurityContext("wrong issuer", null, null);
        new IDTokenVerifier().verify(getIDTokenClaims(), idTokenContext);
    }

    @Test(expected = BadJWTException.class)
    public void verifyShouldRejectIDTokenNotIntendedForThisClient() throws Exception {
        IDTokenSecurityContext idTokenContext = new IDTokenSecurityContext("test_issuer", "client1", null);
        new IDTokenVerifier().verify(getIDTokenClaims(), idTokenContext);
    }

    @Test(expected = BadJWTException.class)
    public void verifyShouldRejectWrongNonce() throws Exception {
        IDTokenSecurityContext idTokenContext = new IDTokenSecurityContext("test_issuer", "test_client", "wrong nonce");
        new IDTokenVerifier().verify(getIDTokenClaims(), idTokenContext);
    }

    @Test
    public void verifyShouldAllowIdTokenWithoutNonceIfNotExpected() throws Exception {
        IDTokenSecurityContext idTokenContext = new IDTokenSecurityContext("test_issuer", "test_client", null);
        new IDTokenVerifier().verify(claims.toJWTClaimsSet(), idTokenContext);
    }

    @Test(expected = BadJWTException.class)
    public void verifyShouldRejectMissingNonceIfExpected() throws Exception {
        IDTokenSecurityContext idTokenContext = new IDTokenSecurityContext("test_issuer", "test_client", "some nonce");
        new IDTokenVerifier().verify(claims.toJWTClaimsSet(), idTokenContext);
    }
}
