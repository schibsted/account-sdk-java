/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.jwt.JWTClaimsSet;
import com.schibsted.account.testutil.TokenHelper;
import kong.unirest.HttpMethod;
import kong.unirest.MockClient;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URL;
import java.util.Date;

import static org.junit.Assert.*;

public class TokenIntrospectorJWKSTest {

    private MockClient mock;

    private TokenIntrospectorJWKS introspector;

    @Before
    public void setup() throws Exception {
        mock = MockClient.register();
        introspector = new TokenIntrospectorJWKS(new URL("https://issuer.example.com/jwks"));
    }

    @After
    public void teardown() {
        mock.verifyAll();
        mock.close();
        MockClient.clear();
    }

    @Test
    public void introspectTokenShouldVerifyValidAccessToken() throws Exception {
        mock.expect(HttpMethod.GET, "https://issuer.example.com/jwks").thenReturn(
            TokenHelper.jwks().toString()
        );

        String token = TokenHelper.createClientAccessToken();
        assertTrue(introspector.introspectToken(token).isActive());
    }

    @Test
    public void introspectTokenShouldReturnInactiveForExpiredToken() throws Exception {
        mock.expect(HttpMethod.GET, "https://issuer.example.com/jwks").thenReturn(
            TokenHelper.jwks().toString()
        );

        Date pastTime = new Date(System.currentTimeMillis() - 100 * 1000);
        JWTClaimsSet claims = TokenHelper.accessTokenClaimsBuilder()
            .expirationTime(pastTime)
            .build();
        String token = TokenHelper.createClientAccessToken(claims);
        assertFalse(introspector.introspectToken(token).isActive());
    }

    @Test
    public void introspectTokenShouldReturnNullForNonJWTToken() {
        assertNull(introspector.introspectToken("foobar"));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenJWKSCanNotBeFetched() throws Exception {
        mock.expect(HttpMethod.GET, "https://issuer.example.com/jwks")
            .thenReturn()
            .withStatus(404);

        String token = TokenHelper.createClientAccessToken();
        assertNull(introspector.introspectToken(token));
    }

    @Test
    public void introspectTokenShouldReturnNullForUserToken() throws Exception {
        String token = TokenHelper.createUserAccessToken();
        assertNull(introspector.introspectToken(token));
    }
}
