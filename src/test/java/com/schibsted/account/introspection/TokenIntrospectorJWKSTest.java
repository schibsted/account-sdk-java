/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.jwt.JWTClaimsSet;
import com.schibsted.account.testutil.HttpHelper;
import com.schibsted.account.testutil.TokenHelper;
import kong.unirest.Config;
import kong.unirest.Unirest;
import kong.unirest.apache.ApacheClient;
import org.apache.http.client.HttpClient;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.net.URL;
import java.util.Date;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class TokenIntrospectorJWKSTest {
    @Mock
    private HttpClient httpClient;

    private TokenIntrospectorJWKS introspector;

    @Before
    public void setup() throws Exception {
        MockitoAnnotations.initMocks(this);
        Unirest.config().httpClient(new ApacheClient(httpClient, new Config()));
        // JWKS response
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(
            TokenHelper.jwks().toString()
        ));
        introspector = new TokenIntrospectorJWKS(new URL("https://issuer.example.com/jwks"));
    }

    @Test
    public void introspectTokenShouldVerifyValidAccessToken() throws Exception {
        String token = TokenHelper.createClientAccessToken();
        assertTrue(introspector.introspectToken(token).isActive());
    }

    @Test
    public void introspectTokenShouldReturnInactiveForExpiredToken() throws Exception {
        Date pastTime = new Date(System.currentTimeMillis() - 100 * 1000);
        JWTClaimsSet claims = TokenHelper.accessTokenClaimsBuilder()
            .expirationTime(pastTime)
            .build();
        String token = TokenHelper.createClientAccessToken(claims);
        assertFalse(introspector.introspectToken(token).isActive());
    }

    @Test
    public void introspectTokenShouldReturnNullForNonJWTToken() throws Exception {
        assertNull(introspector.introspectToken("foobar"));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenJWKSCanNotBeFetched() throws Exception {
        when(httpClient.execute(any())).thenThrow(new IOException("JWKS fetching failed (test)"));
        String token = TokenHelper.createClientAccessToken();
        assertNull(introspector.introspectToken(token));
    }

    @Test
    public void introspectTokenShouldReturnNullForUserToken() throws Exception {
        String token = TokenHelper.createUserAccessToken();
        assertNull(introspector.introspectToken(token));
    }
}
