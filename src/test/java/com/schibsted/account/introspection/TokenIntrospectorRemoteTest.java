/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.schibsted.account.ClientCredentials;
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
import java.net.URI;

import static com.schibsted.account.testutil.HttpHelper.matchesExpectedRequest;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TokenIntrospectorRemoteTest {
    @Mock
    private HttpClient httpClient;

    private static final ClientCredentials CLIENT_CREDENTIALS = new ClientCredentials("client1", "secret1");

    private static URI introspectionEndpoint;
    private TokenIntrospectorRemote introspector;

    @Before
    public void setup() throws Exception {
        MockitoAnnotations.initMocks(this);
        Unirest.config().httpClient(new ApacheClient(httpClient, new Config()));
        introspectionEndpoint = new URI("https://issuer.example.com/introspect");
        introspector = new TokenIntrospectorRemote(introspectionEndpoint, CLIENT_CREDENTIALS);
    }

    @Test
    public void introspectTokenShouldVerifyValidAccessToken() throws Exception {
        String introspectionResponse = TokenHelper.introspectionResponse(TokenHelper.accessTokenClaimsBuilder().build());
        // introspection response for valid token
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(introspectionResponse));

        String token = "test_token";
        assertTrue(introspector.introspectToken(token).isActive());
        TokenIntrospectionRequest expectedRequest = new TokenIntrospectionRequest(
            introspectionEndpoint,
            new ClientSecretBasic(new ClientID(CLIENT_CREDENTIALS.getClientID()),
                new Secret(CLIENT_CREDENTIALS.getClientSecret())),
            new BearerAccessToken(token));
        verify(httpClient).execute(argThat(matchesExpectedRequest(expectedRequest)));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenIntrospectionRequestFails() throws Exception {
        // error during introspection request
        when(httpClient.execute(any())).thenThrow(new IOException("Token introspection failed (test)"));
        assertNull(introspector.introspectToken("test_token"));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenIntrospectionResponseHasUnexpectedHttpStatusCode() throws Exception {
        // failed introspection request
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(400, "Bad request"));
        assertNull(introspector.introspectToken("test_token"));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenIntrospectionIsMalformed() throws Exception {
        // malformed introspection response
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(200, "Not JSON"));
        assertNull(introspector.introspectToken("test_token"));
    }
}
