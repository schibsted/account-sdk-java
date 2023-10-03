/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.schibsted.account.ClientCredentials;
import com.schibsted.account.testutil.TokenHelper;
import kong.unirest.HttpMethod;
import kong.unirest.MockClient;
import org.apache.http.HttpHeaders;
import org.apache.http.client.HttpClient;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import java.io.IOException;
import java.net.URI;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class TokenIntrospectorRemoteTest {

    private static final ClientCredentials CLIENT_CREDENTIALS = new ClientCredentials("client1", "secret1");

    private static URI introspectionEndpoint;
    private TokenIntrospectorRemote introspector;

    private MockClient mock;

    public TokenIntrospectorRemoteTest() {
    }

    @Before
    public void setup() throws Exception {
        mock = MockClient.register();
        introspectionEndpoint = new URI("https://issuer.example.com/introspect");
        introspector = new TokenIntrospectorRemote(introspectionEndpoint, CLIENT_CREDENTIALS);
    }

    @After
    public void teardown() throws Exception {
        mock.verifyAll();
        mock.close();
        MockClient.clear();
    }


    @Test
    public void introspectTokenShouldVerifyValidAccessToken() throws Exception {
        String introspectionResponse = TokenHelper.introspectionResponse(TokenHelper.accessTokenClaimsBuilder().build());
        // introspection response for valid token
        mock.expect(HttpMethod.POST, "https://issuer.example.com/introspect")
            .header(HttpHeaders.AUTHORIZATION,
                "Basic " + Base64.encode(CLIENT_CREDENTIALS.getClientID() + ":" + CLIENT_CREDENTIALS.getClientSecret())
            )
            .thenReturn(introspectionResponse);

        String token = "test_token";
        assertTrue(introspector.introspectToken(token).isActive());
        TokenIntrospectionRequest expectedRequest = new TokenIntrospectionRequest(
            introspectionEndpoint,
            new ClientSecretBasic(new ClientID(CLIENT_CREDENTIALS.getClientID()),
                new Secret(CLIENT_CREDENTIALS.getClientSecret())),
            new BearerAccessToken(token));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenIntrospectionRequestFails() throws Exception {
        // error during introspection request
        mock.expect(HttpMethod.POST, "https://issuer.example.com/introspect")
            .thenReturn("");

        assertNull(introspector.introspectToken("test_token"));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenIntrospectionResponseHasUnexpectedHttpStatusCode() throws Exception {
        // failed introspection request
        mock.expect(HttpMethod.POST, "https://issuer.example.com/introspect")
            .header(HttpHeaders.AUTHORIZATION,
                "Basic " + Base64.encode(CLIENT_CREDENTIALS.getClientID() + ":" + CLIENT_CREDENTIALS.getClientSecret())
            )
            .thenReturn("Bad Request")
            .withStatus(400);
        assertNull(introspector.introspectToken("test_token"));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenIntrospectionIsMalformed() throws Exception {
        // malformed introspection response
        mock.expect(HttpMethod.POST, "https://issuer.example.com/introspect")
            .header(HttpHeaders.AUTHORIZATION,
                "Basic " + Base64.encode(CLIENT_CREDENTIALS.getClientID() + ":" + CLIENT_CREDENTIALS.getClientSecret())
            )
            .thenReturn("Not Json");
        assertNull(introspector.introspectToken("test_token"));
    }
}
