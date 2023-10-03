/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.schibsted.account.ClientCredentials;
import com.schibsted.account.testutil.TokenHelper;
import kong.unirest.HttpMethod;
import kong.unirest.MockClient;
import org.apache.http.HttpHeaders;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

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
    public void teardown() {
        mock.verifyAll();
        mock.close();
        MockClient.clear();
    }


    @Test
    public void introspectTokenShouldVerifyValidAccessToken() {
        String introspectionResponse = TokenHelper.introspectionResponse(TokenHelper.accessTokenClaimsBuilder().build());
        String token = "test_token";
        TokenIntrospectionRequest expectedRequest = new TokenIntrospectionRequest(
            introspectionEndpoint,
            new ClientSecretBasic(new ClientID(CLIENT_CREDENTIALS.getClientID()),
                new Secret(CLIENT_CREDENTIALS.getClientSecret())),
            new BearerAccessToken(token));
        HTTPRequest request = expectedRequest.toHTTPRequest();

        mock.expect(HttpMethod.POST, introspectionEndpoint.toString())
            .header(HttpHeaders.AUTHORIZATION, request.getAuthorization())
            .thenReturn(introspectionResponse);

        IntrospectionResult result = introspector.introspectToken(token);
        assertTrue(result.isActive());
    }

    @Test
    public void introspectTokenShouldReturnNullWhenIntrospectionRequestFails() {
        // error during introspection request
        mock.expect(HttpMethod.POST, introspectionEndpoint.toString())
            .thenReturn("");

        assertNull(introspector.introspectToken("test_token"));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenIntrospectionResponseHasUnexpectedHttpStatusCode() {
        // failed introspection request
        mock.expect(HttpMethod.POST, introspectionEndpoint.toString())
            .header(HttpHeaders.AUTHORIZATION,
                "Basic " + Base64.encode(CLIENT_CREDENTIALS.getClientID() + ":" + CLIENT_CREDENTIALS.getClientSecret())
            )
            .thenReturn("Bad Request")
            .withStatus(400);
        assertNull(introspector.introspectToken("test_token"));
    }

    @Test
    public void introspectTokenShouldReturnNullWhenIntrospectionIsMalformed() {
        // malformed introspection response
        mock.expect(HttpMethod.POST, "https://issuer.example.com/introspect")
            .header(HttpHeaders.AUTHORIZATION,
                "Basic " + Base64.encode(CLIENT_CREDENTIALS.getClientID() + ":" + CLIENT_CREDENTIALS.getClientSecret())
            )
            .thenReturn("Not Json");
        assertNull(introspector.introspectToken("test_token"));
    }
}
