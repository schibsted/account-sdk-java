/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.nimbus;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.schibsted.account.testutil.TokenHelper;
import kong.unirest.Expectation;
import kong.unirest.ExpectedResponse;
import kong.unirest.HttpMethod;
import kong.unirest.MockClient;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class NimbusWrapperTest {
    private final String issuer = "https://issuer.example.com";
    private final String clientId = "client1";
    private final String clientSecret = "secret";
    private final URI tokenEndpoint = URI.create(issuer).resolve("/token");
    private final URI jwksEndpoint = URI.create(issuer).resolve("/jwks");

    private NimbusWrapper wrapper;

    private MockClient mock;

    @Before
    public void setup() throws MalformedURLException {
        mock = MockClient.register();
        wrapper = new NimbusWrapper(
            issuer,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            jwksEndpoint.toURL(),
            tokenEndpoint
        );
    }

    @After
    public void teardown() throws Exception {
        mock.verifyAll();
        mock.close();
        MockClient.clear();
    }

    @Test
    public void clientCredentialsGrantWithScopeAndResource() throws Exception {
        // given
        AccessTokenResponse mockResponse = new AccessTokenResponse(
            new Tokens(new BearerAccessToken(), null)
        );
        Collection<String> scope = Collections.singletonList("test");
        URI resource = URI.create("https://example.com");
        TokenRequest expectedRequest = new TokenRequest(
            tokenEndpoint,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            new ClientCredentialsGrant(),
            Scope.parse(scope),
            Collections.singletonList(resource),
            null
        );
        setUpMock(
            expectedRequest.toHTTPRequest(),
            mockResponse.toHTTPResponse()
        );

        // when
        AccessTokenResponse accessTokenResponse = wrapper.clientCredentialsGrant(scope, Collections.singletonList(resource));

        // then
        assertEquals(
            mockResponse.getTokens().getBearerAccessToken().getValue(),
            accessTokenResponse.getTokens().getBearerAccessToken().getValue()
        );
    }

    @Test
    public void clientCredentialsGrantWithoutScopeAndResource() throws Exception {
        // given
        AccessTokenResponse mockResponse = new AccessTokenResponse(
            new Tokens(new BearerAccessToken(), null)
        );
        TokenRequest expectedRequest = new TokenRequest(
            tokenEndpoint,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            new ClientCredentialsGrant());

        setUpMock(
            expectedRequest.toHTTPRequest(),
            mockResponse.toHTTPResponse()
        );

        // when
        AccessTokenResponse accessTokenResponse = wrapper.clientCredentialsGrant(null, null);

        // then
        assertEquals(
            mockResponse.getTokens().getBearerAccessToken().getValue(),
            accessTokenResponse.getTokens().getBearerAccessToken().getValue()
        );
    }

    @Test
    public void authorizationCodeGrant() throws Exception {
        AccessTokenResponse mockResponse = new OIDCTokenResponse(
            new OIDCTokens(TokenHelper.createIdToken("nonce"), new BearerAccessToken(), new RefreshToken())
        );

        String authCode = "test_auth_code";
        URI redirectUri = URI.create("http://client.example.com");

        TokenRequest expectedRequest = new TokenRequest(
            tokenEndpoint,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            new AuthorizationCodeGrant(new AuthorizationCode(authCode), redirectUri)
        );

        setUpMock(
            expectedRequest.toHTTPRequest(),
            mockResponse.toHTTPResponse()
        );

        // when
        AccessTokenResponse accessTokenResponse = wrapper.authorizationCodeGrant(
            authCode,
            redirectUri
        );

        // then
        assertEquals(
            mockResponse.getTokens().getBearerAccessToken().getValue(),
            accessTokenResponse.getTokens().getBearerAccessToken().getValue()
        );
    }

    @Test
    public void refreshTokenGrant() throws Exception {
        AccessTokenResponse mockResponse = new AccessTokenResponse(
            new Tokens(new BearerAccessToken(), new RefreshToken())
        );
        String refreshToken = "test_refresh_token";

        TokenRequest expectedRequest = new TokenRequest(
            tokenEndpoint,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            new RefreshTokenGrant(new RefreshToken(refreshToken))
        );

        setUpMock(
            expectedRequest.toHTTPRequest(),
            mockResponse.toHTTPResponse()
        );

        // when
        AccessTokenResponse accessTokenResponse = wrapper.refreshTokenGrant(refreshToken);

        // then
        assertEquals(
            mockResponse.getTokens().getBearerAccessToken().getValue(),
            accessTokenResponse.getTokens().getBearerAccessToken().getValue()
        );
    }

    @Test
    public void validateIDToken() throws Exception {
        // given
        String nonce = "test_nonce";
        SignedJWT jwt = TokenHelper.createIdToken(nonce);
        mock
            .expect(HttpMethod.GET, jwksEndpoint.toString())
            .thenReturn(TokenHelper.jwks().toString());

        // when
        IDTokenClaimsSet claims = wrapper.validateIDToken(jwt, nonce);

        // then
        assertEquals(nonce, claims.getNonce().getValue());
    }

    private void setUpMock(
        HTTPRequest expectedRequest,
        HTTPResponse expectedResponse
    ) {
        // Set Request
        Expectation expect = mock.expect(
            HttpMethod.POST,
            expectedRequest.getURL().toString()
        );

        for (Map.Entry<String, List<String>> header : expectedRequest.getHeaderMap().entrySet()) {
            for (String value : header.getValue())
                expect = expect.header(header.getKey(), value);
        }

        // Set/Verify Expected Response
        ExpectedResponse response = expect
            .body(expectedRequest.getBody())
            .thenReturn(
                expectedResponse.getBody()
            ).withStatus(
                expectedResponse.getStatusCode()
            );

        for (Map.Entry<String, List<String>> header : expectedResponse.getHeaderMap().entrySet()) {
            for (String value : header.getValue())
                response = response.withHeader(header.getKey(), value);
        }
    }
}
