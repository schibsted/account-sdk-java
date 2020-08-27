/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.nimbus;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
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

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;

import static com.schibsted.account.testutil.HttpHelper.matchesExpectedRequest;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class NimbusWrapperTest {
    @Mock
    private HttpClient httpClient;

    private final String issuer = "https://issuer.example.com";
    private final String clientId = "client1";
    private final String clientSecret = "secret";
    private final URI tokenEndpoint = URI.create(issuer).resolve("/token");

    private NimbusWrapper wrapper;

    @Before
    public void setup() throws MalformedURLException {
        MockitoAnnotations.initMocks(this);
        Unirest.config().httpClient(new ApacheClient(httpClient, new Config()));
        wrapper = new NimbusWrapper(
            issuer,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            URI.create(issuer).resolve("/jwks").toURL(),
            tokenEndpoint
        );
    }

    @Test
    public void clientCredentialsGrantWithScopeAndResource() throws Exception {
        AccessTokenResponse mockResponse = new AccessTokenResponse(
            new Tokens(new BearerAccessToken(), null)
        );
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(mockResponse.toHTTPResponse().getContent()));

        Collection<String> scope = Collections.singletonList("test");
        URI resource = URI.create("https://example.com");
        AccessTokenResponse accessTokenResponse = wrapper.clientCredentialsGrant(scope, Collections.singletonList(resource));

        assertEquals(
            mockResponse.getTokens().getBearerAccessToken().getValue(),
            accessTokenResponse.getTokens().getBearerAccessToken().getValue()
        );

        TokenRequest expectedRequest = new TokenRequest(
            tokenEndpoint,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            new ClientCredentialsGrant(),
            Scope.parse(scope),
            Collections.singletonList(resource),
            null
        );
        verify(httpClient).execute(argThat(matchesExpectedRequest(expectedRequest)));
    }

    @Test
    public void clientCredentialsGrantWithoutScopeAndResource() throws Exception {
        AccessTokenResponse mockResponse = new AccessTokenResponse(
            new Tokens(new BearerAccessToken(), null)
        );
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(mockResponse.toHTTPResponse().getContent()));

        AccessTokenResponse accessTokenResponse = wrapper.clientCredentialsGrant(null, null);

        assertEquals(
            mockResponse.getTokens().getBearerAccessToken().getValue(),
            accessTokenResponse.getTokens().getBearerAccessToken().getValue()
        );

        TokenRequest expectedRequest = new TokenRequest(
            tokenEndpoint,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            new ClientCredentialsGrant());
        verify(httpClient).execute(argThat(matchesExpectedRequest(expectedRequest)));
    }

    @Test
    public void authorizationCodeGrant() throws Exception {
        AccessTokenResponse mockResponse = new OIDCTokenResponse(
            new OIDCTokens(TokenHelper.createIdToken("nonce"), new BearerAccessToken(), new RefreshToken())
        );
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(mockResponse.toHTTPResponse().getContent()));

        String authCode = "test_auth_code";
        URI redirectUri = URI.create("http://client.example.com");
        AccessTokenResponse accessTokenResponse = wrapper.authorizationCodeGrant(
            authCode,
            redirectUri
        );

        assertEquals(
            mockResponse.getTokens().getBearerAccessToken().getValue(),
            accessTokenResponse.getTokens().getBearerAccessToken().getValue()
        );
        TokenRequest expectedRequest = new TokenRequest(
            tokenEndpoint,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            new AuthorizationCodeGrant(new AuthorizationCode(authCode), redirectUri)
        );
        verify(httpClient).execute(argThat(matchesExpectedRequest(expectedRequest)));
    }

    @Test
    public void refreshTokenGrant() throws Exception {
        AccessTokenResponse mockResponse = new AccessTokenResponse(
            new Tokens(new BearerAccessToken(), new RefreshToken())
        );
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(mockResponse.toHTTPResponse().getContent()));

        String refreshToken = "test_refresh_token";
        AccessTokenResponse accessTokenResponse = wrapper.refreshTokenGrant(refreshToken);

        assertEquals(
            mockResponse.getTokens().getBearerAccessToken().getValue(),
            accessTokenResponse.getTokens().getBearerAccessToken().getValue()
        );
        TokenRequest expectedRequest = new TokenRequest(
            tokenEndpoint,
            new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret)),
            new RefreshTokenGrant(new RefreshToken(refreshToken))
        );
        verify(httpClient).execute(argThat(matchesExpectedRequest(expectedRequest)));
    }

    @Test
    public void validateIDToken() throws Exception {
        // jwks response
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(TokenHelper.jwks().toString()));

        String nonce = "test_nonce";
        IDTokenClaimsSet claims = wrapper.validateIDToken(TokenHelper.createIdToken(nonce), nonce);
        assertEquals(nonce, claims.getNonce().getValue());
    }
}
