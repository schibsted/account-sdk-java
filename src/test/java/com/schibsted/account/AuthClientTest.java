/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.schibsted.account.introspection.IntrospectionResult;
import com.schibsted.account.testutil.HttpHelper;
import com.schibsted.account.testutil.TokenHelper;
import com.schibsted.account.token.IDToken;
import com.schibsted.account.token.UserTokens;
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
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;

import static com.schibsted.account.util.Helpers.toInstant;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class AuthClientTest {
    @Mock
    private HttpClient httpClient;

    private AuthClient.Builder authClientBuilder() {
        return new AuthClient.Builder(
            new ClientCredentials(TokenHelper.CLIENT_ID, "bar"),
            URI.create(TokenHelper.ISSUER)
        );
    }

    @Before
    public void setup() throws URISyntaxException {
        MockitoAnnotations.initMocks(this);
        Unirest.config().httpClient(new ApacheClient(httpClient, new Config()));
    }

    @Test
    public void getLoginURL() throws Exception {
        Collection<String> scopes = Arrays.asList("openid", "scope1", "scope2");
        String state = "test_state";
        String nonce = "test_nonce";
        String redirectUri = "http://client.example.com/redirect";

        AuthClient c = authClientBuilder().build();
        String loginUrl = c.getLoginURL(new URI(redirectUri), state, nonce, scopes).toString();
        String expectedParams = String.format(
            "response_type=code&client_id=%s&state=%s&nonce=%s&scope=%s&redirect_uri=%s",
            TokenHelper.CLIENT_ID,
            state,
            nonce,
            String.join("+", scopes),
            redirectUri
        );
        // make sure the redirect URI is properly URL encoded
        assertTrue(loginUrl.contains(URLEncoder.encode(redirectUri, "utf-8")));
        assertEquals(URLUtils.parseParameters(expectedParams), URLUtils.parseParameters(new URL(loginUrl).getQuery()));
    }

    @Test
    public void remoteAccessTokenValidation() throws IOException, URISyntaxException {
        JWTClaimsSet tokenClaims = TokenHelper.accessTokenClaimsBuilder().build();
        // introspection response
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(TokenHelper.introspectionResponse(tokenClaims)));
        IntrospectionResult expected = new IntrospectionResult(true, tokenClaims);
        AuthClient client = authClientBuilder()
            .withRemoteTokenIntrospection()
            .build();
        assertEquals(
            expected,
            client.validateAccessToken("test token", TokenHelper.SCOPES, TokenHelper.CLIENT_ID)
        );
    }

    @Test
    public void localAccessTokenValidation() throws Exception {
        // JWKS response
        when(httpClient.execute(any())).thenReturn(HttpHelper.httpResponseMock(TokenHelper.jwks().toString()));

        AuthClient client = authClientBuilder()
            .withLocalTokenIntrospection()
            .build();
        String token = TokenHelper.createClientAccessToken();
        IntrospectionResult result = client.validateAccessToken(token, TokenHelper.SCOPES, TokenHelper.CLIENT_ID);
        assertEquals(new IntrospectionResult(true, TokenHelper.accessTokenClaimsBuilder().build()), result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void clientNotConfiguredForIntrospectionFailsWithException() throws URISyntaxException {
        authClientBuilder()
            .build()
            .validateAccessToken("foo", TokenHelper.SCOPES, TokenHelper.CLIENT_ID);
    }

    @Test
    public void codeFlowShouldExposeAllReturnedTokens() throws Exception {
        String nonce = "test_nonce";
        // access token response
        OIDCTokenResponse tokenResponse = new OIDCTokenResponse(new OIDCTokens(
            TokenHelper.createIdToken(nonce),
            new BearerAccessToken(10, new Scope("test_scope")),
            new RefreshToken())
        );
        when(httpClient.execute(any())).thenReturn(
            HttpHelper.httpResponseMock(tokenResponse.toHTTPResponse().getContent()), // token response
            HttpHelper.httpResponseMock(TokenHelper.jwks().toString()) // jwks response for verifying ID Token
        );

        AuthClient client = authClientBuilder().build();
        UserTokens tokens = client.authorizationCodeGrant("test_code", new URI(""), nonce);
        assertEquals(tokenResponse.getOIDCTokens().getAccessToken().getValue(), tokens.getAccessToken().getToken());
        assertEquals(tokenResponse.getOIDCTokens().getRefreshToken().getValue(), tokens.getRefreshToken().getToken());
        assertIdToken(tokenResponse.getOIDCTokens().getIDToken().getJWTClaimsSet(), tokens.getIDToken());
    }

    private void assertIdToken(JWTClaimsSet expected, IDToken idToken) throws ParseException {
        assertEquals(expected.getIssuer(), idToken.getIssuer());
        assertEquals(expected.getSubject(), idToken.getSubject());
        assertEquals(toInstant(expected.getIssueTime()), idToken.getIssuedAt());
        assertEquals(toInstant(expected.getExpirationTime()), idToken.getExpiresAt());
        assertEquals(toInstant(expected.getDateClaim("auth_time")), idToken.getAuthTime());
        assertEquals(expected.getStringClaim("acr"), idToken.getAcr());
    }
}
