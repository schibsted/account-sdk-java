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
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.schibsted.account.introspection.IntrospectionResult;
import com.schibsted.account.testutil.TokenHelper;
import com.schibsted.account.token.IDToken;
import com.schibsted.account.token.UserTokens;
import kong.unirest.HttpMethod;
import kong.unirest.MockClient;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import static com.schibsted.account.util.Helpers.toInstant;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AuthClientTest {

    private MockClient mock;
    private URI serverUri = URI.create(TokenHelper.ISSUER);
    private URI expectedJwksEndpoint = serverUri.resolve("/oauth/jwks");
    private URI expectedIntrospectEndpoint = serverUri.resolve("/oauth/introspect");
    private URI expectedTokenEndpoint = serverUri.resolve("/oauth/token");

    private AuthClient.Builder authClientBuilder() {
        return new AuthClient.Builder(
            new ClientCredentials(TokenHelper.CLIENT_ID, "bar"),
            serverUri
        );
    }

    @Before
    public void setup() throws URISyntaxException {
        mock = MockClient.register();
    }

    @After
    public void teardown() throws Exception {
        mock.verifyAll();
        mock.close();
        MockClient.clear();
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
    public void getLoginURLWithACR() throws Exception {
        Collection<String> scopes = Arrays.asList("openid", "scope1", "scope2");
        String state = "test_state";
        String nonce = "test_nonce";
        String redirectUri = "http://client.example.com/redirect";
        Collection<ACR> acrValues = Arrays.asList(new ACR("sms"), new ACR("pwd"));

        AuthClient c = authClientBuilder().build();
        String loginUrl = c.getLoginURL(new URI(redirectUri), state, nonce, scopes, acrValues).toString();
        String expectedParams = String.format(
            "response_type=code&client_id=%s&state=%s&nonce=%s&scope=%s&redirect_uri=%s&acr_values=%s",
            TokenHelper.CLIENT_ID,
            state,
            nonce,
            String.join("+", scopes),
            redirectUri,
            acrValues.stream().map(ACR::toString).collect(Collectors.joining("+"))
        );
        // make sure the redirect URI is properly URL encoded
        assertTrue(loginUrl.contains(URLEncoder.encode(redirectUri, "utf-8")));
        assertEquals(URLUtils.parseParameters(expectedParams), URLUtils.parseParameters(new URL(loginUrl).getQuery()));
    }

    @Test
    public void remoteAccessTokenValidation() throws IOException, URISyntaxException {
        JWTClaimsSet tokenClaims = TokenHelper.accessTokenClaimsBuilder().build();
        // introspection response
        mock.expect(HttpMethod.POST, expectedIntrospectEndpoint.toString())
            .thenReturn(TokenHelper.introspectionResponse(tokenClaims));

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
        mock.expect(HttpMethod.GET, expectedJwksEndpoint.toString())
            .thenReturn(TokenHelper.jwks().toString());

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
        mock.expect(HttpMethod.GET, expectedJwksEndpoint.toString())
            .thenReturn(TokenHelper.jwks().toString());
        mock.expect(HttpMethod.POST, expectedTokenEndpoint.toString())
            .thenReturn(tokenResponse.toHTTPResponse().getBody());

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
