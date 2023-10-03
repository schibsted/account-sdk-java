/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.schibsted.account.token.verifier.IDTokenSecurityContext;
import com.schibsted.account.token.verifier.IDTokenVerifier;
import kong.unirest.HttpRequestWithBody;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Wrapper for functionality using the Nimbus OAuth 2.0 SDK.
 */
public class NimbusWrapper {
    private static final Logger logger = LoggerFactory.getLogger(NimbusWrapper.class);

    private final String issuer;
    private final ClientSecretBasic clientCredentials;
    private final URI tokenEndpoint;
    private final DefaultJWTProcessor<IDTokenSecurityContext> idTokenProcessor;

    /**
     * Constructor.
     *
     * @param issuer            issuer identifier of the OIDC/OAuth 2.0 server
     * @param clientCredentials credentials to be used in requests to the server
     * @param jwksEndpoint      URL to the JWKS published by the server
     * @param tokenEndpoint     URL to the token endpoint of the server
     */
    public NimbusWrapper(String issuer, ClientSecretBasic clientCredentials, URL jwksEndpoint, URI tokenEndpoint) {
        this.clientCredentials = clientCredentials;
        this.issuer = issuer;
        this.tokenEndpoint = tokenEndpoint;
        this.idTokenProcessor = new DefaultJWTProcessor<>();
        this.idTokenProcessor.setJWTClaimsSetVerifier(new IDTokenVerifier());
        JWSKeySelector<IDTokenSecurityContext> keySelector = new JWSVerificationKeySelector<>(
            JWSAlgorithm.RS256,
            JWKSourceBuilder.<IDTokenSecurityContext>create(jwksEndpoint, new UnirestResourceRetriever())
                .build()
        );
        this.idTokenProcessor.setJWSKeySelector(keySelector);

    }

    /**
     * Makes an access token request using the "Client Credentials Grant".
     *
     * @param scope     requested scope of the token
     * @param resources intended resources of the token
     * @return the access token response.
     * @throws HTTPException   if the HTTP request failed
     * @throws NimbusException if the response could not be parsed
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.4">OAuth 2.0, section 4.4</a>
     */
    public AccessTokenResponse clientCredentialsGrant(Collection<String> scope, List<URI> resources) throws HTTPException, NimbusException {
        logger.debug("Requesting token with client credentials...");

        TokenRequest request = new TokenRequest(this.tokenEndpoint, this.clientCredentials,
            new ClientCredentialsGrant(), Scope.parse(scope), resources, null);
        return makeOAuthTokenRequest(request);
    }

    /**
     * Makes an OpenID Connect access token request, using the "Authorization Code Grant".
     *
     * @param authCode    authorization code
     * @param redirectUri redirect URI associated with the authorization code
     * @return the access token response.
     * @throws HTTPException   if the HTTP request failed
     * @throws NimbusException if the response could not be parsed
     * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest">OpenID Connect 1.0, section 3.1.3.1</a>
     */
    public OIDCTokenResponse authorizationCodeGrant(String authCode,
                                                    URI redirectUri) throws HTTPException, NimbusException {
        logger.debug("Exchanging auth code for user token...");
        TokenRequest request = new TokenRequest(this.tokenEndpoint, this.clientCredentials,
            new AuthorizationCodeGrant(new AuthorizationCode(authCode), redirectUri));
        return makeOIDCTokenRequest(request);
    }

    /**
     * Makes a token refresh request.
     *
     * @param refreshToken refresh token
     * @return the access token response
     * @throws HTTPException   if the HTTP request failed
     * @throws NimbusException if the response could not be parsed
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-6">OAuth 2.0, section 6</a>
     */
    public AccessTokenResponse refreshTokenGrant(String refreshToken) throws HTTPException, NimbusException {
        logger.debug("Requesting new token with refresh token...");
        TokenRequest request = new TokenRequest(this.tokenEndpoint, this.clientCredentials,
            new RefreshTokenGrant(new RefreshToken(refreshToken)));
        return makeOAuthTokenRequest(request);
    }

    /**
     * Validates an ID token.
     *
     * @param idToken       JWT to validate
     * @param expectedNonce expected nonce of the ID Token
     * @return the claims of the ID Token
     * @throws NimbusException if the ID Token was invalid
     * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">OpenID Connect 1.0, section 3.1.3.7</a>
     */
    public IDTokenClaimsSet validateIDToken(JWT idToken, String expectedNonce) throws NimbusException {
        try {
            IDTokenSecurityContext context = new IDTokenSecurityContext(issuer, clientCredentials.getClientID().getValue(), expectedNonce);
            JWTClaimsSet verified = idTokenProcessor.process(idToken, context);
            return new IDTokenClaimsSet(verified);
        } catch (JOSEException | BadJOSEException e) {
            logger.error("Could not verify ID Token: {}", e.getMessage());
            throw new NimbusException(e);
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            logger.error("Could not parse ID Token: {}", e.getMessage());
            throw new NimbusException(e);
        }
    }

    private AccessTokenResponse makeOAuthTokenRequest(TokenRequest request) throws HTTPException, NimbusException {
        TokenResponse tokenResponse;
        try {
            tokenResponse = TokenResponse.parse(makeHTTPRequest(request.toHTTPRequest()));
        } catch (ParseException e) {
            throw new NimbusException(e);
        }

        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse error = (TokenErrorResponse) tokenResponse;
            throw new NimbusException(error.getErrorObject());
        }

        return (AccessTokenResponse) tokenResponse;
    }

    private OIDCTokenResponse makeOIDCTokenRequest(TokenRequest request) throws HTTPException, NimbusException {
        TokenResponse tokenResponse;
        try {
            tokenResponse = OIDCTokenResponseParser.parse(makeHTTPRequest(request.toHTTPRequest()));
        } catch (ParseException e) {
            throw new NimbusException(e);
        }

        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse error = (TokenErrorResponse) tokenResponse;
            throw new NimbusException(error.getErrorObject());
        }

        return (OIDCTokenResponse) tokenResponse;
    }

    private JSONObject makeHTTPRequest(HTTPRequest httpRequest) throws HTTPException {
        HttpRequestWithBody request = Unirest.post(httpRequest.getURL().toString());

        Map<String, List<String>> headers = httpRequest.getHeaderMap();
        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            for (String value : header.getValue()) {
                request.header(header.getKey(), value);
            }
        }

        try {
            // Rewritten due to usage of deprecated API
            boolean isPost = HTTPRequest.Method.POST.equals(httpRequest.getMethod());
            String body = isPost ? httpRequest.getBody() : httpRequest.getURL().getQuery();
            HttpResponse<String> response = request.body(body).asString();

            String responseBody = response.getBody();
            Map<String, Object> parsedBody = JSONObjectUtils.parse(responseBody != null ? responseBody : "");

            return new JSONObject(parsedBody);
        } catch (UnirestException | java.text.ParseException e) {
            throw new HTTPException(e);
        }
    }
}
