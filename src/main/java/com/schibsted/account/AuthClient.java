/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.schibsted.account.introspection.*;
import com.schibsted.account.nimbus.HTTPException;
import com.schibsted.account.nimbus.NimbusException;
import com.schibsted.account.nimbus.NimbusWrapper;
import com.schibsted.account.token.AccessToken;
import com.schibsted.account.token.IDToken;
import com.schibsted.account.token.RefreshToken;
import com.schibsted.account.token.UserTokens;
import com.schibsted.account.util.Helpers;
import kong.unirest.Unirest;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * {@code AuthClient} handles both obtaining and introspecting OAuth tokens.
 * Use {@link AuthClient.Builder} to create a new instance configured with the necessary URLs
 * (see {@link AuthClient.Environment} to use pre-configured URLs for Schibsted account).
 */
public class AuthClient {

    private static final String OAUTH_TOKEN_ENDPOINT = "/oauth/token";
    private static final String OAUTH_INTROSPECT_ENDPOINT = "/oauth/introspect";
    private static final String OAUTH_JWKS_ENDPOINT = "/oauth/jwks";
    private static final String OAUTH_AUTHENTICATION_ENDPOINT = "/oauth/authorize";
    private static final Map<Environment, URI> environmentURIs = Collections.unmodifiableMap(Stream.of(
        new AbstractMap.SimpleEntry<>(Environment.DEV, URI.create("https://identity-dev.schibsted.com")),
        new AbstractMap.SimpleEntry<>(Environment.PRE, URI.create("https://identity-pre.schibsted.com")),
        new AbstractMap.SimpleEntry<>(Environment.PRO, URI.create("https://login.schibsted.com")),
        new AbstractMap.SimpleEntry<>(Environment.PRO_NO, URI.create("https://payment.schibsted.no"))
        ).collect(Collectors.toMap(e -> e.getKey(), e -> e.getValue()))
    );

    static {
        Unirest.config().setDefaultHeader("X-OIDC", "v1");
    }

    private final URI serverAddress;
    private final String issuer;
    private final NimbusWrapper nimbus;
    private ClientCredentials clientCredentials;
    private TokenValidator tokenValidator;

    private AuthClient(URI serverAddress, URL jwksURL, ClientCredentials clientCredentials, TokenValidator tokenValidator) {
        this.serverAddress = serverAddress;
        this.issuer = getIssuer(serverAddress);
        this.clientCredentials = clientCredentials;
        this.tokenValidator = tokenValidator;
        this.nimbus = new NimbusWrapper(
            this.issuer,
            new ClientSecretBasic(new ClientID(clientCredentials.getClientID()),
                new Secret(clientCredentials.getClientSecret())),
            jwksURL,
            serverAddress.resolve(OAUTH_TOKEN_ENDPOINT)
        );
    }

    private String getIssuer(URI serverAddress) {
        return serverAddress.toString();
    }

    /**
     * Obtains a client token, using the client credentials.
     *
     * @return the issued client token
     * @throws AccountSDKException if a token could not be obtained
     * @see <a href="https://techdocs.login.schibsted.com/oauth/token/#grant-type-client-credentials-for-server-tokens">Obtaining client tokens</a>
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.4">OAuth 2.0 Client Credentials Grant</a>
     */
    public AccessToken clientCredentialsGrant() {
        return clientCredentialsGrant(null, null);
    }

    /**
     * Obtains a client token, using the client credentials.
     *
     * @param scope requested scope of token
     * @return the issued client token
     * @throws AccountSDKException if a token could not be obtained
     * @see <a href="https://techdocs.login.schibsted.com/oauth/token/#grant-type-client-credentials-for-server-tokens">Obtaining client tokens</a>
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.4">OAuth 2.0 Client Credentials Grant</a>
     */
    public AccessToken clientCredentialsGrant(Collection<String> scope) {
        return clientCredentialsGrant(scope, null);
    }

    /**
     * Obtains a client token (using the client credentials) with the given scope intended for the given resources.
     *
     * @param scope     requested scope of token
     * @param resources intended resources of the token
     * @return the issued client token
     * @throws AccountSDKException if a token could not be obtained
     * @see <a href="https://techdocs.login.schibsted.com/oauth/token/#grant-type-client-credentials-for-server-tokens">Obtaining client tokens</a>
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.4">OAuth 2.0 Client Credentials Grant</a>
     */
    public AccessToken clientCredentialsGrant(Collection<String> scope, List<URI> resources) {
        AccessTokenResponse tokenResponse;
        try {
            tokenResponse = nimbus.clientCredentialsGrant(scope, resources);
        } catch (HTTPException | NimbusException e) {
            throw new AccountSDKException("Obtaining a client token failed", e);
        }

        com.nimbusds.oauth2.sdk.token.AccessToken accessToken = tokenResponse.getTokens().getAccessToken();
        List<String> tokenScope = accessToken.getScope() != null ? accessToken.getScope().toStringList() : null;
        return new AccessToken(accessToken.toString(), tokenScope, accessToken.getLifetime());
    }

    /**
     * Obtains user tokens (access token, ID Token, and possibly refresh token).
     *
     * @param authCode      issued OAuth authorization code to exchange for tokens
     * @param redirectURI   client redirect URI associated with the authorization code (specified in the authentication
     *                      request, see {@link AuthClient#getLoginURL(URI, String, String, Collection)})
     * @param expectedNonce the nonce associated with the authorization code (specified in the authentication request)
     * @return the issued user tokens
     * @throws AccountSDKException if no tokens could be obtained
     * @see <a href="https://techdocs.login.schibsted.com/oauth/token/#grant-type-authorization-code-for-user-tokens">Obtaining user tokens</a>
     * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint">OpenID Connect Authorization Code Flow</a>
     */
    public UserTokens authorizationCodeGrant(String authCode, URI redirectURI, String expectedNonce) {
        OIDCTokenResponse tokenResponse;
        try {
            tokenResponse = nimbus.authorizationCodeGrant(authCode, redirectURI);
        } catch (HTTPException | NimbusException e) {
            throw new AccountSDKException("Exchanging the authorization code for a token failed", e);
        }
        return parseUserTokens(tokenResponse, expectedNonce);
    }

    /**
     * Obtains new tokens, using a refresh token.
     *
     * @param refreshToken refresh token to use
     * @return the refreshed tokens
     * @see <a href="https://techdocs.login.schibsted.com/oauth/token/#grant-type-refresh-token-for-user-tokens">Refreshing tokens</a>
     * @see <a href="https://tools.ietf.org/html/rfc6749#section-6">OAuth 2.0 Refreshing an access token</a>
     */
    public UserTokens refreshTokenGrant(String refreshToken) {
        AccessTokenResponse tokenResponse;
        try {
            tokenResponse = nimbus.refreshTokenGrant(refreshToken);
        } catch (HTTPException | NimbusException e) {
            throw new AccountSDKException("Using the refresh token failed", e);
        }
        return parseUserTokens(tokenResponse);
    }

    /**
     * Creates the login URL to redirect the user to, making an OpenID Connect authentication request.
     *
     * @param redirectUri URL (that must be pre-registered for the client) to which the response will be sent
     *                    after the user authentication is completed
     * @param state       opaque value to maintain state between the request and the response delivered to the
     *                    {@code redirectURI}. This should be verified upon receiving the response, to prevent
     *                    Cross-Site Request Forgery.
     * @param nonce       opaque value to associate a session with the ID Token that will be issued on successful
     *                    user authentication
     * @param scopes      requested scope, must contain the {@code "openid"} value
     * @return the URL to redirect the user to for authentication
     * @see <a href="https://techdocs.login.schibsted.com/oauth/authorize/">User login</a>
     * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OpenID Connect Authentication Request</a>
     */
    public URI getLoginURL(URI redirectUri, String state, String nonce, Collection<String> scopes) {
        if (redirectUri == null) {
            throw new IllegalArgumentException("redirectUri may not be null");
        }
        if (state == null || state.isEmpty()) {
            throw new IllegalArgumentException("state may not be null or empty");
        }
        if (nonce == null || nonce.isEmpty()) {
            throw new IllegalArgumentException("nonce may not be null or empty");
        }
        if (scopes == null || scopes.isEmpty()) {
            throw new IllegalArgumentException("scopes may not be null or empty");
        }

        AuthenticationRequest authReq = new AuthenticationRequest.Builder(
            new ResponseType(ResponseType.Value.CODE),
            Scope.parse(scopes),
            new ClientID(clientCredentials.getClientID()),
            redirectUri
        )
            .endpointURI(this.serverAddress.resolve(OAUTH_AUTHENTICATION_ENDPOINT))
            .state(new State(state))
            .nonce(new Nonce(nonce))
            .build();
        return authReq.toURI();
    }

    /**
     * Validates an access token, by introspecting it and checking has all required scopes and the expected audience.
     *
     * @param token            token to validate
     * @param requiredScopes   required scopes of the token
     * @param requiredAudience expected audience of the token
     * @return the authorization data associated with the validated token
     * @throws IllegalArgumentException if this instance is not configured to perform token validation
     * @throws InvalidTokenException    if the token is invalid
     */

    public IntrospectionResult validateAccessToken(String token, Collection<String> requiredScopes, String requiredAudience) {
        if (tokenValidator == null) {
            throw new IllegalArgumentException("This client is not configured for token validation");
        }
        return tokenValidator.validateAccessToken(token, this.issuer, requiredScopes, requiredAudience);
    }

    private UserTokens parseUserTokens(AccessTokenResponse tokenResponse) {
        com.nimbusds.oauth2.sdk.token.AccessToken accessToken = tokenResponse.getTokens().getAccessToken();
        AccessToken at = new AccessToken(accessToken.toString(), accessToken.getScope().toStringList(), accessToken.getLifetime());

        RefreshToken rt = null;
        if (tokenResponse.getTokens().getRefreshToken() != null) {
            rt = new RefreshToken(tokenResponse.getTokens().getRefreshToken().toString());
        }
        return new UserTokens(null, at, rt);
    }

    private UserTokens parseUserTokens(OIDCTokenResponse tokenResponse, String expectedNonce) {
        UserTokens tokens = parseUserTokens(tokenResponse);
        IDTokenClaimsSet claims;
        try {
            claims = nimbus.validateIDToken(tokenResponse.getOIDCTokens().getIDToken(), expectedNonce);
        } catch (NimbusException e) {
            throw new AccountSDKException("Verifying the ID Token failed", e);
        }
        IDToken idToken = new IDToken(
            claims.getIssuer().getValue(),
            claims.getSubject().getValue(),
            Helpers.toInstant(claims.getAuthenticationTime()),
            claims.getACR() != null ? claims.getACR().getValue() : null,
            Helpers.toInstant(claims.getIssueTime()),
            Helpers.toInstant(claims.getExpirationTime())
        );
        return new UserTokens(idToken, tokens.getAccessToken(), tokens.getRefreshToken());
    }

    /**
     * Markers for the different environments of Schibsted account.
     */
    public enum Environment {
        DEV, PRE, PRO, PRO_NO
    }

    /**
     * Builder for configuring and creating a new instance of {@link AuthClient}.
     */
    public static class Builder {
        private final ClientCredentials clientCredentials;
        private final URI serverAddress;
        private final URL jwksURL;
        private final List<TokenIntrospector> tokenIntrospectors;

        /**
         * Constructor for creating {@link AuthClient} configured to communicate with Schibsted account's production
         * environment.
         *
         * @param clientCredentials issued client credentials
         */
        public Builder(ClientCredentials clientCredentials) {
            this(clientCredentials, Environment.PRO);
        }

        /**
         * Constructor specifying which Schibsted account environment to use.
         *
         * @param clientCredentials issued client credentials
         * @param environment       the Schibsted account environment to use
         */
        public Builder(ClientCredentials clientCredentials, Environment environment) {
            this(clientCredentials, environmentURIs.get(environment));
        }

        /**
         * Constructor specifying the URL of the OAuth server.
         *
         * @param clientCredentials issued client credentials
         * @param serverAddress     URL of the OpenID Connect/OAuth 2.0 server
         */
        public Builder(ClientCredentials clientCredentials, URI serverAddress) {
            this.clientCredentials = clientCredentials;
            this.serverAddress = serverAddress;
            try {
                this.jwksURL = this.serverAddress.resolve(OAUTH_JWKS_ENDPOINT).toURL();
            } catch (MalformedURLException e) {
                throw new AccountSDKException("Failed to resolve JWKS endpoint", e);
            }
            this.tokenIntrospectors = new ArrayList<>(2);
        }

        /**
         * Enables local token introspection.
         *
         * @return this {@code Builder}
         * @see <a href="https://techdocs.login.schibsted.com/token-introspection/#local-token-introspection">Local token introspection</a>
         */
        public Builder withLocalTokenIntrospection() {
            this.tokenIntrospectors.add(new TokenIntrospectorJWKS(jwksURL));
            return this;
        }

        /**
         * Enables remote token introspection.
         *
         * @return this {@code Builder}
         * @see <a href="https://techdocs.login.schibsted.com/token-introspection/#token-introspection-request">Token introspection request</a>
         * @see <a href="https://tools.ietf.org/html/rfc7662">OAuth 2.0 Token Introspection</a>
         */
        public Builder withRemoteTokenIntrospection() {
            this.tokenIntrospectors.add(new TokenIntrospectorRemote(this.serverAddress.resolve(OAUTH_INTROSPECT_ENDPOINT), clientCredentials));
            return this;
        }

        /**
         * Builds an {@code AuthClient} with the configured properties.
         *
         * @return configured {@code AuthClient} instance
         */
        public AuthClient build() {
            TokenValidator tokenValidator = null;
            if (!tokenIntrospectors.isEmpty()) {
                tokenValidator = new TokenValidator(tokenIntrospectors);
            }

            return new AuthClient(serverAddress, jwksURL, this.clientCredentials, tokenValidator);
        }
    }
}
