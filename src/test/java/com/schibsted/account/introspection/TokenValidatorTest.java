/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.jwt.JWTClaimsSet;
import com.schibsted.account.testutil.TokenHelper;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TokenValidatorTest {
    private static final String token = "test_token";

    private TokenValidator tokenValidatorInstance(IntrospectionResult mockedIntrospectionResult) {
        TokenIntrospector tokenIntrospectorMock = mock(TokenIntrospector.class);
        when(tokenIntrospectorMock.introspectToken(token)).thenReturn(mockedIntrospectionResult);
        return new TokenValidator(Collections.singletonList(tokenIntrospectorMock));
    }

    private IntrospectionResult validate(Collection<String> requiredScopes, String requiredAudience) {
        JWTClaimsSet tokenClaims = TokenHelper.accessTokenClaimsBuilder().build();
        TokenValidator validator = tokenValidatorInstance(new IntrospectionResult(true, tokenClaims));
        return validator.validateAccessToken(token, TokenHelper.ISSUER, requiredScopes, requiredAudience);
    }

    @Test(expected = InvalidTokenException.MissingRequiredScopes.class)
    public void validateAccessTokenChecksRequiredScopes() {
        validate(Arrays.asList("scope1", "unexpected_scope"), TokenHelper.CLIENT_ID);
    }

    @Test(expected = InvalidTokenException.MissingRequiredAudience.class)
    public void validateAccessTokenChecksExpectedAudience() {
        validate(TokenHelper.SCOPES, "unexpected_audience");
    }

    @Test(expected = InvalidTokenException.IntrospectionFailed.class)
    public void validateAccessTokenReturnsInactiveWhenIntrospectionFails() {
        TokenValidator validator = tokenValidatorInstance(null);
        validator.validateAccessToken(token, TokenHelper.ISSUER, TokenHelper.SCOPES, TokenHelper.CLIENT_ID);
    }

    @Test(expected = InvalidTokenException.IncorrectIssuer.class)
    public void validateAccessTokenChecksExpectedIssuer() {
        JWTClaimsSet tokenClaims = TokenHelper.accessTokenClaimsBuilder().build();
        TokenValidator validator = tokenValidatorInstance(new IntrospectionResult(true, tokenClaims));
        validator.validateAccessToken(token, "wrong issuer", TokenHelper.SCOPES, TokenHelper.CLIENT_ID);
    }

    @Test
    public void validateAccessTokenChecksExpectedIssuerIgnoringTrailingSlash() {
        JWTClaimsSet tokenClaims = TokenHelper.accessTokenClaimsBuilder().issuer(TokenHelper.ISSUER + "/").build();
        TokenValidator validator = tokenValidatorInstance(new IntrospectionResult(true, tokenClaims));
        IntrospectionResult introspectionResult = validator.validateAccessToken(token,
            "https://issuer.example.com",
            TokenHelper.SCOPES,
            TokenHelper.CLIENT_ID);
        assertTrue(introspectionResult.isActive());
    }

    @Test
    public void validateAccessTokenShouldAllowNullRequiredScopes() {
        IntrospectionResult introspectionResult = validate(null, TokenHelper.CLIENT_ID);
        assertTrue(introspectionResult.isActive());
    }

    @Test
    public void validateAccessTokenShouldAllowEmptyRequiredScopes() {
        IntrospectionResult introspectionResult = validate(Collections.emptyList(), TokenHelper.CLIENT_ID);
        assertTrue(introspectionResult.isActive());
    }

    @Test
    public void validateAccessTokenShouldAllowNullRequiredAudience() {
        IntrospectionResult introspectionResult = validate(TokenHelper.SCOPES, null);
        assertTrue(introspectionResult.isActive());
    }

    @Test
    public void validateAccessTokenShouldAllowEmptyRequiredAudience() {
        IntrospectionResult introspectionResult = validate(TokenHelper.SCOPES, "");
        assertTrue(introspectionResult.isActive());
    }
}
