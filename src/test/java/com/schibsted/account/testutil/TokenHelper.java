/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.testutil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import net.minidev.json.JSONObject;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;

public class TokenHelper {
    public static final String ISSUER = "https://issuer.example.com";
    public static final Collection<String> SCOPES = Arrays.asList("scope1", "scope2");
    public static final String CLIENT_ID = "client1";
    public static final String USER_ID = "user1";
    public static final String KEY_ID = "test_key";
    public static final KeyPair KEY_PAIR = generateRSAKeyPair();

    private static final String USER_TOKEN_SECRET_KEY = "super secret key of at least 256 bits";

    public static JWTClaimsSet.Builder accessTokenClaimsBuilder() {
        return new JWTClaimsSet.Builder()
            .issuer(ISSUER)
            .audience(CLIENT_ID)
            .issueTime(now())
            .expirationTime(later(10))
            .claim("scope", String.join(" ", SCOPES))
            .claim("client_id", CLIENT_ID);
    }

    public static String createClientAccessToken() throws JOSEException {
        JWTClaimsSet claims = accessTokenClaimsBuilder().build();
        return createClientAccessToken(claims);
    }

    public static String createClientAccessToken(JWTClaimsSet claims) throws JOSEException {
        return createAsymmetricallySignedJWT(claims).serialize();
    }

    public static String createUserAccessToken() throws JOSEException {
        JWTClaimsSet claims = accessTokenClaimsBuilder()
            .subject(USER_ID)
            .build();
        return createUserAccessToken(claims);
    }

    public static String createUserAccessToken(JWTClaimsSet claims) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
            .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new MACSigner(USER_TOKEN_SECRET_KEY));
        return jwt.serialize();
    }

    public static SignedJWT createIdToken(String nonce) throws JOSEException, ParseException {
        IDTokenClaimsSet claims = new IDTokenClaimsSet(
            new Issuer(ISSUER),
            new Subject(USER_ID),
            Collections.singletonList(new Audience(CLIENT_ID)),
            now(),
            later(10)
        );
        claims.setAuthenticationTime(now());
        claims.setNonce(new Nonce(nonce));
        claims.setACR(new ACR("test_acr"));
        return createAsymmetricallySignedJWT(claims.toJWTClaimsSet());
    }

    public static JWKSet jwks() {
        RSAKey publicKey = new RSAKey.Builder((RSAPublicKey) KEY_PAIR.getPublic())
            .keyUse(KeyUse.SIGNATURE)
            .keyID(KEY_ID)
            .algorithm(JWSAlgorithm.RS256)
            .build();
        return new JWKSet(publicKey);
    }

    public static String introspectionResponse(JWTClaimsSet tokenClaims) {
        JSONObject claims = tokenClaims.toJSONObject();
        claims.put("active", true);
        return claims.toJSONString();
    }

    public static Date now() {
        return new Date();
    }

    public static Date later(int plusSeconds) {
        return new Date(System.currentTimeMillis() + plusSeconds * 1000);
    }

    private static SignedJWT createAsymmetricallySignedJWT(JWTClaimsSet claims) throws JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
            .keyID(KEY_ID)
            .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(KEY_PAIR.getPrivate()));
        return jwt;
    }

    private static KeyPair generateRSAKeyPair() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
