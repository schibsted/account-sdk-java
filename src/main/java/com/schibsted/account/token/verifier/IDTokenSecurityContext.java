/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.token.verifier;

import com.nimbusds.jose.proc.SimpleSecurityContext;

/**
 * {@code IDTokenSecurityContext} contains the necessary data to properly verify an ID Token.
 *
 * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">OpenID Connect, section 3.1.3.7</a>
 */
public class IDTokenSecurityContext extends SimpleSecurityContext {
    public IDTokenSecurityContext(String expectedIssuer, String clientId, String expectedNonce) {
        put("issuer", expectedIssuer);
        put("client_id", clientId);
        put("nonce", expectedNonce);
    }

    public String getIssuer() {
        return (String) get("issuer");
    }

    public String getClientId() {
        return (String) get("client_id");
    }

    public String getNonce() {
        return (String) get("nonce");
    }
}
