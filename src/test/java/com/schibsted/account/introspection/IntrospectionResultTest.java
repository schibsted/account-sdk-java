/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class IntrospectionResultTest {
    @Test
    public void inactiveResultShouldNotBeActive() {
        assertFalse(IntrospectionResult.inactive().isActive());
    }

    @Test
    public void constructorShouldHandleClientIdInClientIdClaim() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("client_id", "client1").build();
        IntrospectionResult result = new IntrospectionResult(true, claims);
        assertEquals("client1", result.getClient());
    }

    @Test
    public void constructorShouldHandleClientIdInAuthorizedPartyClaim() {
        JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("azp", "client1").build();
        IntrospectionResult result = new IntrospectionResult(true, claims);
        assertEquals("client1", result.getClient());
    }
}
