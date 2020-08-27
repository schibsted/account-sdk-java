/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

/**
 * Interface for introspecting a token.
 */
public interface TokenIntrospector {
    /**
     * Introspects the token.
     *
     * @param token the token to introspect
     * @return the introspection result, or {@code null} if the introspection failed
     */
    IntrospectionResult introspectToken(String token);
}
