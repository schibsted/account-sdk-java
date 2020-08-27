/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.introspection;

import com.schibsted.account.AccountSDKException;

/**
 * {@code InvalidTokenException} is the superclass of exceptions thrown when an introspected token is invalid.
 */
public class InvalidTokenException extends AccountSDKException {
    public InvalidTokenException() { super(); }

    /**
     * Thrown when the issuer of the token does not match the expected identifier.
     */
    public static final class IncorrectIssuer extends InvalidTokenException {}
    /**
     * Thrown when the token could not be introspected.
     */
    public static final class IntrospectionFailed extends InvalidTokenException {}
    /**
     * Thrown when the intended audience of the token does not match the expected identifier.
     */
    public static final class MissingRequiredAudience extends InvalidTokenException {}
    /**
     * Thrown when all the required scopes are <strong>not</strong> in the token.
     */
    public static final class MissingRequiredScopes extends InvalidTokenException {}
}
