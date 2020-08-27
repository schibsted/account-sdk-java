/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.nimbus;

import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * Internal exception wrapping all exceptions originating from the underlying OAuth library (Nimbus OAuth 2.0 SDK).
 */
public class NimbusException extends Exception {
    /* Make this a checked exception to help ensure sure it's handled within this SDK, and not leaked outside. */

    public NimbusException(ErrorObject error) {
        super(errorObjectToMessage(error));
    }

    public NimbusException(Throwable t) {
        super(t);
    }

    private static String errorObjectToMessage(ErrorObject error) {
        String msg = error.getCode();
        if (error.getDescription() != null) {
            msg += ": " + error.getDescription();
        }

        return msg;
    }
}
