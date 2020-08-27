/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.nimbus;

/**
 * Internal exception thrown when an HTTP request fails.
 */
public class HTTPException extends Exception {
    /* Make this a checked exception to help ensure sure it's handled within this SDK, and not leaked outside. */
    public HTTPException(Throwable t) {
        super(t);
    }
}
