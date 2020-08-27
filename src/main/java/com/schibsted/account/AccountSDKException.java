/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account;

/**
 * {@code AccountSDKException} is the superclass of all exceptions thrown by this SDK.
 */
public class AccountSDKException extends RuntimeException {
    public AccountSDKException() {
        super();
    }

    public AccountSDKException(String message, Throwable cause) {
        super(message, cause);
    }
}
