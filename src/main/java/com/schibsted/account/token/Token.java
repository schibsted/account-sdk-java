/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.token;

import java.io.Serializable;

/**
 * {@code Token} is the superclass of all token types.
 */
abstract public class Token implements Serializable {
    protected String token;

    public Token(String token) {
        if (token == null) {
            throw new IllegalArgumentException("token may not be null");
        }
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
