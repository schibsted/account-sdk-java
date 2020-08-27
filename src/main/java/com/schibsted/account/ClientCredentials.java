/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account;

/**
 * Client credentials issued by the OpenID Connect/OAuth server.
 */
public class ClientCredentials {
    /**
     * Client identifier, corresponds to the "client_id" parameter.
     */
    private final String clientID;
    /**
     * Client secret, corresponds to the "client_secret" parameter.
     */
    private final String clientSecret;

    public ClientCredentials(String clientID, String clientSecret) {
        this.clientID = clientID;
        this.clientSecret = clientSecret;
    }

    public String getClientID() {
        return clientID;
    }

    public String getClientSecret() {
        return clientSecret;
    }
}
