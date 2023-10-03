/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.nimbus;

import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.ResourceRetriever;

import java.net.URL;

/**
 * Implementation of {@link RemoteJWKSet} pre-configured with a {@link ResourceRetriever} that uses Unirest for HTTP
 * requests.
 * {@link RemoteJWKSet} has been deprecated
 */
@Deprecated
public class UnirestRemoteJWKSet<C extends SecurityContext> extends RemoteJWKSet<C> {

    public UnirestRemoteJWKSet(URL jwkSetURL) {
        super(jwkSetURL, new UnirestResourceRetriever());
    }
}
