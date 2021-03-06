/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.nimbus;

import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;

/**
 * Implementation of {@link RemoteJWKSet} pre-configured with a {@link ResourceRetriever} that uses Unirest for HTTP
 * requests.
 */
public class UnirestRemoteJWKSet<C extends SecurityContext> extends RemoteJWKSet<C> {

    public UnirestRemoteJWKSet(URL jwkSetURL) {
        super(jwkSetURL, new UnirestResourceRetriever());
    }

    private static class UnirestResourceRetriever implements ResourceRetriever {
        private static final Logger logger = LoggerFactory.getLogger(UnirestResourceRetriever.class);

        @Override
        public Resource retrieveResource(URL url) throws IOException {
            try {
                HttpResponse<String> response = Unirest.get(url.toString()).asString();

                // Ensure 2xx status code
                final int statusCode = response.getStatus();
                final String statusMessage = response.getStatusText();
                if (statusCode > 299 || statusCode < 200) {
                    logger.error("Unexpected HTTP status code: '{} {}'", statusCode, statusMessage);
                    throw new IOException("HTTP " + statusCode + ": " + statusMessage);
                }

                return new Resource(response.getBody(), response.getHeaders().getFirst("Content-Type"));
            } catch (UnirestException e) {
                logger.error("HTTP request problem: '{}'", e.getMessage());
                throw new IOException("HTTP request problem", e);
            }

        }
    }
}
