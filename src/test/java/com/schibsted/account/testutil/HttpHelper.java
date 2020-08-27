/*
 * Copyright (c) 2020 Schibsted Media Group.
 * Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.testutil;

import com.nimbusds.oauth2.sdk.Request;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.util.URLUtils;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.util.EntityUtils;
import org.mockito.ArgumentMatcher;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;

public class HttpHelper {
    public static HttpResponse httpResponseMock(String responseBody) throws UnsupportedEncodingException {
        return httpResponseMock(200, responseBody);
    }

    public static HttpResponse httpResponseMock(int statusCode, String responseBody) throws UnsupportedEncodingException {
        HttpResponse httpResponse = new BasicHttpResponse(
            new BasicStatusLine(
                new ProtocolVersion("HTTP", 1, 1),
                statusCode,
                EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, null))
        );
        httpResponse.setEntity(new StringEntity(responseBody));
        return httpResponse;
    }

    public static ArgumentMatcher<HttpUriRequest> matchesExpectedRequest(Request expectedRequest) {
        return new RequestMatcher(expectedRequest);
    }

    private static class RequestMatcher implements ArgumentMatcher<HttpUriRequest> {
        private HTTPRequest expectedRequest;

        private RequestMatcher(Request expectedRequest) {
            this.expectedRequest = expectedRequest.toHTTPRequest();
        }

        @Override
        public boolean matches(HttpUriRequest request) {
            String requestBody;
            try {
                requestBody = EntityUtils.toString(((HttpEntityEnclosingRequest) request).getEntity());
            } catch (IOException e) {
                throw new RuntimeException("Could not read response", e);
            }

            Map<String, List<String>> expectedParams = URLUtils.parseParameters(expectedRequest.getQuery());
            Map<String, List<String>> actualParams = URLUtils.parseParameters(requestBody);
            return expectedRequest.getURL().toString().equals(request.getURI().toString()) &&
                request.getFirstHeader("Authorization").getValue().equals(expectedRequest.getAuthorization()) &&
                expectedParams.equals(actualParams);
        }
    }
}
