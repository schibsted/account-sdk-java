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

}
