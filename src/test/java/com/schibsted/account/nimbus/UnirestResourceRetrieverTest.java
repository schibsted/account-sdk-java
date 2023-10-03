package com.schibsted.account.nimbus;

import com.nimbusds.jose.util.Resource;
import kong.unirest.HttpMethod;
import kong.unirest.MockClient;
import org.apache.http.HttpHeaders;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;

import static junit.framework.TestCase.assertEquals;

public class UnirestResourceRetrieverTest {

    private MockClient mock;

    @Before
    public void setUp() {
        mock = MockClient.register();
    }

    @After
    public void tearDown() {
        mock.verifyAll();
        mock.close();
        MockClient.clear();
    }

    @Test
    public void shouldReturnRetrievedResourceWhenHttpStatus200() throws IOException {
        // given
        URL url = new URL("http://www.example.test");
        String response = "expected_response";
        String contentType = "application/text+test";
        mock.expect(HttpMethod.GET, url.toString())
            .thenReturn(response)
            .withHeader(HttpHeaders.CONTENT_TYPE, contentType);
        UnirestResourceRetriever underTest = new UnirestResourceRetriever();

        // when
        Resource result = underTest.retrieveResource(url);

        // then
        assertEquals(
            response,
            result.getContent()
        );
        assertEquals(
            contentType,
            result.getContentType()
        );
    }

    @Test
    public void shouldThrowIOExceptionWhenHttpStatus400() throws IOException {
        // given
        URL url = new URL("http://www.example.test");
        String response = "expected_response";
        String contentType = "application/text+test";
        mock.expect(HttpMethod.GET, url.toString())
            .thenReturn(response)
            .withHeader(HttpHeaders.CONTENT_TYPE, contentType)
            .withStatus(400);
        UnirestResourceRetriever underTest = new UnirestResourceRetriever();

        // when / then
        Assert.assertThrows(
            IOException.class,
            () -> {
                underTest.retrieveResource(url);
            }
        );
    }
}
