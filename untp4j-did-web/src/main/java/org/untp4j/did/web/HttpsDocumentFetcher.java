package org.untp4j.did.web;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Fetches DID documents over HTTPS with conservative limits: HTTPS only, no redirects,
 * bounded time and size.
 */
public final class HttpsDocumentFetcher implements DocumentFetcher {

    /** Default maximum DID document size. */
    public static final int DEFAULT_MAX_BYTES = 64 * 1024;

    private final HttpClient client;
    private final Duration timeout;
    private final int maxBytes;

    public HttpsDocumentFetcher() {
        this(Duration.ofSeconds(10), DEFAULT_MAX_BYTES);
    }

    public HttpsDocumentFetcher(Duration timeout, int maxBytes) {
        this.timeout = timeout;
        this.maxBytes = maxBytes;
        this.client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public byte[] fetch(URI url) throws IOException {
        if (!"https".equals(url.getScheme())) {
            throw new IOException("Only https is allowed: " + url);
        }
        HttpRequest request = HttpRequest.newBuilder(url)
                .timeout(timeout)
                .header("Accept", "application/did+ld+json, application/did+json, application/json")
                .build();
        HttpResponse<InputStream> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted fetching " + url, e);
        }
        try (InputStream body = response.body()) {
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode() + " from " + url);
            }
            byte[] bytes = body.readNBytes(maxBytes + 1);
            if (bytes.length > maxBytes) {
                throw new IOException("DID document exceeds " + maxBytes + " bytes: " + url);
            }
            return bytes;
        }
    }
}
