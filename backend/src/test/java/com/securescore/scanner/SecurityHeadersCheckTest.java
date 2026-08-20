package com.securescore.scanner;

import com.securescore.entity.CheckStatus;
import com.securescore.entity.Severity;
import com.securescore.scanner.impl.SecurityHeadersCheck;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Security Headers Check Tests")
class SecurityHeadersCheckTest {

    private MockWebServer mockServer;
    private SecurityHeadersCheck check;

    @BeforeEach
    void setUp() throws IOException {
        mockServer = new MockWebServer();
        mockServer.start();
        check = new SecurityHeadersCheck();
    }

    @AfterEach
    void tearDown() throws IOException {
        mockServer.shutdown();
    }

    private Target buildTarget(String path) {
        String host = mockServer.getHostName();
        int port = mockServer.getPort();
        String url = "http://" + host + ":" + port + path;
        return new Target(url, url, host + ":" + port, host, false);
    }

    @Test
    @DisplayName("All security headers present should return all PASS")
    void allHeadersPresent() {
        mockServer.enqueue(new MockResponse()
            .addHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            .addHeader("Content-Security-Policy", "default-src 'self'")
            .addHeader("X-Frame-Options", "SAMEORIGIN")
            .addHeader("X-Content-Type-Options", "nosniff")
            .addHeader("Referrer-Policy", "strict-origin-when-cross-origin")
            .setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget("/"));
        assertThat(results).isNotEmpty();
        assertThat(results).allMatch(r -> r.getStatus() == CheckStatus.PASS);
    }

    @Test
    @DisplayName("Missing HSTS should return HIGH severity FAIL")
    void missingHsts() {
        mockServer.enqueue(new MockResponse()
            .addHeader("X-Frame-Options", "SAMEORIGIN")
            .addHeader("X-Content-Type-Options", "nosniff")
            .setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget("/"));
        assertThat(results).anyMatch(r ->
            r.getTitle().contains("HSTS") &&
            r.getStatus() == CheckStatus.FAIL &&
            r.getSeverity() == Severity.HIGH
        );
    }

    @Test
    @DisplayName("Missing CSP should return MEDIUM severity")
    void missingCsp() {
        mockServer.enqueue(new MockResponse()
            .addHeader("Strict-Transport-Security", "max-age=31536000")
            .addHeader("X-Frame-Options", "SAMEORIGIN")
            .addHeader("X-Content-Type-Options", "nosniff")
            .addHeader("Referrer-Policy", "strict-origin")
            .setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget("/"));
        assertThat(results).anyMatch(r ->
            r.getTitle().contains("Content-Security-Policy") &&
            r.getStatus() == CheckStatus.FAIL &&
            r.getSeverity() == Severity.MEDIUM
        );
    }

    @Test
    @DisplayName("HSTS with short max-age should be flagged")
    void hstsShortMaxAge() {
        mockServer.enqueue(new MockResponse()
            .addHeader("Strict-Transport-Security", "max-age=3600")  // 1 hour — too short
            .addHeader("Content-Security-Policy", "default-src 'self'")
            .addHeader("X-Frame-Options", "SAMEORIGIN")
            .addHeader("X-Content-Type-Options", "nosniff")
            .addHeader("Referrer-Policy", "strict-origin")
            .setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget("/"));
        assertThat(results).anyMatch(r ->
            r.getTitle().contains("HSTS") &&
            r.getStatus() == CheckStatus.FAIL
        );
    }
}
