package com.securescore.scanner;

import com.securescore.entity.CheckStatus;
import com.securescore.entity.Severity;
import com.securescore.scanner.impl.CookieSecurityCheck;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Cookie Security Check Tests")
class CookieSecurityCheckTest {

    private MockWebServer mockServer;
    private CookieSecurityCheck check;

    @BeforeEach
    void setUp() throws IOException {
        mockServer = new MockWebServer();
        mockServer.start();
        check = new CookieSecurityCheck();
    }

    @AfterEach
    void tearDown() throws IOException {
        mockServer.shutdown();
    }

    private Target buildTarget() {
        String host = mockServer.getHostName();
        int port = mockServer.getPort();
        String url = "http://" + host + ":" + port;
        return new Target(url, url, host + ":" + port, host, false);
    }

    @Test
    @DisplayName("No cookies should return INFO result")
    void noCookies() {
        mockServer.enqueue(new MockResponse().setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget());
        assertThat(results).hasSize(1);
        assertThat(results.get(0).getSeverity()).isEqualTo(Severity.INFO);
    }

    @Test
    @DisplayName("Cookie with all security flags should PASS")
    void secureCookie() {
        mockServer.enqueue(new MockResponse()
            .addHeader("Set-Cookie", "session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/")
            .setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget());
        assertThat(results).allMatch(r -> r.getStatus() == CheckStatus.PASS);
    }

    @Test
    @DisplayName("Cookie missing Secure flag should fail")
    void missingSecureFlag() {
        mockServer.enqueue(new MockResponse()
            .addHeader("Set-Cookie", "session=abc123; HttpOnly; SameSite=Strict")
            .setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget());
        assertThat(results).anyMatch(r ->
            r.getTitle().contains("Secure") && r.getStatus() == CheckStatus.FAIL
        );
    }

    @Test
    @DisplayName("Cookie missing HttpOnly flag should fail")
    void missingHttpOnlyFlag() {
        mockServer.enqueue(new MockResponse()
            .addHeader("Set-Cookie", "session=abc123; Secure; SameSite=Strict")
            .setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget());
        assertThat(results).anyMatch(r ->
            r.getTitle().contains("HttpOnly") && r.getStatus() == CheckStatus.FAIL
        );
    }

    @Test
    @DisplayName("Cookie missing SameSite should fail with MEDIUM severity")
    void missingSameSite() {
        mockServer.enqueue(new MockResponse()
            .addHeader("Set-Cookie", "session=abc123; Secure; HttpOnly")
            .setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget());
        assertThat(results).anyMatch(r ->
            r.getTitle().contains("SameSite") &&
            r.getStatus() == CheckStatus.FAIL &&
            r.getSeverity() == Severity.MEDIUM
        );
    }

    @Test
    @DisplayName("Session cookie missing Secure should be HIGH severity")
    void sessionCookieMissingSecureIsHighSeverity() {
        mockServer.enqueue(new MockResponse()
            // "session" name matches heuristic for session cookies
            .addHeader("Set-Cookie", "session=abc123; HttpOnly; SameSite=Strict")
            .setResponseCode(200));

        List<CheckResult> results = check.execute(buildTarget());
        assertThat(results).anyMatch(r ->
            r.getTitle().contains("Secure") &&
            r.getSeverity() == Severity.HIGH
        );
    }

    @Test
    @DisplayName("Cookie parser handles multiple cookies correctly")
    void multipleCookies() {
        mockServer.enqueue(new MockResponse()
            .addHeader("Set-Cookie", "tracking=xyz; Secure; SameSite=Lax")
            .addHeader("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Strict")
            .setResponseCode(200));

        // Should not throw
        List<CheckResult> results = check.execute(buildTarget());
        assertThat(results).isNotEmpty();
    }
}
