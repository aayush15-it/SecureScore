package com.securescore.scanner;

import com.securescore.exception.InvalidUrlException;
import com.securescore.exception.SsrfException;
import com.securescore.util.SsrfValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SSRF Validator Tests")
class SsrfValidatorTest {

    private SsrfValidator validator;

    @BeforeEach
    void setUp() {
        validator = new SsrfValidator();
    }

    @Test
    @DisplayName("Valid public HTTPS URL should pass")
    void validHttpsUrl() {
        assertDoesNotThrow(() -> validator.validate("https://example.com"));
    }

    @Test
    @DisplayName("Valid public HTTP URL should pass")
    void validHttpUrl() {
        assertDoesNotThrow(() -> validator.validate("http://example.com"));
    }

    @ParameterizedTest
    @DisplayName("Private IP ranges should be blocked")
    @ValueSource(strings = {
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://172.31.255.255",
    })
    void privateIpRangesBlocked(String url) {
        assertThrows(SsrfException.class, () -> validator.validate(url));
    }

    @ParameterizedTest
    @DisplayName("Loopback addresses should be blocked")
    @ValueSource(strings = {
        "http://localhost",
        "http://127.0.0.1",
    })
    void loopbackAddressesBlocked(String url) {
        assertThrows(Exception.class, () -> validator.validate(url));
    }

    @Test
    @DisplayName("Cloud metadata endpoint should be blocked")
    void cloudMetadataBlocked() {
        assertThrows(SsrfException.class,
            () -> validator.validate("http://169.254.169.254/latest/meta-data/"));
    }

    @ParameterizedTest
    @DisplayName("Non-http/https schemes should be blocked")
    @ValueSource(strings = {
        "ftp://example.com",
        "file:///etc/passwd",
        "ssh://example.com",
        "jdbc:mysql://localhost/db"
    })
    void nonHttpSchemesBlocked(String url) {
        assertThrows(InvalidUrlException.class, () -> validator.validate(url));
    }

    @Test
    @DisplayName("Empty URL should be rejected")
    void emptyUrlRejected() {
        assertThrows(InvalidUrlException.class, () -> validator.validate(""));
    }

    @Test
    @DisplayName("URL without host should be rejected")
    void urlWithoutHostRejected() {
        assertThrows(InvalidUrlException.class, () -> validator.validate("https://"));
    }

    @Test
    @DisplayName("Single-label hostname should be blocked")
    void singleLabelHostnameBlocked() {
        // "internalserver" with no dots is an internal hostname
        assertThrows(SsrfException.class, () -> validator.validate("http://internalserver/"));
    }
}
