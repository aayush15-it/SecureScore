package com.securescore.scanner;

/**
 * Validated scan target passed to each SecurityCheck.
 * Only created after SSRF validation passes.
 */
public record Target(
    String originalUrl,
    String normalizedUrl,
    String hostname,
    String displayHost,
    boolean isHttps
) {
    public String httpUrl() {
        return "http://" + hostname;
    }

    public String httpsUrl() {
        return "https://" + hostname;
    }
}
