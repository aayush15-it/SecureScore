package com.securescore.util;

import com.securescore.exception.InvalidUrlException;
import com.securescore.exception.SsrfException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * SSRF Protection: validates that a URL targets only public internet addresses.
 *
 * Blocks:
 * - localhost / 127.x.x.x / ::1
 * - Private IPv4 ranges (10.x, 172.16-31.x, 192.168.x)
 * - Link-local (169.254.x.x / fe80::/10)
 * - Cloud metadata endpoints (169.254.169.254, etc.)
 * - Non-http/https protocols
 * - Internal hostnames without TLD
 */
@Component
public class SsrfValidator {

    private static final Logger log = LoggerFactory.getLogger(SsrfValidator.class);

    private static final List<String> BLOCKED_HOSTNAMES = List.of(
        "localhost",
        "metadata.google.internal",
        "169.254.169.254",  // AWS metadata
        "metadata.azure.com",
        "100.100.100.200"   // Alibaba metadata
    );

    private static final Pattern INTERNAL_HOSTNAME_PATTERN =
        Pattern.compile("^[a-zA-Z0-9-]+$"); // single-label hostname (no dots = internal)

    /**
     * Validates a URL is safe to scan.
     * Throws InvalidUrlException or SsrfException if not safe.
     *
     * @param url the raw URL from the user
     * @return the parsed URI if valid
     */
    public URI validate(String url) {
        if (url == null || url.isBlank()) {
            throw new InvalidUrlException("URL cannot be empty.");
        }

        URI uri;
        try {
            uri = new URI(url.trim());
        } catch (URISyntaxException e) {
            throw new InvalidUrlException("Invalid URL format: " + e.getReason());
        }

        // Protocol check
        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            throw new InvalidUrlException(
                "Only http:// and https:// URLs are supported. Received: " + scheme);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new InvalidUrlException("URL must include a hostname.");
        }

        // Check blocked hostnames
        for (String blocked : BLOCKED_HOSTNAMES) {
            if (host.equalsIgnoreCase(blocked)) {
                throw new SsrfException("Blocked hostname: " + host);
            }
        }

        // Block single-label hostnames (internal machines like "server1")
        if (!host.contains(".") && !host.startsWith("[")) {
            throw new SsrfException("Single-label hostnames are not allowed: " + host);
        }

        // Resolve and check IP
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                validateIpAddress(addr);
            }
        } catch (UnknownHostException e) {
            throw new InvalidUrlException("Cannot resolve domain: " + host +
                ". Please check the URL and try again.");
        }

        return uri;
    }

    /**
     * Validates a redirect destination during scanning.
     * Same rules as validate() but used for mid-scan redirect hops.
     */
    public void validateRedirectDestination(String location) {
        if (location == null || location.isBlank()) {
            throw new SsrfException("Redirect location is empty.");
        }
        try {
            validate(location);
        } catch (InvalidUrlException | SsrfException e) {
            throw new SsrfException("Redirect destination blocked: " + e.getMessage());
        }
    }

    private void validateIpAddress(InetAddress addr) {
        byte[] bytes = addr.getAddress();

        if (addr.isLoopbackAddress()) {
            throw new SsrfException("Loopback address blocked: " + addr.getHostAddress());
        }
        if (addr.isSiteLocalAddress()) {
            throw new SsrfException("Private/site-local address blocked: " + addr.getHostAddress());
        }
        if (addr.isLinkLocalAddress()) {
            throw new SsrfException("Link-local address blocked: " + addr.getHostAddress());
        }
        if (addr.isMulticastAddress()) {
            throw new SsrfException("Multicast address blocked: " + addr.getHostAddress());
        }
        if (addr.isAnyLocalAddress()) {
            throw new SsrfException("Any-local address blocked: " + addr.getHostAddress());
        }

        // Extra check: 10.0.0.0/8
        if (bytes.length == 4 && (bytes[0] & 0xFF) == 10) {
            throw new SsrfException("Private range 10.x.x.x blocked.");
        }
        // 172.16.0.0/12
        if (bytes.length == 4 && (bytes[0] & 0xFF) == 172
            && (bytes[1] & 0xFF) >= 16 && (bytes[1] & 0xFF) <= 31) {
            throw new SsrfException("Private range 172.16-31.x.x blocked.");
        }
        // 100.64.0.0/10 (CGNAT)
        if (bytes.length == 4 && (bytes[0] & 0xFF) == 100
            && (bytes[1] & 0xFF) >= 64 && (bytes[1] & 0xFF) <= 127) {
            throw new SsrfException("CGNAT range blocked.");
        }
    }
}
