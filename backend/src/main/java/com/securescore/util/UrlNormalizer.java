package com.securescore.util;

import com.securescore.exception.InvalidUrlException;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;

@Component
public class UrlNormalizer {

    /**
     * Normalizes a URL for deduplication:
     * - Strips trailing slash
     * - Lowercases scheme and host
     * - Preserves path
     * - Strips fragment
     */
    public String normalize(String url) {
        try {
            URI uri = new URI(url.trim());
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "https";
            String host = uri.getHost() != null ? uri.getHost().toLowerCase() : "";
            int port = uri.getPort();
            String path = uri.getPath() != null ? uri.getPath() : "";

            // Strip trailing slash from root
            if (path.equals("/")) path = "";

            StringBuilder normalized = new StringBuilder();
            normalized.append(scheme).append("://").append(host);
            if (port != -1
                && !(scheme.equals("http") && port == 80)
                && !(scheme.equals("https") && port == 443)) {
                normalized.append(":").append(port);
            }
            normalized.append(path);

            return normalized.toString();
        } catch (URISyntaxException e) {
            throw new InvalidUrlException("Cannot normalize URL: " + url);
        }
    }

    /**
     * Extracts a clean display hostname (without www. prefix).
     */
    public String extractDisplayHost(String url) {
        try {
            URI uri = new URI(url.trim());
            String host = uri.getHost() != null ? uri.getHost().toLowerCase() : url;
            if (host.startsWith("www.")) {
                host = host.substring(4);
            }
            return host;
        } catch (URISyntaxException e) {
            return url;
        }
    }

    /**
     * Returns the HTTP version of a URL (for HTTPS redirect check).
     */
    public String toHttpUrl(String url) {
        try {
            URI uri = new URI(url.trim());
            return "http://" + uri.getHost() +
                (uri.getPort() != -1 ? ":" + uri.getPort() : "") +
                (uri.getPath() != null ? uri.getPath() : "");
        } catch (URISyntaxException e) {
            return url.replaceFirst("https://", "http://");
        }
    }
}
