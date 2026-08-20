package com.securescore.scanner.impl;

import com.securescore.entity.CheckStatus;
import com.securescore.entity.Severity;
import com.securescore.scanner.CheckResult;
import com.securescore.scanner.SecurityCheck;
import com.securescore.scanner.Target;
import com.securescore.util.SsrfValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * CHECK 3: HTTPS Redirect
 *
 * Makes an HTTP request and inspects:
 * - Status code (must be 301 or 308 for permanent redirect)
 * - Location header destination (must be HTTPS)
 * - Redirect chain length
 * - Redirect loops
 * - Destination validation (SSRF safe)
 */
@Component
public class HttpsRedirectCheck implements SecurityCheck {

    private static final Logger log = LoggerFactory.getLogger(HttpsRedirectCheck.class);
    private static final String CHECK_NAME = "HTTPS_REDIRECT";

    @Value("${scanner.timeout.connect-ms:10000}")
    private int connectTimeoutMs;

    @Value("${scanner.timeout.read-ms:15000}")
    private int readTimeoutMs;

    @Value("${scanner.max-redirects:5}")
    private int maxRedirects;

    private final SsrfValidator ssrfValidator;

    public HttpsRedirectCheck(SsrfValidator ssrfValidator) {
        this.ssrfValidator = ssrfValidator;
    }

    @Override
    public String getCheckName() { return CHECK_NAME; }

    @Override
    public String getDisplayName() { return "HTTPS Redirect"; }

    @Override
    public List<CheckResult> execute(Target target) {
        List<CheckResult> results = new ArrayList<>();

        String httpUrl = target.httpUrl();
        List<String> redirectChain = new ArrayList<>();
        redirectChain.add(httpUrl);

        try {
            RedirectResult result = followRedirects(httpUrl, redirectChain, 0);
            results.add(analyzeResult(result, redirectChain));

        } catch (RedirectLoopException e) {
            results.add(CheckResult.builder(CHECK_NAME, "Redirect Loop Detected")
                .status(CheckStatus.FAIL)
                .severity(Severity.HIGH)
                .description("A redirect loop was detected. The server is stuck in an infinite redirect cycle.")
                .evidence("Redirect chain:\n" + String.join(" → \n", redirectChain))
                .whyItMatters("A redirect loop makes your website inaccessible to visitors. " +
                    "Browsers will show an error after following too many redirects.")
                .remediation(getRedirectLoopRemediation())
                .build());
        } catch (java.net.SocketTimeoutException e) {
            results.add(CheckResult.builder(CHECK_NAME, "HTTPS Redirect Check Timeout")
                .status(CheckStatus.UNKNOWN)
                .severity(Severity.UNKNOWN)
                .description("Connection timed out while checking HTTP redirect.")
                .evidence("Timed out connecting to: " + httpUrl)
                .whyItMatters("SecureScore could not check if HTTP redirects to HTTPS.")
                .remediation("Verify your server is reachable on HTTP port 80.")
                .build());
        } catch (IOException e) {
            results.add(CheckResult.builder(CHECK_NAME, "HTTPS Redirect Check Error")
                .status(CheckStatus.UNKNOWN)
                .severity(Severity.UNKNOWN)
                .description("Could not connect to the server on HTTP.")
                .evidence("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage())
                .whyItMatters("SecureScore could not verify whether HTTP redirects to HTTPS.")
                .remediation("Ensure your server is configured to respond on port 80.")
                .build());
        } catch (Exception e) {
            log.warn("HTTPS redirect check error for {}: {}", target.hostname(), e.getMessage());
            results.add(CheckResult.builder(CHECK_NAME, "HTTPS Redirect Check Error")
                .status(CheckStatus.ERROR)
                .severity(Severity.UNKNOWN)
                .description("An unexpected error occurred.")
                .evidence("Error: " + e.getClass().getSimpleName())
                .whyItMatters("SecureScore could not verify HTTPS redirect.")
                .remediation("Try scanning again.")
                .build());
        }

        return results;
    }

    private record RedirectResult(
        int statusCode,
        String location,
        boolean redirectsToHttps,
        boolean isPermanent,
        int hopCount
    ) {}

    private RedirectResult followRedirects(String url, List<String> chain, int hops)
        throws IOException, RedirectLoopException {

        if (hops > maxRedirects) {
            throw new RedirectLoopException("Too many redirects: " + hops);
        }

        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        conn.setRequestMethod("GET");
        conn.setInstanceFollowRedirects(false); // Manual redirect tracking
        conn.setRequestProperty("User-Agent", "SecureScore/1.0 Security Scanner");

        try {
            int status = conn.getResponseCode();
            String location = conn.getHeaderField("Location");

            if (isRedirect(status) && location != null) {
                // Validate redirect destination for SSRF
                String absoluteLocation = resolveAbsolute(url, location);
                try {
                    ssrfValidator.validateRedirectDestination(absoluteLocation);
                } catch (Exception e) {
                    // Redirect to blocked destination — treat as UNKNOWN
                    return new RedirectResult(status, absoluteLocation, false, isPermanentRedirect(status), hops);
                }

                // Check for loop
                if (chain.contains(absoluteLocation)) {
                    throw new RedirectLoopException("Loop detected at: " + absoluteLocation);
                }
                chain.add(absoluteLocation);

                // Check if this redirects to HTTPS
                if (absoluteLocation.startsWith("https://")) {
                    return new RedirectResult(status, absoluteLocation, true,
                        isPermanentRedirect(status), hops + 1);
                }

                // Follow next hop
                return followRedirects(absoluteLocation, chain, hops + 1);
            }

            // No redirect
            return new RedirectResult(status, location, url.startsWith("https://"),
                false, hops);

        } finally {
            conn.disconnect();
        }
    }

    private CheckResult analyzeResult(RedirectResult result, List<String> chain) {
        String chainEvidence = "Redirect chain:\n" +
            String.join(" → ", chain) +
            "\nFinal status code: " + result.statusCode() +
            (result.location() != null ? "\nLocation: " + result.location() : "");

        if (result.redirectsToHttps()) {
            if (result.isPermanent()) {
                return CheckResult.builder(CHECK_NAME, "HTTP Correctly Redirects to HTTPS")
                    .status(CheckStatus.PASS)
                    .severity(Severity.PASS)
                    .description("HTTP traffic is permanently redirected to HTTPS.")
                    .evidence(chainEvidence)
                    .whyItMatters("All visitors using HTTP are automatically upgraded to a secure HTTPS connection.")
                    .remediation("No action needed. Your redirect is correctly configured.")
                    .build();
            } else {
                return CheckResult.builder(CHECK_NAME, "HTTP Redirects to HTTPS (Non-Permanent)")
                    .status(CheckStatus.FAIL)
                    .severity(Severity.LOW)
                    .description("HTTP redirects to HTTPS, but with a temporary redirect (" +
                        result.statusCode() + ") instead of a permanent one (301/308).")
                    .evidence(chainEvidence)
                    .whyItMatters("Temporary redirects (302/307) are not cached by browsers. " +
                        "Use a permanent redirect (301/308) so browsers remember to use HTTPS directly.")
                    .remediation(getTemporaryRedirectRemediation())
                    .build();
            }
        } else if (result.statusCode() == 200) {
            return CheckResult.builder(CHECK_NAME, "No HTTPS Redirect — Site Accessible over HTTP")
                .status(CheckStatus.FAIL)
                .severity(Severity.HIGH)
                .description("The website responds normally on HTTP without redirecting to HTTPS.")
                .evidence(chainEvidence)
                .whyItMatters("Visitors using http:// URLs are never upgraded to secure HTTPS connections. " +
                    "Their data is transmitted in plain text, visible to anyone monitoring the network.")
                .remediation(getMissingRedirectRemediation(chain.get(0)))
                .build();
        } else {
            return CheckResult.builder(CHECK_NAME, "HTTPS Redirect Status Unknown")
                .status(CheckStatus.UNKNOWN)
                .severity(Severity.UNKNOWN)
                .description("Server responded with status " + result.statusCode() + " to the HTTP request.")
                .evidence(chainEvidence)
                .whyItMatters("SecureScore could not determine if HTTP is correctly redirecting to HTTPS.")
                .remediation("Verify your server is configured to redirect HTTP traffic to HTTPS.")
                .build();
        }
    }

    private boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303
            || status == 307 || status == 308;
    }

    private boolean isPermanentRedirect(int status) {
        return status == 301 || status == 308;
    }

    private String resolveAbsolute(String base, String location) {
        if (location.startsWith("http://") || location.startsWith("https://")) {
            return location;
        }
        try {
            URL baseUrl = new URL(base);
            return new URL(baseUrl, location).toString();
        } catch (Exception e) {
            return location;
        }
    }

    private static class RedirectLoopException extends Exception {
        RedirectLoopException(String msg) { super(msg); }
    }

    // ---- Remediation Templates ----

    private String getMissingRedirectRemediation(String httpUrl) {
        String domain = httpUrl.replace("http://", "");
        return """
            HOW TO REDIRECT HTTP TO HTTPS
            
            Nginx — add to your HTTP server block (port 80):
            server {
                listen 80;
                server_name %s;
                return 301 https://$host$request_uri;
            }
            
            Apache — add to .htaccess or VirtualHost:
            RewriteEngine On
            RewriteCond %%{HTTPS} off
            RewriteRule ^ https://%%{HTTP_HOST}%%{REQUEST_URI} [R=301,L]
            
            cPanel / Hosting Panel:
            - Log in to cPanel
            - Navigate to "Redirects"
            - Add redirect: http://%s → https://%s
            
            After adding, reload your web server:
            sudo systemctl reload nginx
            sudo systemctl reload apache2
            """.formatted(domain, domain, domain);
    }

    private String getTemporaryRedirectRemediation() {
        return """
            HOW TO CHANGE TO A PERMANENT REDIRECT (301)
            
            Nginx — use return 301 instead of return 302:
            return 301 https://$host$request_uri;
            
            Apache — use R=301 instead of R=302:
            RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
            
            A 301 redirect is permanently cached by browsers and search engines.
            """;
    }

    private String getRedirectLoopRemediation() {
        return """
            HOW TO FIX A REDIRECT LOOP
            
            Causes:
            1. Your HTTPS server block is also redirecting to HTTPS (loop)
            2. HTTP → HTTPS redirect is pointing back to itself
            3. Proxy/load balancer is stripping HTTPS headers
            
            Nginx fix — ensure your HTTPS server block does NOT redirect:
            server {
                listen 443 ssl;
                server_name example.com;
                # DO NOT add return 301 here
                ...
            }
            
            Apache fix — add HTTPS condition:
            RewriteCond %{HTTPS} off
            RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
            
            If behind a load balancer, also check:
            RewriteCond %{HTTP:X-Forwarded-Proto} !https
            """;
    }
}
