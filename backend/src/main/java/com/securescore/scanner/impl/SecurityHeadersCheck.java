package com.securescore.scanner.impl;

import com.securescore.entity.CheckStatus;
import com.securescore.entity.Severity;
import com.securescore.scanner.CheckResult;
import com.securescore.scanner.SecurityCheck;
import com.securescore.scanner.Target;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * CHECK 2: Security Headers
 *
 * Checks the following HTTP response headers:
 * - Strict-Transport-Security (HSTS)
 * - Content-Security-Policy (CSP)
 * - X-Frame-Options
 * - X-Content-Type-Options
 * - Referrer-Policy
 */
@Component
public class SecurityHeadersCheck implements SecurityCheck {

    private static final Logger log = LoggerFactory.getLogger(SecurityHeadersCheck.class);
    private static final String CHECK_NAME = "SECURITY_HEADERS";

    @Value("${scanner.timeout.connect-ms:10000}")
    private int connectTimeoutMs;

    @Value("${scanner.timeout.read-ms:15000}")
    private int readTimeoutMs;

    @Override
    public String getCheckName() { return CHECK_NAME; }

    @Override
    public String getDisplayName() { return "Security Headers"; }

    @Override
    public List<CheckResult> execute(Target target) {
        List<CheckResult> results = new ArrayList<>();

        try {
            Map<String, List<String>> headers = fetchHeaders(target);

            results.add(checkHsts(headers));
            results.add(checkCsp(headers));
            results.add(checkXFrameOptions(headers));
            results.add(checkXContentTypeOptions(headers));
            results.add(checkReferrerPolicy(headers));

        } catch (java.net.SocketTimeoutException | java.net.http.HttpTimeoutException e) {
            results.add(errorResult("Security Headers Check Timeout",
                "Connection timed out while fetching headers.",
                "Verify your server is reachable and responding."));
        } catch (Exception e) {
            log.warn("Security headers check error for {}: {}", target.hostname(), e.getMessage());
            results.add(errorResult("Security Headers Check Error",
                "An error occurred: " + e.getClass().getSimpleName(),
                "Try scanning again. Verify your server is publicly accessible."));
        }

        return results;
    }

    private Map<String, List<String>> fetchHeaders(Target target) throws Exception {
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(connectTimeoutMs))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

        // Try HTTPS first, fall back to HTTP
        String url = target.isHttps() ? target.normalizedUrl() : target.httpsUrl();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofMillis(readTimeoutMs))
            .method("HEAD", HttpRequest.BodyPublishers.noBody())
            .build();

        try {
            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            return response.headers().map();
        } catch (Exception e) {
            // HEAD failed, try GET with size limit
            log.debug("HEAD failed for {}, trying GET: {}", url, e.getMessage());
            HttpRequest getRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofMillis(readTimeoutMs))
                .GET()
                .build();
            HttpResponse<String> response = client.send(getRequest,
                HttpResponse.BodyHandlers.ofString());
            return response.headers().map();
        }
    }

    private CheckResult checkHsts(Map<String, List<String>> headers) {
        Optional<String> hsts = getHeader(headers, "strict-transport-security");

        if (hsts.isEmpty()) {
            return CheckResult.builder(CHECK_NAME, "Missing HSTS (Strict-Transport-Security)")
                .status(CheckStatus.FAIL)
                .severity(Severity.HIGH)
                .description("The Strict-Transport-Security (HSTS) header is not present.")
                .evidence("Header: Strict-Transport-Security\nStatus: NOT PRESENT")
                .whyItMatters("Without HSTS, even if your site supports HTTPS, browsers may connect " +
                    "via plain HTTP first. This creates a window for attackers to intercept the initial " +
                    "connection (SSL stripping attack). HSTS tells browsers to always use HTTPS.")
                .remediation(getHstsRemediation())
                .build();
        }

        String value = hsts.get();
        boolean hasMaxAge = value.toLowerCase().contains("max-age=");

        if (!hasMaxAge) {
            return CheckResult.builder(CHECK_NAME, "HSTS Header Invalid (Missing max-age)")
                .status(CheckStatus.FAIL)
                .severity(Severity.MEDIUM)
                .description("The HSTS header is present but missing the required max-age directive.")
                .evidence("Header: Strict-Transport-Security\nValue: " + value)
                .whyItMatters("An HSTS header without max-age is ignored by browsers.")
                .remediation(getHstsRemediation())
                .build();
        }

        // Check max-age value (warn if too low)
        long maxAge = extractMaxAge(value);
        if (maxAge > 0 && maxAge < 2592000) { // Less than 30 days
            return CheckResult.builder(CHECK_NAME, "HSTS max-age Too Short")
                .status(CheckStatus.FAIL)
                .severity(Severity.LOW)
                .description("HSTS is enabled but with a short max-age of " + maxAge + " seconds (" +
                    (maxAge / 86400) + " days). Recommended: at least 180 days (15552000 seconds).")
                .evidence("Header: Strict-Transport-Security\nValue: " + value)
                .whyItMatters("A short max-age means HSTS protection expires quickly, leaving windows for attacks.")
                .remediation(getHstsRemediation())
                .build();
        }

        return CheckResult.builder(CHECK_NAME, "HSTS Enabled")
            .status(CheckStatus.PASS)
            .severity(Severity.PASS)
            .description("HSTS is correctly configured.")
            .evidence("Header: Strict-Transport-Security\nValue: " + value)
            .whyItMatters("HSTS protects visitors from SSL-stripping attacks.")
            .remediation("No action needed.")
            .build();
    }

    private CheckResult checkCsp(Map<String, List<String>> headers) {
        Optional<String> csp = getHeader(headers, "content-security-policy");

        if (csp.isEmpty()) {
            return CheckResult.builder(CHECK_NAME, "Missing Content-Security-Policy (CSP)")
                .status(CheckStatus.FAIL)
                .severity(Severity.MEDIUM)
                .description("The Content-Security-Policy header is not present.")
                .evidence("Header: Content-Security-Policy\nStatus: NOT PRESENT")
                .whyItMatters("Without CSP, your website is more vulnerable to Cross-Site Scripting (XSS) attacks. " +
                    "CSP tells browsers which scripts and content are allowed to run on your pages.")
                .remediation(getCspRemediation())
                .build();
        }

        String value = csp.get();

        // Warn about unsafe-inline
        if (value.contains("'unsafe-inline'") && value.contains("script-src")) {
            return CheckResult.builder(CHECK_NAME, "CSP Present but Weak ('unsafe-inline')")
                .status(CheckStatus.FAIL)
                .severity(Severity.LOW)
                .description("CSP is enabled but allows 'unsafe-inline' scripts, which reduces its effectiveness.")
                .evidence("Header: Content-Security-Policy\nValue: " + truncate(value, 500))
                .whyItMatters("'unsafe-inline' allows inline scripts to run, which is the main attack vector " +
                    "CSP is designed to block.")
                .remediation(getCspRemediation())
                .build();
        }

        return CheckResult.builder(CHECK_NAME, "Content-Security-Policy Present")
            .status(CheckStatus.PASS)
            .severity(Severity.PASS)
            .description("A Content-Security-Policy header is configured.")
            .evidence("Header: Content-Security-Policy\nValue: " + truncate(value, 200))
            .whyItMatters("CSP reduces the risk of XSS attacks.")
            .remediation("Review your CSP policy periodically and tighten it where possible.")
            .build();
    }

    private CheckResult checkXFrameOptions(Map<String, List<String>> headers) {
        Optional<String> xfo = getHeader(headers, "x-frame-options");

        if (xfo.isEmpty()) {
            return CheckResult.builder(CHECK_NAME, "Missing X-Frame-Options")
                .status(CheckStatus.FAIL)
                .severity(Severity.MEDIUM)
                .description("The X-Frame-Options header is not present.")
                .evidence("Header: X-Frame-Options\nStatus: NOT PRESENT")
                .whyItMatters("Without X-Frame-Options, attackers can embed your website in an invisible iframe " +
                    "and trick your visitors into clicking on hidden buttons (clickjacking attack).")
                .remediation(getXFrameOptionsRemediation())
                .build();
        }

        String value = xfo.get().trim().toUpperCase();
        if (value.equals("DENY") || value.equals("SAMEORIGIN")) {
            return CheckResult.builder(CHECK_NAME, "X-Frame-Options Configured")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("X-Frame-Options is correctly configured.")
                .evidence("Header: X-Frame-Options\nValue: " + xfo.get())
                .whyItMatters("Prevents clickjacking attacks.")
                .remediation("No action needed.")
                .build();
        }

        return CheckResult.builder(CHECK_NAME, "X-Frame-Options Has Unexpected Value")
            .status(CheckStatus.FAIL)
            .severity(Severity.LOW)
            .description("X-Frame-Options is present but has an unexpected value: " + xfo.get())
            .evidence("Header: X-Frame-Options\nValue: " + xfo.get() + "\nExpected: DENY or SAMEORIGIN")
            .whyItMatters("An incorrect X-Frame-Options value may not protect against clickjacking.")
            .remediation(getXFrameOptionsRemediation())
            .build();
    }

    private CheckResult checkXContentTypeOptions(Map<String, List<String>> headers) {
        Optional<String> xcto = getHeader(headers, "x-content-type-options");

        if (xcto.isEmpty()) {
            return CheckResult.builder(CHECK_NAME, "Missing X-Content-Type-Options")
                .status(CheckStatus.FAIL)
                .severity(Severity.LOW)
                .description("The X-Content-Type-Options header is not present.")
                .evidence("Header: X-Content-Type-Options\nStatus: NOT PRESENT")
                .whyItMatters("Without this header, browsers may guess the content type of files, which can " +
                    "allow attackers to disguise malicious files as innocent ones (MIME sniffing attack).")
                .remediation(getXContentTypeOptionsRemediation())
                .build();
        }

        if (xcto.get().trim().equalsIgnoreCase("nosniff")) {
            return CheckResult.builder(CHECK_NAME, "X-Content-Type-Options: nosniff")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("X-Content-Type-Options is correctly set to 'nosniff'.")
                .evidence("Header: X-Content-Type-Options\nValue: " + xcto.get())
                .whyItMatters("Prevents MIME sniffing attacks.")
                .remediation("No action needed.")
                .build();
        }

        return CheckResult.builder(CHECK_NAME, "X-Content-Type-Options Invalid Value")
            .status(CheckStatus.FAIL)
            .severity(Severity.LOW)
            .description("X-Content-Type-Options has an unexpected value: " + xcto.get())
            .evidence("Header: X-Content-Type-Options\nValue: " + xcto.get() + "\nExpected: nosniff")
            .whyItMatters("The header must be set to 'nosniff' to be effective.")
            .remediation(getXContentTypeOptionsRemediation())
            .build();
    }

    private CheckResult checkReferrerPolicy(Map<String, List<String>> headers) {
        Optional<String> rp = getHeader(headers, "referrer-policy");

        if (rp.isEmpty()) {
            return CheckResult.builder(CHECK_NAME, "Missing Referrer-Policy")
                .status(CheckStatus.FAIL)
                .severity(Severity.LOW)
                .description("The Referrer-Policy header is not present.")
                .evidence("Header: Referrer-Policy\nStatus: NOT PRESENT")
                .whyItMatters("Without Referrer-Policy, your full page URLs may be sent to third-party websites " +
                    "when visitors click links. This can leak sensitive URL parameters.")
                .remediation(getReferrerPolicyRemediation())
                .build();
        }

        String value = rp.get().trim().toLowerCase();
        List<String> safeValues = List.of(
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "same-origin", "origin", "no-referrer-when-downgrade"
        );

        if (safeValues.contains(value)) {
            return CheckResult.builder(CHECK_NAME, "Referrer-Policy Configured")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("Referrer-Policy is configured.")
                .evidence("Header: Referrer-Policy\nValue: " + rp.get())
                .whyItMatters("Controls what referrer information is shared.")
                .remediation("No action needed.")
                .build();
        }

        return CheckResult.builder(CHECK_NAME, "Referrer-Policy May Be Too Permissive")
            .status(CheckStatus.FAIL)
            .severity(Severity.LOW)
            .description("Referrer-Policy is set to '" + value + "' which may share more information than necessary.")
            .evidence("Header: Referrer-Policy\nValue: " + rp.get())
            .whyItMatters("A permissive referrer policy can leak URL data to third parties.")
            .remediation(getReferrerPolicyRemediation())
            .build();
    }

    // ---- Helpers ----

    private Optional<String> getHeader(Map<String, List<String>> headers, String name) {
        return headers.entrySet().stream()
            .filter(e -> e.getKey() != null && e.getKey().equalsIgnoreCase(name))
            .map(e -> String.join(", ", e.getValue()))
            .findFirst();
    }

    private long extractMaxAge(String hstsValue) {
        try {
            for (String part : hstsValue.split(";")) {
                part = part.trim().toLowerCase();
                if (part.startsWith("max-age=")) {
                    return Long.parseLong(part.substring(8).trim());
                }
            }
        } catch (NumberFormatException ignored) {}
        return -1;
    }

    private String truncate(String s, int maxLen) {
        return s != null && s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }

    private CheckResult errorResult(String title, String evidence, String remediation) {
        return CheckResult.builder(CHECK_NAME, title)
            .status(CheckStatus.ERROR)
            .severity(Severity.UNKNOWN)
            .description("SecureScore could not complete this check.")
            .evidence(evidence)
            .whyItMatters("Security headers help protect your website visitors from common web attacks.")
            .remediation(remediation)
            .build();
    }

    // ---- Remediation Templates ----

    private String getHstsRemediation() {
        return """
            HOW TO ADD HSTS (Strict-Transport-Security)
            
            Nginx — add to your server block:
            add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
            
            Apache — add to your VirtualHost or .htaccess:
            Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
            
            Explanation:
            - max-age=31536000 = enforce HTTPS for 1 year
            - includeSubDomains = also protects subdomains
            
            IMPORTANT: Only add HSTS after confirming your site fully works on HTTPS.
            
            After adding, restart your web server:
            sudo systemctl reload nginx
            sudo systemctl reload apache2
            """;
    }

    private String getCspRemediation() {
        return """
            HOW TO ADD CONTENT-SECURITY-POLICY (CSP)
            
            A safe starting point for most websites:
            
            Nginx:
            add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self';" always;
            
            Apache:
            Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self';"
            
            NOTE: CSP must be tuned for your specific site. Test thoroughly before deploying.
            Use a CSP evaluator: https://csp-evaluator.withgoogle.com/
            """;
    }

    private String getXFrameOptionsRemediation() {
        return """
            HOW TO ADD X-Frame-Options
            
            Nginx:
            add_header X-Frame-Options "SAMEORIGIN" always;
            
            Apache:
            Header always set X-Frame-Options "SAMEORIGIN"
            
            Options:
            - DENY: Never allow embedding in any frame
            - SAMEORIGIN: Only allow embedding from the same domain
            
            Recommended: SAMEORIGIN (allows legitimate uses like embedding your own content)
            """;
    }

    private String getXContentTypeOptionsRemediation() {
        return """
            HOW TO ADD X-Content-Type-Options
            
            Nginx:
            add_header X-Content-Type-Options "nosniff" always;
            
            Apache:
            Header always set X-Content-Type-Options "nosniff"
            
            This is a simple, one-line addition with no downsides.
            """;
    }

    private String getReferrerPolicyRemediation() {
        return """
            HOW TO ADD Referrer-Policy
            
            Nginx:
            add_header Referrer-Policy "strict-origin-when-cross-origin" always;
            
            Apache:
            Header always set Referrer-Policy "strict-origin-when-cross-origin"
            
            Recommended value: strict-origin-when-cross-origin
            - Sends referrer only to same-origin requests
            - Sends only the origin (not full URL) to cross-origin HTTPS requests
            - Sends no referrer to HTTP targets
            """;
    }
}
