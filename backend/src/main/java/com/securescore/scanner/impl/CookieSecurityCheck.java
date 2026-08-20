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
import java.util.*;

/**
 * CHECK 4: Cookie Security
 *
 * Inspects Set-Cookie headers with a proper parser.
 * Checks each cookie for:
 * - Secure flag
 * - HttpOnly flag
 * - SameSite attribute
 *
 * Cookie values are NEVER logged or included in reports.
 */
@Component
public class CookieSecurityCheck implements SecurityCheck {

    private static final Logger log = LoggerFactory.getLogger(CookieSecurityCheck.class);
    private static final String CHECK_NAME = "COOKIE_SECURITY";

    @Value("${scanner.timeout.connect-ms:10000}")
    private int connectTimeoutMs;

    @Value("${scanner.timeout.read-ms:15000}")
    private int readTimeoutMs;

    @Override
    public String getCheckName() { return CHECK_NAME; }

    @Override
    public String getDisplayName() { return "Cookie Security"; }

    @Override
    public List<CheckResult> execute(Target target) {
        List<CheckResult> results = new ArrayList<>();

        try {
            List<String> rawCookies = fetchSetCookieHeaders(target);

            if (rawCookies.isEmpty()) {
                results.add(CheckResult.builder(CHECK_NAME, "No Cookies Detected")
                    .status(CheckStatus.PASS)
                    .severity(Severity.INFO)
                    .description("No Set-Cookie headers were found in the server response.")
                    .evidence("No Set-Cookie headers present.")
                    .whyItMatters("No cookies means no cookie security issues to report. " +
                        "If your application uses cookies, verify they are set correctly.")
                    .remediation("No action needed. If you add cookies in the future, configure them with " +
                        "Secure, HttpOnly, and SameSite attributes.")
                    .build());
                return results;
            }

            // Analyze each cookie
            List<ParsedCookie> cookies = rawCookies.stream()
                .map(this::parseCookie)
                .toList();

            // Generate per-finding results
            results.addAll(analyzeCookies(cookies));

        } catch (java.net.SocketTimeoutException | java.net.http.HttpTimeoutException e) {
            results.add(errorResult("Cookie Security Check Timeout",
                "Connection timed out while fetching cookies."));
        } catch (Exception e) {
            log.warn("Cookie security check error for {}: {}", target.hostname(), e.getMessage());
            results.add(errorResult("Cookie Security Check Error",
                "Error: " + e.getClass().getSimpleName()));
        }

        return results;
    }

    private List<String> fetchSetCookieHeaders(Target target) throws Exception {
        HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofMillis(connectTimeoutMs))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

        String url = target.isHttps() ? target.normalizedUrl() : target.httpsUrl();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .timeout(Duration.ofMillis(readTimeoutMs))
            .GET()
            .build();

        HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
        return response.headers().allValues("set-cookie");
    }

    /**
     * Proper cookie parser.
     * Does NOT use contains("secure") on the whole string.
     * Parses each attribute by name, case-insensitively.
     * Cookie VALUES are never stored or reported.
     */
    private ParsedCookie parseCookie(String rawCookie) {
        String[] parts = rawCookie.split(";");

        // First part is name=value — extract name only
        String cookieName = "unknown";
        if (parts.length > 0) {
            String nameValue = parts[0].trim();
            int eqIdx = nameValue.indexOf('=');
            cookieName = eqIdx > 0 ? nameValue.substring(0, eqIdx).trim() : nameValue;
        }

        boolean secure = false;
        boolean httpOnly = false;
        String sameSite = null;
        String path = null;
        String domain = null;

        // Parse attributes (skip first part which is name=value)
        for (int i = 1; i < parts.length; i++) {
            String attr = parts[i].trim();
            String attrLower = attr.toLowerCase();

            if (attrLower.equals("secure")) {
                secure = true;
            } else if (attrLower.equals("httponly")) {
                httpOnly = true;
            } else if (attrLower.startsWith("samesite=")) {
                sameSite = attr.substring("samesite=".length()).trim();
            } else if (attrLower.startsWith("path=")) {
                path = attr.substring("path=".length()).trim();
            } else if (attrLower.startsWith("domain=")) {
                domain = attr.substring("domain=".length()).trim();
            }
        }

        return new ParsedCookie(cookieName, secure, httpOnly, sameSite, path, domain);
    }

    private List<CheckResult> analyzeCookies(List<ParsedCookie> cookies) {
        List<CheckResult> results = new ArrayList<>();

        // Classify session-like cookies (common naming patterns)
        List<ParsedCookie> sessionLikeCookies = cookies.stream()
            .filter(c -> isLikelySessionCookie(c.name()))
            .toList();

        List<ParsedCookie> allCookies = cookies;

        // Report insecure flags
        List<ParsedCookie> missingSecure = allCookies.stream()
            .filter(c -> !c.secure())
            .toList();

        List<ParsedCookie> missingHttpOnly = allCookies.stream()
            .filter(c -> !c.httpOnly())
            .toList();

        List<ParsedCookie> missingSameSite = allCookies.stream()
            .filter(c -> c.sameSite() == null || c.sameSite().isBlank())
            .toList();

        // Missing Secure flag
        if (!missingSecure.isEmpty()) {
            Severity severity = sessionLikeCookies.stream()
                .anyMatch(c -> !c.secure()) ? Severity.HIGH : Severity.MEDIUM;

            String cookieNames = missingSecure.stream()
                .map(ParsedCookie::name)
                .toList()
                .toString();

            results.add(CheckResult.builder(CHECK_NAME, "Cookies Missing 'Secure' Flag")
                .status(CheckStatus.FAIL)
                .severity(severity)
                .description(missingSecure.size() + " cookie(s) are missing the Secure flag.")
                .evidence("Cookies missing Secure: " + cookieNames +
                    "\nTotal cookies inspected: " + allCookies.size())
                .whyItMatters("Cookies without the Secure flag can be transmitted over unencrypted HTTP connections. " +
                    "An attacker on the same network can steal these cookies. " +
                    (sessionLikeCookies.stream().anyMatch(c -> !c.secure())
                        ? "⚠️ Affected cookies appear to be session cookies, making this higher priority."
                        : ""))
                .remediation(getSecureFlagRemediation())
                .build());
        } else {
            results.add(CheckResult.builder(CHECK_NAME, "All Cookies Have 'Secure' Flag")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("All " + allCookies.size() + " cookie(s) have the Secure flag set.")
                .evidence("Cookies inspected: " + allCookies.size() + "\nAll have Secure flag: YES")
                .whyItMatters("Secure cookies cannot be transmitted over HTTP.")
                .remediation("No action needed.")
                .build());
        }

        // Missing HttpOnly flag
        if (!missingHttpOnly.isEmpty()) {
            Severity severity = sessionLikeCookies.stream()
                .anyMatch(c -> !c.httpOnly()) ? Severity.HIGH : Severity.MEDIUM;

            String cookieNames = missingHttpOnly.stream()
                .map(ParsedCookie::name)
                .toList()
                .toString();

            results.add(CheckResult.builder(CHECK_NAME, "Cookies Missing 'HttpOnly' Flag")
                .status(CheckStatus.FAIL)
                .severity(severity)
                .description(missingHttpOnly.size() + " cookie(s) are missing the HttpOnly flag.")
                .evidence("Cookies missing HttpOnly: " + cookieNames +
                    "\nTotal cookies inspected: " + allCookies.size())
                .whyItMatters("Without HttpOnly, JavaScript running on your page can access these cookies. " +
                    "If an attacker injects malicious JavaScript (XSS), they can steal these cookies. " +
                    (sessionLikeCookies.stream().anyMatch(c -> !c.httpOnly())
                        ? "⚠️ Affected cookies appear to be session cookies — cookie theft can lead to account takeover."
                        : ""))
                .remediation(getHttpOnlyRemediation())
                .build());
        } else {
            results.add(CheckResult.builder(CHECK_NAME, "All Cookies Have 'HttpOnly' Flag")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("All " + allCookies.size() + " cookie(s) have the HttpOnly flag set.")
                .evidence("Cookies inspected: " + allCookies.size() + "\nAll have HttpOnly flag: YES")
                .whyItMatters("HttpOnly cookies cannot be accessed by JavaScript.")
                .remediation("No action needed.")
                .build());
        }

        // Missing SameSite
        if (!missingSameSite.isEmpty()) {
            String cookieNames = missingSameSite.stream()
                .map(ParsedCookie::name)
                .toList()
                .toString();

            results.add(CheckResult.builder(CHECK_NAME, "Cookies Missing 'SameSite' Attribute")
                .status(CheckStatus.FAIL)
                .severity(Severity.MEDIUM)
                .description(missingSameSite.size() + " cookie(s) are missing the SameSite attribute.")
                .evidence("Cookies missing SameSite: " + cookieNames +
                    "\nTotal cookies inspected: " + allCookies.size())
                .whyItMatters("Without SameSite, cookies may be sent on cross-site requests, " +
                    "enabling Cross-Site Request Forgery (CSRF) attacks. Attackers can trick your " +
                    "logged-in users into performing actions they didn't intend.")
                .remediation(getSameSiteRemediation())
                .build());
        } else {
            results.add(CheckResult.builder(CHECK_NAME, "All Cookies Have 'SameSite' Attribute")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("All " + allCookies.size() + " cookie(s) have the SameSite attribute.")
                .evidence("Cookies inspected: " + allCookies.size() + "\nAll have SameSite: YES")
                .whyItMatters("SameSite cookies help protect against CSRF attacks.")
                .remediation("No action needed.")
                .build());
        }

        return results;
    }

    /**
     * Heuristic: Is this likely a session/auth cookie?
     * Based on common naming patterns.
     * NOT a definitive classification — used only to adjust severity.
     */
    private boolean isLikelySessionCookie(String name) {
        if (name == null) return false;
        String lower = name.toLowerCase();
        return lower.contains("session") || lower.contains("sess")
            || lower.contains("auth") || lower.contains("token")
            || lower.contains("jwt") || lower.contains("sid")
            || lower.contains("login") || lower.contains("user")
            || lower.contains("csrf") || lower.equals("jsessionid")
            || lower.equals("phpsessid") || lower.equals("asp.net_sessionid");
    }

    private CheckResult errorResult(String title, String evidence) {
        return CheckResult.builder(CHECK_NAME, title)
            .status(CheckStatus.ERROR)
            .severity(Severity.UNKNOWN)
            .description("SecureScore could not complete the cookie security check.")
            .evidence(evidence)
            .whyItMatters("Cookie security flags protect user sessions from being stolen.")
            .remediation("Try scanning again. If the problem persists, verify your server is publicly accessible.")
            .build();
    }

    // ---- Cookie model ----

    private record ParsedCookie(
        String name,
        boolean secure,
        boolean httpOnly,
        String sameSite,
        String path,
        String domain
    ) {}

    // ---- Remediation Templates ----

    private String getSecureFlagRemediation() {
        return """
            HOW TO ADD THE 'Secure' FLAG TO COOKIES
            
            The Secure flag must be set in your application code, not at the web server level.
            
            PHP:
            setcookie('session', $value, [
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict',
                'path' => '/'
            ]);
            
            Java (Spring Boot):
            server:
              servlet:
                session:
                  cookie:
                    secure: true
                    http-only: true
                    same-site: strict
            
            Node.js (Express):
            res.cookie('session', value, {
              secure: true,
              httpOnly: true,
              sameSite: 'strict'
            });
            
            WordPress (.htaccess):
            <IfModule mod_rewrite.c>
              RewriteEngine On
              RewriteCond %{HTTPS} on
              Header edit Set-Cookie ^(.*)$ $1;Secure;HttpOnly;SameSite=Strict
            </IfModule>
            """;
    }

    private String getHttpOnlyRemediation() {
        return """
            HOW TO ADD THE 'HttpOnly' FLAG TO COOKIES
            
            PHP:
            setcookie('session', $value, ['httponly' => true, 'secure' => true]);
            
            Java (Spring Boot):
            server.servlet.session.cookie.http-only=true
            
            Node.js (Express):
            res.cookie('session', value, { httpOnly: true, secure: true });
            
            Nginx (for all cookies via header edit):
            proxy_cookie_path / "/; HttpOnly; Secure; SameSite=Strict";
            """;
    }

    private String getSameSiteRemediation() {
        return """
            HOW TO ADD THE 'SameSite' ATTRIBUTE TO COOKIES
            
            Recommended value: SameSite=Strict (or Lax for cross-site GET requests)
            
            PHP:
            setcookie('session', $value, ['samesite' => 'Strict']);
            
            Java (Spring Boot):
            server.servlet.session.cookie.same-site=strict
            
            Node.js (Express):
            res.cookie('session', value, { sameSite: 'strict' });
            
            SameSite Values:
            - Strict: Cookie only sent for same-site requests (most secure)
            - Lax: Cookie sent for same-site + top-level navigation GET (good balance)
            - None: Cookie sent cross-site (requires Secure flag)
            """;
    }
}
