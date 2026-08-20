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

import javax.net.ssl.*;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * CHECK 1: SSL/TLS
 *
 * Inspects externally observable TLS information:
 * - Certificate validity and expiry
 * - Hostname match
 * - TLS protocol version
 * - Basic chain trust (via JVM trust store)
 */
@Component
public class SslTlsCheck implements SecurityCheck {

    private static final Logger log = LoggerFactory.getLogger(SslTlsCheck.class);
    private static final String CHECK_NAME = "SSL_TLS";

    @Value("${scanner.timeout.connect-ms:10000}")
    private int connectTimeoutMs;

    @Value("${scanner.timeout.read-ms:15000}")
    private int readTimeoutMs;

    @Override
    public String getCheckName() { return CHECK_NAME; }

    @Override
    public String getDisplayName() { return "SSL/TLS Certificate"; }

    @Override
    public List<CheckResult> execute(Target target) {
        List<CheckResult> results = new ArrayList<>();

        // Only makes sense if the target supports HTTPS
        String httpsUrl = target.httpsUrl();

        try {
            URL url = new URL(httpsUrl);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setConnectTimeout(connectTimeoutMs);
            conn.setReadTimeout(readTimeoutMs);
            conn.setRequestMethod("HEAD");
            conn.setInstanceFollowRedirects(false);

            // Capture TLS details
            SSLSession session = null;
            Certificate[] serverCerts = null;
            String protocol = null;
            String cipherSuite = null;

            try {
                conn.connect();
                Object sslSessionObj = conn.getSSLSession();
                if (sslSessionObj instanceof java.util.Optional<?> optSession) {
                    session = (SSLSession) ((java.util.Optional<?>) optSession).orElse(null);
                } else if (sslSessionObj instanceof SSLSession s) {
                    session = s;
                }
                if (session != null) {
                    protocol = session.getProtocol();
                    cipherSuite = session.getCipherSuite();
                    serverCerts = session.getPeerCertificates();
                }
            } catch (SSLHandshakeException e) {
                results.add(CheckResult.builder(CHECK_NAME, "SSL/TLS Handshake Failed")
                    .status(CheckStatus.FAIL)
                    .severity(Severity.HIGH)
                    .description("The SSL/TLS handshake with the server failed.")
                    .evidence("Error: " + sanitizeMessage(e.getMessage()))
                    .whyItMatters("If your server cannot complete a TLS handshake, browsers will show " +
                        "a security warning and refuse to connect. Visitors cannot reach your site securely.")
                    .remediation(getTlsHandshakeRemediation())
                    .build());
                return results;
            } catch (SSLException e) {
                results.add(CheckResult.builder(CHECK_NAME, "SSL/TLS Connection Error")
                    .status(CheckStatus.FAIL)
                    .severity(Severity.HIGH)
                    .description("An SSL/TLS error occurred when connecting to the server.")
                    .evidence("Error: " + sanitizeMessage(e.getMessage()))
                    .whyItMatters("SSL errors prevent secure connections. Visitors will see browser warnings.")
                    .remediation(getTlsHandshakeRemediation())
                    .build());
                return results;
            } finally {
                conn.disconnect();
            }

            // --- Certificate Analysis ---
            if (serverCerts != null && serverCerts.length > 0
                && serverCerts[0] instanceof X509Certificate cert) {

                // 1. Certificate Validity
                results.add(checkCertValidity(cert));

                // 2. Certificate Expiry (warn if expiring soon)
                results.add(checkCertExpiry(cert));

                // 3. Hostname Match
                results.add(checkHostname(cert, target.hostname(), conn));

                // 4. TLS Version
                if (protocol != null) {
                    results.add(checkTlsVersion(protocol, cipherSuite));
                }

            } else {
                results.add(CheckResult.builder(CHECK_NAME, "SSL Certificate Not Retrieved")
                    .status(CheckStatus.UNKNOWN)
                    .severity(Severity.UNKNOWN)
                    .description("Could not retrieve the server certificate for analysis.")
                    .evidence("No certificate chain was returned from the server.")
                    .whyItMatters("SSL certificates are required for secure HTTPS connections.")
                    .remediation("Ensure your web server is configured with a valid SSL certificate.")
                    .build());
            }

        } catch (java.net.SocketTimeoutException e) {
            results.add(CheckResult.builder(CHECK_NAME, "SSL/TLS Connection Timeout")
                .status(CheckStatus.UNKNOWN)
                .severity(Severity.UNKNOWN)
                .description("The connection to the server timed out during SSL/TLS check.")
                .evidence("Connection timed out after " + connectTimeoutMs + "ms.")
                .whyItMatters("SecureScore could not reach the server to check SSL/TLS.")
                .remediation("Verify your server is reachable and responding to HTTPS connections.")
                .build());
        } catch (java.net.ConnectException e) {
            results.add(CheckResult.builder(CHECK_NAME, "HTTPS Not Available")
                .status(CheckStatus.FAIL)
                .severity(Severity.HIGH)
                .description("The server is not accepting HTTPS connections on port 443.")
                .evidence("Connection refused to " + httpsUrl)
                .whyItMatters("Without HTTPS, all data transmitted between your visitors and your website " +
                    "is unencrypted and can be intercepted.")
                .remediation("Contact your hosting provider to enable HTTPS/SSL on your website.")
                .build());
        } catch (Exception e) {
            log.warn("SSL check unexpected error for {}: {}", target.hostname(), e.getMessage());
            results.add(CheckResult.builder(CHECK_NAME, "SSL/TLS Check Error")
                .status(CheckStatus.ERROR)
                .severity(Severity.UNKNOWN)
                .description("An unexpected error occurred during the SSL/TLS check.")
                .evidence("Error type: " + e.getClass().getSimpleName())
                .whyItMatters("SecureScore was unable to complete the SSL/TLS check.")
                .remediation("Try scanning again. If the problem persists, verify your server is publicly accessible.")
                .build());
        }

        return results;
    }

    private CheckResult checkCertValidity(X509Certificate cert) {
        try {
            cert.checkValidity();
            Date notBefore = cert.getNotBefore();
            Date notAfter = cert.getNotAfter();
            String subject = cert.getSubjectX500Principal().getName();

            return CheckResult.builder(CHECK_NAME, "SSL Certificate Valid")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("The SSL certificate is currently valid.")
                .evidence("Subject: " + simplifyDN(subject) + "\n" +
                    "Valid from: " + notBefore + "\n" +
                    "Valid until: " + notAfter)
                .whyItMatters("A valid certificate confirms your server's identity and enables encrypted connections.")
                .remediation("No action needed. Your certificate is valid.")
                .build();

        } catch (CertificateExpiredException e) {
            return CheckResult.builder(CHECK_NAME, "SSL Certificate Expired")
                .status(CheckStatus.FAIL)
                .severity(Severity.CRITICAL)
                .description("The SSL certificate has expired. Browsers will show a security warning to all visitors.")
                .evidence("Certificate expired on: " + cert.getNotAfter())
                .whyItMatters("An expired certificate causes browsers to block access to your site with a full-screen " +
                    "warning. This actively drives away customers and damages trust.")
                .remediation(getExpiredCertRemediation())
                .build();

        } catch (CertificateNotYetValidException e) {
            return CheckResult.builder(CHECK_NAME, "SSL Certificate Not Yet Valid")
                .status(CheckStatus.FAIL)
                .severity(Severity.HIGH)
                .description("The SSL certificate is not yet valid (validity period has not started).")
                .evidence("Certificate valid from: " + cert.getNotBefore())
                .whyItMatters("Browsers will reject this certificate until its start date.")
                .remediation("Wait until the certificate's start date, or re-issue the certificate with the correct validity period.")
                .build();
        }
    }

    private CheckResult checkCertExpiry(X509Certificate cert) {
        Date notAfter = cert.getNotAfter();
        Instant expiry = notAfter.toInstant();
        Instant now = Instant.now();
        long daysUntilExpiry = ChronoUnit.DAYS.between(now, expiry);

        if (daysUntilExpiry < 0) {
            // Already caught by checkCertValidity
            return null;
        }

        if (daysUntilExpiry <= 14) {
            return CheckResult.builder(CHECK_NAME, "SSL Certificate Expiring Soon")
                .status(CheckStatus.FAIL)
                .severity(Severity.HIGH)
                .description("Your SSL certificate expires in " + daysUntilExpiry + " days.")
                .evidence("Expiry date: " + notAfter + "\nDays remaining: " + daysUntilExpiry)
                .whyItMatters("When the certificate expires, browsers will block access to your site. " +
                    "Renew now before it affects your visitors.")
                .remediation(getRenewCertRemediation())
                .build();
        } else if (daysUntilExpiry <= 30) {
            return CheckResult.builder(CHECK_NAME, "SSL Certificate Expiring Within 30 Days")
                .status(CheckStatus.FAIL)
                .severity(Severity.MEDIUM)
                .description("Your SSL certificate expires in " + daysUntilExpiry + " days.")
                .evidence("Expiry date: " + notAfter + "\nDays remaining: " + daysUntilExpiry)
                .whyItMatters("Plan your certificate renewal soon to avoid any service interruption.")
                .remediation(getRenewCertRemediation())
                .build();
        } else {
            return CheckResult.builder(CHECK_NAME, "SSL Certificate Expiry OK")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("Your SSL certificate is valid and not expiring soon.")
                .evidence("Expiry date: " + notAfter + "\nDays remaining: " + daysUntilExpiry)
                .whyItMatters("Your certificate will remain valid for the foreseeable future.")
                .remediation("No action needed.")
                .build();
        }
    }

    private CheckResult checkHostname(X509Certificate cert, String hostname,
                                       HttpsURLConnection conn) {
        try {
            // Use the built-in hostname verifier
            HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
            Object rawSession = conn.getSSLSession();
            SSLSession session = null;
            if (rawSession instanceof java.util.Optional<?> opt) {
                session = (SSLSession) opt.orElse(null);
            } else if (rawSession instanceof SSLSession s) {
                session = s;
            }

            if (session != null) {

                boolean valid = verifier.verify(hostname, session);
                if (valid) {
                    return CheckResult.builder(CHECK_NAME, "SSL Hostname Match")
                        .status(CheckStatus.PASS)
                        .severity(Severity.PASS)
                        .description("The certificate hostname matches your domain.")
                        .evidence("Certificate is valid for: " + hostname)
                        .whyItMatters("Hostname matching confirms the certificate belongs to your domain.")
                        .remediation("No action needed.")
                        .build();
                } else {
                    String subject = cert.getSubjectX500Principal().getName();
                    return CheckResult.builder(CHECK_NAME, "SSL Hostname Mismatch")
                        .status(CheckStatus.FAIL)
                        .severity(Severity.HIGH)
                        .description("The SSL certificate does not match your domain name.")
                        .evidence("Expected hostname: " + hostname + "\nCertificate subject: " + simplifyDN(subject))
                        .whyItMatters("A hostname mismatch causes browsers to show a security warning. Visitors cannot " +
                            "verify they are on your site.")
                        .remediation("Obtain a certificate issued for the correct domain name. " +
                            "Use Let's Encrypt (certbot) or your hosting provider's SSL panel.")
                        .build();
                }
            }
        } catch (Exception e) {
            log.debug("Hostname check error: {}", e.getMessage());
        }

        return CheckResult.builder(CHECK_NAME, "SSL Hostname Check Incomplete")
            .status(CheckStatus.UNKNOWN)
            .severity(Severity.UNKNOWN)
            .description("Could not verify hostname match.")
            .evidence("Verification skipped due to connection state.")
            .whyItMatters("Hostname matching is important for certificate trust.")
            .remediation("Manually verify your certificate is issued for the correct domain.")
            .build();
    }

    private CheckResult checkTlsVersion(String protocol, String cipherSuite) {
        String evidenceText = "Protocol: " + protocol +
            (cipherSuite != null ? "\nCipher suite: " + cipherSuite : "");

        return switch (protocol) {
            case "TLSv1.3" -> CheckResult.builder(CHECK_NAME, "TLS Version: TLS 1.3")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("Your server is using TLS 1.3, the latest and most secure version.")
                .evidence(evidenceText)
                .whyItMatters("TLS 1.3 provides the strongest encryption available.")
                .remediation("No action needed. TLS 1.3 is excellent.")
                .build();

            case "TLSv1.2" -> CheckResult.builder(CHECK_NAME, "TLS Version: TLS 1.2")
                .status(CheckStatus.PASS)
                .severity(Severity.PASS)
                .description("Your server is using TLS 1.2, which is still considered secure.")
                .evidence(evidenceText)
                .whyItMatters("TLS 1.2 is widely supported and secure. Consider upgrading to TLS 1.3 for the best security.")
                .remediation("TLS 1.2 is acceptable. Optionally enable TLS 1.3 in your server config.")
                .build();

            case "TLSv1.1" -> CheckResult.builder(CHECK_NAME, "Outdated TLS Version: TLS 1.1")
                .status(CheckStatus.FAIL)
                .severity(Severity.MEDIUM)
                .description("Your server is using TLS 1.1, which is deprecated and no longer recommended.")
                .evidence(evidenceText)
                .whyItMatters("TLS 1.1 has known weaknesses. Modern browsers may warn users or refuse connections.")
                .remediation(getOldTlsRemediation("TLSv1.1"))
                .build();

            case "TLSv1", "TLSv1.0" -> CheckResult.builder(CHECK_NAME, "Outdated TLS Version: TLS 1.0")
                .status(CheckStatus.FAIL)
                .severity(Severity.HIGH)
                .description("Your server is using TLS 1.0, which is deprecated and has known vulnerabilities.")
                .evidence(evidenceText)
                .whyItMatters("TLS 1.0 is vulnerable to attacks like POODLE and BEAST. " +
                    "PCI DSS compliance requires disabling TLS 1.0.")
                .remediation(getOldTlsRemediation("TLSv1"))
                .build();

            default -> CheckResult.builder(CHECK_NAME, "TLS Version: " + protocol)
                .status(CheckStatus.UNKNOWN)
                .severity(Severity.UNKNOWN)
                .description("TLS version detected: " + protocol)
                .evidence(evidenceText)
                .whyItMatters("TLS version affects the security of encrypted connections.")
                .remediation("Ensure your server is configured to use TLS 1.2 or TLS 1.3.")
                .build();
        };
    }

    // ---- Remediation Templates ----

    private String getExpiredCertRemediation() {
        return """
            YOUR CERTIFICATE HAS EXPIRED — RENEW IMMEDIATELY
            
            Option 1: Let's Encrypt (Free — Recommended)
            Run on your server:
            
            sudo certbot renew
            sudo systemctl reload nginx  # or apache2
            
            Option 2: cPanel / Hosting Panel
            - Log in to your hosting control panel
            - Navigate to SSL/TLS section
            - Click "Renew" or "Re-install" for your domain
            
            Option 3: Purchase SSL from your host
            Contact your hosting provider and ask them to renew your SSL certificate.
            
            After renewing, restart your web server and scan again to verify.
            """;
    }

    private String getRenewCertRemediation() {
        return """
            HOW TO RENEW YOUR SSL CERTIFICATE
            
            Option 1: Let's Encrypt (Free — Recommended)
            If you used certbot, renewal is automatic. Verify with:
            sudo certbot renew --dry-run
            
            Check your renewal timer:
            systemctl status certbot.timer
            
            Option 2: cPanel / Hosting Panel
            Most hosting panels auto-renew SSL certificates.
            Check: SSL/TLS section → AutoSSL → Run AutoSSL
            
            Option 3: Manual Renewal
            Purchase a new certificate from your registrar or CA,
            then install it in your server's SSL configuration.
            """;
    }

    private String getTlsHandshakeRemediation() {
        return """
            HOW TO FIX TLS HANDSHAKE FAILURES
            
            1. Check your certificate is installed correctly:
               - Certificate matches the domain
               - Full chain is included (intermediate certificates)
               - Certificate is not expired
            
            2. Test with SSL Labs:
               https://www.ssllabs.com/ssltest/
            
            3. Nginx — check your certificate config:
               ssl_certificate /path/to/fullchain.pem;
               ssl_certificate_key /path/to/privkey.pem;
            
            4. Apache — check your certificate config:
               SSLCertificateFile /path/to/cert.pem
               SSLCertificateKeyFile /path/to/privkey.pem
               SSLCertificateChainFile /path/to/chain.pem
            """;
    }

    private String getOldTlsRemediation(String version) {
        return """
            HOW TO DISABLE %s AND ENABLE TLS 1.2+
            
            Nginx:
            ssl_protocols TLSv1.2 TLSv1.3;
            
            Apache:
            SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
            
            After making changes, restart your web server:
            sudo systemctl reload nginx
            sudo systemctl reload apache2
            
            Verify with: https://www.ssllabs.com/ssltest/
            """.formatted(version);
    }

    private String simplifyDN(String dn) {
        // Extract CN= from distinguished name for readability
        if (dn == null) return "Unknown";
        for (String part : dn.split(",")) {
            if (part.trim().startsWith("CN=")) {
                return part.trim().substring(3);
            }
        }
        return dn;
    }

    private String sanitizeMessage(String message) {
        if (message == null) return "Unknown error";
        // Don't expose internal paths or sensitive details
        return message.replaceAll("(password|key|secret|token)", "[redacted]");
    }
}
