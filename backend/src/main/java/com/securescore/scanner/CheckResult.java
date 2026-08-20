package com.securescore.scanner;

import com.securescore.entity.CheckStatus;
import com.securescore.entity.Severity;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Result of a single security finding from a check.
 *
 * A single SecurityCheck may return multiple CheckResults
 * (e.g., SecurityHeadersCheck returns one per header).
 */
public class CheckResult {

    private final String checkName;
    private final String title;
    private final CheckStatus status;
    private final Severity severity;
    private final String description;
    private final String evidence;
    private final String whyItMatters;
    private final String remediation;
    private final Map<String, Object> technicalDetails;
    private final Instant timestamp;

    private CheckResult(Builder b) {
        this.checkName = b.checkName;
        this.title = b.title;
        this.status = b.status;
        this.severity = b.severity;
        this.description = b.description;
        this.evidence = b.evidence;
        this.whyItMatters = b.whyItMatters;
        this.remediation = b.remediation;
        this.technicalDetails = Map.copyOf(b.technicalDetails);
        this.timestamp = Instant.now();
    }

    // Getters
    public String getCheckName() { return checkName; }
    public String getTitle() { return title; }
    public CheckStatus getStatus() { return status; }
    public Severity getSeverity() { return severity; }
    public String getDescription() { return description; }
    public String getEvidence() { return evidence; }
    public String getWhyItMatters() { return whyItMatters; }
    public String getRemediation() { return remediation; }
    public Map<String, Object> getTechnicalDetails() { return technicalDetails; }
    public Instant getTimestamp() { return timestamp; }

    public static Builder builder(String checkName, String title) {
        return new Builder(checkName, title);
    }

    public static class Builder {
        private final String checkName;
        private final String title;
        private CheckStatus status = CheckStatus.UNKNOWN;
        private Severity severity = Severity.UNKNOWN;
        private String description = "";
        private String evidence = "";
        private String whyItMatters = "";
        private String remediation = "";
        private final Map<String, Object> technicalDetails = new HashMap<>();

        public Builder(String checkName, String title) {
            this.checkName = checkName;
            this.title = title;
        }

        public Builder status(CheckStatus s) { this.status = s; return this; }
        public Builder severity(Severity s) { this.severity = s; return this; }
        public Builder description(String d) { this.description = d; return this; }
        public Builder evidence(String e) { this.evidence = e; return this; }
        public Builder whyItMatters(String w) { this.whyItMatters = w; return this; }
        public Builder remediation(String r) { this.remediation = r; return this; }
        public Builder detail(String key, Object value) {
            this.technicalDetails.put(key, value); return this;
        }
        public CheckResult build() { return new CheckResult(this); }
    }
}
