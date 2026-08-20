package com.securescore.entity;

/**
 * Severity of a security finding.
 * These are application-level classifications, NOT official CVSS ratings.
 */
public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
    PASS,
    UNKNOWN
}
