package com.securescore.exception;

public class ScanNotFoundException extends RuntimeException {
    public ScanNotFoundException(String scanId) {
        super("Scan not found: " + scanId);
    }
}
