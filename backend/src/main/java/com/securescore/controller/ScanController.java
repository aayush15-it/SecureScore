package com.securescore.controller;

import com.securescore.dto.*;
import com.securescore.service.ScanService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    /**
     * POST /api/scans
     * Start a new security scan.
     */
    @PostMapping
    public ResponseEntity<ScanResponse> createScan(
        @Valid @RequestBody ScanRequest request,
        HttpServletRequest httpRequest
    ) {
        String clientIp = getClientIp(httpRequest);
        ScanResponse response = scanService.createScan(request, clientIp);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * GET /api/scans/{scanId}
     * Get scan status and results.
     */
    @GetMapping("/{scanId}")
    public ResponseEntity<ScanResponse> getScan(@PathVariable String scanId) {
        return ResponseEntity.ok(scanService.getScan(scanId));
    }

    /**
     * GET /api/scans/{scanId}/findings
     * Get all findings for a completed scan.
     */
    @GetMapping("/{scanId}/findings")
    public ResponseEntity<List<FindingResponse>> getFindings(@PathVariable String scanId) {
        return ResponseEntity.ok(scanService.getFindings(scanId));
    }

    /**
     * POST /api/scans/{scanId}/verify
     * Re-run a specific check to verify a fix was applied.
     */
    @PostMapping("/{scanId}/verify")
    public ResponseEntity<VerifyResponse> verifyFix(
        @PathVariable String scanId,
        @Valid @RequestBody VerifyRequest request
    ) {
        return ResponseEntity.ok(scanService.verifyFix(scanId, request));
    }

    /**
     * GET /api/scans
     * Get all scans (for history page).
     */
    @GetMapping
    public ResponseEntity<List<ScanResponse>> getAllScans() {
        return ResponseEntity.ok(scanService.getAllScans());
    }

    private String getClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }
}
