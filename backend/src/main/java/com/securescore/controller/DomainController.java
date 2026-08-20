package com.securescore.controller;

import com.securescore.dto.DomainScanHistoryResponse;
import com.securescore.service.ScanService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/domains")
public class DomainController {

    private final ScanService scanService;

    public DomainController(ScanService scanService) {
        this.scanService = scanService;
    }

    /**
     * GET /api/domains/{domainId}/scans
     * Get scan history for a specific domain.
     */
    @GetMapping("/{domainId}/scans")
    public ResponseEntity<DomainScanHistoryResponse> getDomainHistory(
        @PathVariable Long domainId
    ) {
        return ResponseEntity.ok(scanService.getDomainHistory(domainId));
    }
}
