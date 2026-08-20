package com.securescore.dto;

import java.time.Instant;
import java.util.List;
import com.securescore.entity.ScanStatus;

public record DomainScanHistoryResponse(
    Long domainId,
    String url,
    List<ScanSummary> scans
) {
    public record ScanSummary(
        String id,
        ScanStatus status,
        Instant startedAt,
        Instant completedAt,
        int highCount,
        int mediumCount,
        int lowCount,
        int passCount,
        int unknownCount
    ) {}
}
