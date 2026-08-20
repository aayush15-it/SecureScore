package com.securescore.dto;

import com.securescore.entity.ScanStatus;
import java.time.Instant;
import java.util.List;

public record ScanResponse(
    String id,
    String target,
    Long domainId,
    ScanStatus status,
    int completedChecks,
    int totalChecks,
    Instant startedAt,
    Instant completedAt,
    String errorMessage,
    List<FindingResponse> findings
) {
    public static ScanResponse ofRunning(String id, String target, Long domainId,
                                         int completedChecks, Instant startedAt) {
        return new ScanResponse(id, target, domainId, ScanStatus.RUNNING,
                completedChecks, 4, startedAt, null, null, null);
    }
}
