package com.securescore.dto;

import com.securescore.entity.CheckStatus;
import com.securescore.entity.Finding;
import com.securescore.entity.Severity;
import java.time.Instant;

public record FindingResponse(
    Long id,
    String checkName,
    String title,
    Severity severity,
    CheckStatus status,
    String description,
    String evidence,
    String whyItMatters,
    String remediation,
    Instant createdAt
) {
    public static FindingResponse from(Finding f) {
        return new FindingResponse(
            f.getId(),
            f.getCheckName(),
            f.getTitle(),
            f.getSeverity(),
            f.getStatus(),
            f.getDescription(),
            f.getEvidence(),
            f.getWhyItMatters(),
            f.getRemediation(),
            f.getCreatedAt()
        );
    }
}
