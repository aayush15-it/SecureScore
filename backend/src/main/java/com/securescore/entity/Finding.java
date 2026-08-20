package com.securescore.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Entity
@Table(name = "finding", indexes = {
    @Index(name = "idx_finding_scan_id", columnList = "scan_id"),
    @Index(name = "idx_finding_severity", columnList = "severity"),
    @Index(name = "idx_finding_check_name", columnList = "check_name")
})
@Data
@NoArgsConstructor
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id", nullable = false)
    private Scan scan;

    @Column(name = "check_name", nullable = false, length = 100)
    private String checkName;
    

    @Column(name = "title", nullable = false, length = 500)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 20)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private CheckStatus status;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "evidence", columnDefinition = "TEXT")
    private String evidence;

    @Column(name = "why_it_matters", columnDefinition = "TEXT")
    private String whyItMatters;

    @Column(name = "remediation", columnDefinition = "MEDIUMTEXT")
    private String remediation;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
