package com.securescore.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scan", indexes = {
    @Index(name = "idx_scan_domain_id", columnList = "domain_id"),
    @Index(name = "idx_scan_status", columnList = "status"),
    @Index(name = "idx_scan_started_at", columnList = "started_at")
})
@Data
@NoArgsConstructor
public class Scan {

    @Id
    @Column(name = "id", length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "domain_id", nullable = false)
    private Domain domain;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private ScanStatus status;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Finding> findings = new ArrayList<>();

    public Scan(String id, Domain domain) {
        this.id = id;
        this.domain = domain;
        this.status = ScanStatus.QUEUED;
        this.startedAt = Instant.now();
    }
}
