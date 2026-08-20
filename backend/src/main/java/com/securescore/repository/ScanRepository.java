package com.securescore.repository;

import com.securescore.entity.Scan;
import com.securescore.entity.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanRepository extends JpaRepository<Scan, String> {

    @Query("SELECT s FROM Scan s WHERE s.domain.id = :domainId ORDER BY s.startedAt DESC")
    List<Scan> findByDomainIdOrderByStartedAtDesc(@Param("domainId") Long domainId);

    @Query("SELECT s FROM Scan s WHERE s.domain.normalizedUrl = :normalizedUrl ORDER BY s.startedAt DESC")
    List<Scan> findByDomainNormalizedUrlOrderByStartedAtDesc(@Param("normalizedUrl") String normalizedUrl);

    List<Scan> findByStatus(ScanStatus status);
}
