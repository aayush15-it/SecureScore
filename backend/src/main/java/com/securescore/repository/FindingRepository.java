package com.securescore.repository;

import com.securescore.entity.Finding;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FindingRepository extends JpaRepository<Finding, Long> {
    List<Finding> findByScanIdOrderBySeverityAscCreatedAtAsc(String scanId);
    List<Finding> findByScanId(String scanId);
    void deleteByScanId(String scanId);
}
