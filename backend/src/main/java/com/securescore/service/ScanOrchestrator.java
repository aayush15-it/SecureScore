package com.securescore.service;

import com.securescore.entity.*;
import com.securescore.repository.FindingRepository;
import com.securescore.repository.ScanRepository;
import com.securescore.scanner.CheckResult;
import com.securescore.scanner.SecurityCheck;
import com.securescore.scanner.Target;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Orchestrates the execution of all four security checks in parallel.
 * Manages the scan lifecycle: QUEUED → RUNNING → COMPLETED/FAILED.
 *
 * Individual check failures do NOT fail the entire scan.
 * A scan only fails if ALL checks fail catastrophically.
 *
 * NOTE: executeScan is intentionally NOT @Transactional.
 * It runs asynchronously in a separate thread from the HTTP request thread.
 * Each DB update within uses its own short-lived transaction.
 */
@Service
public class ScanOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestrator.class);

    private final List<SecurityCheck> securityChecks;
    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final ExecutorService checkExecutor;

    @Value("${scanner.overall-timeout-seconds:90}")
    private int overallTimeoutSeconds;

    public ScanOrchestrator(
        List<SecurityCheck> securityChecks,
        ScanRepository scanRepository,
        FindingRepository findingRepository
    ) {
        this.securityChecks = securityChecks;
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        // Fixed thread pool for running the 4 checks in parallel
        this.checkExecutor = Executors.newFixedThreadPool(4);
        log.info("ScanOrchestrator initialized with {} checks: {}",
            securityChecks.size(),
            securityChecks.stream().map(SecurityCheck::getCheckName).collect(Collectors.joining(", ")));
    }

    /**
     * Execute the full scan asynchronously.
     * Called from ScanService after scan record is committed to DB.
     *
     * IMPORTANT: NOT @Transactional — each DB update uses its own transaction
     * via the repository methods, avoiding transaction propagation conflicts.
     */
    @Async("scannerExecutor")
    public void executeScan(String scanId, Target target) {
        log.info("Starting scan {} for target {}", scanId, target.hostname());

        // Re-fetch the scan in this new async thread context
        Scan scan = scanRepository.findById(scanId).orElse(null);
        if (scan == null) {
            log.error("Scan {} not found at start of executeScan", scanId);
            return;
        }

        // Mark as RUNNING in its own transaction
        markRunning(scanId);

        try {
            // Launch all checks concurrently on separate threads
            List<CompletableFuture<List<CheckResult>>> futures = securityChecks.stream()
                .map(check -> CompletableFuture.supplyAsync(
                    () -> executeCheckSafely(check, target),
                    checkExecutor
                ))
                .toList();

            // Wait for all with overall timeout
            CompletableFuture<Void> allOf = CompletableFuture.allOf(
                futures.toArray(new CompletableFuture[0])
            );

            try {
                allOf.get(overallTimeoutSeconds, TimeUnit.SECONDS);
            } catch (java.util.concurrent.TimeoutException e) {
                log.warn("Scan {} timed out after {}s. Collecting completed results.", scanId, overallTimeoutSeconds);
            }

            // Collect all results (completed or timed out)
            List<CheckResult> allResults = new ArrayList<>();
            for (CompletableFuture<List<CheckResult>> future : futures) {
                if (future.isDone() && !future.isCompletedExceptionally()) {
                    try {
                        allResults.addAll(future.get());
                    } catch (Exception e) {
                        log.error("Failed to collect check result: {}", e.getMessage());
                    }
                }
            }

            // Persist findings in one transaction
            persistFindings(scanId, allResults);

            // Mark as COMPLETED
            markCompleted(scanId);

            log.info("Scan {} completed with {} findings.", scanId, allResults.size());

        } catch (Exception e) {
            log.error("Scan {} failed with unexpected error: {}", scanId, e.getMessage(), e);
            markFailed(scanId, "Scan failed: " + e.getMessage());
        }
    }

    /**
     * Re-run a single check for the verify-fix feature.
     * Does NOT modify any scan record.
     */
    public List<CheckResult> executeCheckByName(String checkName, Target target) {
        return securityChecks.stream()
            .filter(c -> c.getCheckName().equals(checkName))
            .findFirst()
            .map(check -> executeCheckSafely(check, target))
            .orElseGet(() -> {
                log.warn("No check found with name: {}", checkName);
                return List.of();
            });
    }

    /**
     * Get all registered check names.
     */
    public List<String> getCheckNames() {
        return securityChecks.stream()
            .map(SecurityCheck::getCheckName)
            .toList();
    }

    // ---- Private helpers ----

    private List<CheckResult> executeCheckSafely(SecurityCheck check, Target target) {
        try {
            log.info("Executing check {} for {}", check.getCheckName(), target.hostname());
            List<CheckResult> results = check.execute(target);
            log.info("Check {} returned {} results", check.getCheckName(), results.size());
            return results;
        } catch (Exception e) {
            log.error("Check {} threw unexpected exception for {}: {}",
                check.getCheckName(), target.hostname(), e.getMessage(), e);
            return List.of(CheckResult.builder(check.getCheckName(), "Check Execution Error")
                .status(CheckStatus.ERROR)
                .severity(Severity.UNKNOWN)
                .description("An internal error prevented this check from running.")
                .evidence("Error: " + e.getClass().getSimpleName())
                .whyItMatters("This check could not be completed.")
                .remediation("Try scanning again.")
                .build());
        }
    }

    @Transactional
    protected void markRunning(String scanId) {
        scanRepository.findById(scanId).ifPresent(scan -> {
            scan.setStatus(ScanStatus.RUNNING);
            scan.setStartedAt(Instant.now());
            scanRepository.save(scan);
        });
    }

    @Transactional
    protected void markCompleted(String scanId) {
        scanRepository.findById(scanId).ifPresent(scan -> {
            scan.setStatus(ScanStatus.COMPLETED);
            scan.setCompletedAt(Instant.now());
            scanRepository.save(scan);
        });
    }

    @Transactional
    protected void markFailed(String scanId, String errorMessage) {
        scanRepository.findById(scanId).ifPresent(scan -> {
            scan.setStatus(ScanStatus.FAILED);
            scan.setCompletedAt(Instant.now());
            scan.setErrorMessage(errorMessage);
            scanRepository.save(scan);
        });
    }

    @Transactional
    protected void persistFindings(String scanId, List<CheckResult> results) {
        Scan scan = scanRepository.findById(scanId).orElse(null);
        if (scan == null) return;

        List<Finding> findings = results.stream()
            .filter(r -> r != null)
            .map(result -> {
                Finding finding = new Finding();
                finding.setScan(scan);
                finding.setCheckName(result.getCheckName());
                finding.setTitle(result.getTitle());
                finding.setSeverity(result.getSeverity());
                finding.setStatus(result.getStatus());
                finding.setDescription(result.getDescription());
                finding.setEvidence(result.getEvidence());
                finding.setWhyItMatters(result.getWhyItMatters());
                finding.setRemediation(result.getRemediation());
                return finding;
            })
            .toList();

        findingRepository.saveAll(findings);
    }
}
