package com.securescore.service;

import com.securescore.dto.*;
import com.securescore.entity.*;
import com.securescore.exception.InvalidUrlException;
import com.securescore.exception.ScanNotFoundException;
import com.securescore.repository.DomainRepository;
import com.securescore.repository.FindingRepository;
import com.securescore.repository.ScanRepository;
import com.securescore.scanner.CheckResult;
import com.securescore.scanner.Target;
import com.securescore.util.InMemoryRateLimiter;
import com.securescore.util.SsrfValidator;
import com.securescore.util.UrlNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final ScanRepository scanRepository;
    private final DomainRepository domainRepository;
    private final FindingRepository findingRepository;
    private final SsrfValidator ssrfValidator;
    private final UrlNormalizer urlNormalizer;
    private final ScanOrchestrator orchestrator;
    private final InMemoryRateLimiter rateLimiter;

    public ScanService(ScanRepository scanRepository, DomainRepository domainRepository,
                       FindingRepository findingRepository, SsrfValidator ssrfValidator,
                       UrlNormalizer urlNormalizer, ScanOrchestrator orchestrator,
                       InMemoryRateLimiter rateLimiter) {
        this.scanRepository = scanRepository;
        this.domainRepository = domainRepository;
        this.findingRepository = findingRepository;
        this.ssrfValidator = ssrfValidator;
        this.urlNormalizer = urlNormalizer;
        this.orchestrator = orchestrator;
        this.rateLimiter = rateLimiter;
    }

    /**
     * Create a new scan for the given URL.
     * Validates URL, checks SSRF, creates DB records, triggers async scan.
     */
    @Transactional
    public ScanResponse createScan(ScanRequest request, String clientIp) {
        // Rate limiting
        rateLimiter.checkLimit(clientIp);

        // Validate and SSRF-check URL
        URI uri = ssrfValidator.validate(request.url());

        String normalizedUrl = urlNormalizer.normalize(request.url());
        String hostname = uri.getHost();
        String displayHost = urlNormalizer.extractDisplayHost(request.url());
        boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());

        // Find or create domain
        Domain domain = domainRepository.findByNormalizedUrl(normalizedUrl)
            .orElseGet(() -> {
                Domain d = new Domain(request.url(), normalizedUrl);
                return domainRepository.save(d);
            });

        // Create scan record
        String scanId = UUID.randomUUID().toString();
        Scan scan = new Scan(scanId, domain);
        scanRepository.save(scan);

        // Build target
        Target target = new Target(request.url(), normalizedUrl, hostname, displayHost, isHttps);

        // Launch async scan — pass scanId not entity to avoid detached entity across threads
        orchestrator.executeScan(scanId, target);

        log.info("Scan {} created for target {}", scanId, hostname);

        return new ScanResponse(scanId, displayHost, domain.getId(),
            ScanStatus.QUEUED, 0, 4, scan.getStartedAt(), null, null, null);
    }

    /**
     * Get current scan status and findings (if completed).
     */
    @Transactional(readOnly = true)
    public ScanResponse getScan(String scanId) {
        Scan scan = scanRepository.findById(scanId)
            .orElseThrow(() -> new ScanNotFoundException(scanId));

        List<FindingResponse> findings = null;
        if (scan.getStatus() == ScanStatus.COMPLETED || scan.getStatus() == ScanStatus.FAILED) {
            findings = findingRepository.findByScanId(scanId).stream()
                .map(FindingResponse::from)
                .toList();
        }

        int completedChecks = 0;
        if (scan.getStatus() == ScanStatus.COMPLETED || scan.getStatus() == ScanStatus.FAILED) {
            completedChecks = 4;
        } else if (scan.getStatus() == ScanStatus.RUNNING) {
            // Approximate: count distinct check names in findings so far
            completedChecks = (int) findingRepository.findByScanId(scanId).stream()
                .map(Finding::getCheckName)
                .distinct()
                .count();
        }

        String displayHost = urlNormalizer.extractDisplayHost(scan.getDomain().getNormalizedUrl());

        return new ScanResponse(
            scan.getId(),
            displayHost,
            scan.getDomain().getId(),
            scan.getStatus(),
            completedChecks,
            4,
            scan.getStartedAt(),
            scan.getCompletedAt(),
            scan.getErrorMessage(),
            findings
        );
    }

    /**
     * Get all findings for a scan.
     */
    @Transactional(readOnly = true)
    public List<FindingResponse> getFindings(String scanId) {
        if (!scanRepository.existsById(scanId)) {
            throw new ScanNotFoundException(scanId);
        }
        return findingRepository.findByScanId(scanId).stream()
            .map(FindingResponse::from)
            .toList();
    }

    /**
     * Verify fix — re-run a specific check and return before/after comparison.
     */
    @Transactional(readOnly = true)
    public VerifyResponse verifyFix(String scanId, VerifyRequest request) {
        Scan scan = scanRepository.findById(scanId)
            .orElseThrow(() -> new ScanNotFoundException(scanId));

        String checkName = request.checkName().toUpperCase().replace("-", "_").replace(" ", "_");

        if (!orchestrator.getCheckNames().contains(checkName)) {
            throw new InvalidUrlException("Unknown check name: " + checkName +
                ". Valid values: " + String.join(", ", orchestrator.getCheckNames()));
        }

        // Get original findings for this check
        List<FindingResponse> before = findingRepository.findByScanId(scanId).stream()
            .filter(f -> f.getCheckName().equals(checkName))
            .map(FindingResponse::from)
            .toList();

        // Build target from scan domain
        Domain domain = scan.getDomain();
        URI uri = ssrfValidator.validate(domain.getNormalizedUrl());
        String hostname = uri.getHost();
        String displayHost = urlNormalizer.extractDisplayHost(domain.getNormalizedUrl());
        boolean isHttps = domain.getNormalizedUrl().startsWith("https://");

        Target target = new Target(domain.getUrl(), domain.getNormalizedUrl(),
            hostname, displayHost, isHttps);

        // Re-run the check
        List<CheckResult> newResults = orchestrator.executeCheckByName(checkName, target);

        List<FindingResponse> after = newResults.stream()
            .map(r -> new FindingResponse(
                null, r.getCheckName(), r.getTitle(), r.getSeverity(),
                r.getStatus(), r.getDescription(), r.getEvidence(),
                r.getWhyItMatters(), r.getRemediation(), r.getTimestamp()
            ))
            .toList();

        // Determine if improved: if any FAIL finding is now PASS
        boolean improved = before.stream()
            .anyMatch(b -> b.status() == CheckStatus.FAIL) &&
            after.stream().allMatch(a -> a.status() == CheckStatus.PASS);

        return new VerifyResponse(checkName, displayHost, before, after, improved);
    }

    /**
     * Get scan history for a domain.
     */
    @Transactional(readOnly = true)
    public DomainScanHistoryResponse getDomainHistory(Long domainId) {
        Domain domain = domainRepository.findById(domainId)
            .orElseThrow(() -> new ScanNotFoundException("Domain " + domainId));

        List<Scan> scans = scanRepository.findByDomainIdOrderByStartedAtDesc(domainId);

        List<DomainScanHistoryResponse.ScanSummary> summaries = scans.stream()
            .map(scan -> {
                List<Finding> findings = findingRepository.findByScanId(scan.getId());
                long high = findings.stream().filter(f -> f.getSeverity() == Severity.HIGH || f.getSeverity() == Severity.CRITICAL).count();
                long medium = findings.stream().filter(f -> f.getSeverity() == Severity.MEDIUM).count();
                long low = findings.stream().filter(f -> f.getSeverity() == Severity.LOW).count();
                long pass = findings.stream().filter(f -> f.getStatus() == CheckStatus.PASS).count();
                long unknown = findings.stream().filter(f -> f.getSeverity() == Severity.UNKNOWN).count();

                return new DomainScanHistoryResponse.ScanSummary(
                    scan.getId(), scan.getStatus(), scan.getStartedAt(),
                    scan.getCompletedAt(), (int)high, (int)medium, (int)low,
                    (int)pass, (int)unknown
                );
            })
            .toList();

        return new DomainScanHistoryResponse(domain.getId(),
            urlNormalizer.extractDisplayHost(domain.getNormalizedUrl()), summaries);
    }

    /**
     * Get all scans (for global history view).
     */
    @Transactional(readOnly = true)
    public List<ScanResponse> getAllScans() {
        return scanRepository.findAll().stream()
            .sorted((a, b) -> {
                if (a.getStartedAt() == null) return 1;
                if (b.getStartedAt() == null) return -1;
                return b.getStartedAt().compareTo(a.getStartedAt());
            })
            .map(scan -> {
                String displayHost = urlNormalizer.extractDisplayHost(scan.getDomain().getNormalizedUrl());
                List<FindingResponse> findings = null;
                if (scan.getStatus() == ScanStatus.COMPLETED || scan.getStatus() == ScanStatus.FAILED) {
                    findings = findingRepository.findByScanId(scan.getId()).stream()
                        .map(FindingResponse::from)
                        .toList();
                }
                return new ScanResponse(scan.getId(), displayHost, scan.getDomain().getId(),
                    scan.getStatus(), 4, 4, scan.getStartedAt(), scan.getCompletedAt(),
                    scan.getErrorMessage(), findings);
            })
            .toList();
    }
}
