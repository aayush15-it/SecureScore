package com.securescore.scanner;

import java.util.List;

/**
 * Core abstraction for all security checks.
 *
 * Each implementation is independently testable and can be added
 * to the orchestrator without rewriting existing checks.
 */
public interface SecurityCheck {

    /**
     * Execute the security check against the given target.
     *
     * Implementations should:
     * - Never throw unchecked exceptions that crash the orchestrator
     * - Return CheckStatus.ERROR instead of throwing when a check fails
     * - Return CheckStatus.UNKNOWN when the check cannot make a confident determination
     * - Use appropriate Severity values (not inflate findings)
     *
     * @param target the validated scan target
     * @return list of findings (may be multiple per check, e.g. one per header)
     */
    List<CheckResult> execute(Target target);

    /**
     * Unique identifier for this check type.
     * Used for routing verify-fix requests.
     */
    String getCheckName();

    /**
     * Human-readable display name.
     */
    String getDisplayName();
}
