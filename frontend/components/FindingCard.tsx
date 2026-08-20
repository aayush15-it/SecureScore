'use client';

import { useState } from 'react';
import { FindingResponse } from '@/types';
import { SEVERITY_CONFIG } from '@/types';
import SeverityBadge from '@/components/SeverityBadge';
import RemediationPanel from '@/components/RemediationPanel';
import VerifyFixButton from '@/components/VerifyFixButton';

interface FindingCardProps {
  finding: FindingResponse;
  scanId: string;
  isExpanded: boolean;
  onToggle: () => void;
}

export default function FindingCard({ finding, scanId, isExpanded, onToggle }: FindingCardProps) {
  const config = SEVERITY_CONFIG[finding.severity];
  const isPass = finding.status === 'PASS';

  return (
    <div
      className={`bg-white border rounded-xl overflow-hidden shadow-card transition-all duration-200
        ${isExpanded ? 'shadow-card-hover' : 'hover:shadow-card-hover'}
        ${isPass ? 'border-green-100' : `border-gray-100`}`}
    >
      {/* Header — always visible */}
      <button
        id={`finding-${finding.id}`}
        className="w-full text-left px-5 py-4 flex items-start gap-3"
        onClick={onToggle}
        aria-expanded={isExpanded}
      >
        <div className="flex-shrink-0 mt-0.5">
          {isPass ? (
            <div className="w-8 h-8 bg-green-50 rounded-lg flex items-center justify-center border border-green-100">
              <svg className="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
              </svg>
            </div>
          ) : (
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center border ${config.bg} ${config.border}`}>
              <span className="text-base leading-none">{config.icon}</span>
            </div>
          )}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <h3 className="font-semibold text-gray-900 text-sm leading-tight">{finding.title}</h3>
              <p className="text-xs text-gray-500 mt-0.5 truncate">{finding.checkName.replace(/_/g, ' ')}</p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <SeverityBadge severity={finding.severity} status={finding.status} size="sm" />
              <svg
                className={`w-4 h-4 text-gray-400 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                fill="none" stroke="currentColor" viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            </div>
          </div>

          {!isExpanded && (
            <p className="text-xs text-gray-400 mt-1 line-clamp-1">{finding.description}</p>
          )}
        </div>
      </button>

      {/* Expanded content */}
      {isExpanded && (
        <div className="px-5 pb-5 border-t border-gray-50 animate-fade-in">
          {/* Description */}
          <div className="py-4">
            <p className="text-sm text-gray-700">{finding.description}</p>
          </div>

          {/* Evidence */}
          {finding.evidence && (
            <div className="mb-4">
              <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">What We Found</h4>
              <div className="bg-gray-50 border border-gray-100 rounded-lg px-4 py-3">
                <pre className="text-xs text-gray-700 whitespace-pre-wrap font-mono">{finding.evidence}</pre>
              </div>
            </div>
          )}

          {/* Why it matters */}
          {finding.whyItMatters && !isPass && (
            <div className="mb-4">
              <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Why It Matters</h4>
              <p className="text-sm text-gray-600 bg-amber-50 border border-amber-100 rounded-lg px-4 py-3">
                {finding.whyItMatters}
              </p>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && !isPass && (
            <RemediationPanel remediation={finding.remediation} />
          )}

          {/* Verify Fix button */}
          {!isPass && (
            <div className="mt-4">
              <VerifyFixButton
                scanId={scanId}
                checkName={finding.checkName}
                originalFinding={finding}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
