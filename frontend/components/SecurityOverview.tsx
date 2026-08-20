'use client';

import { FindingResponse } from '@/types';
import { SEVERITY_CONFIG } from '@/types';

interface SecurityOverviewProps {
  findings: FindingResponse[];
  target: string;
}

export default function SecurityOverview({ findings, target }: SecurityOverviewProps) {
  const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = findings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter(f => f.severity === 'LOW').length;
  const passCount = findings.filter(f => f.status === 'PASS').length;
  const unknownCount = findings.filter(f => f.severity === 'UNKNOWN').length;

  const totalIssues = criticalCount + highCount + mediumCount + lowCount;

  const overallStatus = criticalCount > 0 ? 'critical'
    : highCount > 0 ? 'high'
    : mediumCount > 0 ? 'medium'
    : lowCount > 0 ? 'low'
    : 'clean';

  const statusConfig = {
    critical: { label: 'Critical Issues Found', color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-200', icon: '🚨' },
    high: { label: 'Issues Found', color: 'text-red-600', bg: 'bg-red-50', border: 'border-red-200', icon: '⚠️' },
    medium: { label: 'Issues Found', color: 'text-amber-700', bg: 'bg-amber-50', border: 'border-amber-200', icon: '⚠️' },
    low: { label: 'Minor Issues', color: 'text-yellow-700', bg: 'bg-yellow-50', border: 'border-yellow-200', icon: 'ℹ️' },
    clean: { label: 'All Checks Passed', color: 'text-green-700', bg: 'bg-green-50', border: 'border-green-200', icon: '✅' },
  };

  const status = statusConfig[overallStatus];


  const counters = [
    { ...SEVERITY_CONFIG.CRITICAL, label: 'Critical', count: criticalCount },
    { ...SEVERITY_CONFIG.HIGH,     label: 'High',     count: highCount },
    { ...SEVERITY_CONFIG.MEDIUM,   label: 'Medium',   count: mediumCount },
    { ...SEVERITY_CONFIG.LOW,      label: 'Low',      count: lowCount },
    { ...SEVERITY_CONFIG.PASS,     label: 'Passed',   count: passCount },
    { ...SEVERITY_CONFIG.UNKNOWN,  label: 'Unknown',  count: unknownCount },
  ].filter(c => c.count > 0);


  return (
    <div className={`rounded-2xl border-2 p-6 ${status.bg} ${status.border}`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-2xl">{status.icon}</span>
            <h2 className={`text-xl font-bold ${status.color}`}>{status.label}</h2>
          </div>
          <p className="text-sm text-gray-500">
            <span className="font-medium text-gray-700">{target}</span>
            {totalIssues > 0
              ? ` · ${totalIssues} issue${totalIssues !== 1 ? 's' : ''} found across ${findings.length} checks`
              : ` · All ${findings.length} checks passed`
            }
          </p>
          <p className="text-xs text-gray-400 mt-1">
            SecureScore checked 4 externally observable security areas. This is not a complete security audit.
          </p>
        </div>
      </div>

      {/* Severity grid */}
      <div className="flex flex-wrap gap-3">
        {counters.map(c => (
          <div
            key={c.label}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border bg-white/60 backdrop-blur-sm
              ${c.count > 0 ? `${c.border}` : 'border-gray-100'}`}
          >
            <span className="text-lg leading-none">{c.icon}</span>
            <div>
              <span className={`text-2xl font-bold leading-none ${c.color}`}>{c.count}</span>
              <span className={`ml-1.5 text-sm font-medium ${c.color}`}>{c.label}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
