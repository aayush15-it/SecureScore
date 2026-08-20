'use client';

import { useEffect, useState, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { ScanResponse, FindingResponse, CHECK_DISPLAY_NAMES } from '@/types';
import SecurityOverview from '../../../components/SecurityOverview';
import FindingCard from '../../../components/FindingCard';
import ScanProgressView from '../../../components/ScanProgressView';

const POLL_INTERVAL_MS = 2000;
const MAX_POLLS = 60;

export default function ScanPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pollCount, setPollCount] = useState(0);
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);

  const fetchScan = useCallback(async () => {
    try {
      const data = await api.getScan(scanId);
      setScan(data);
      return data;
    } catch (err: unknown) {
      const apiErr = err as { message?: string };
      setError(apiErr?.message || 'Failed to load scan results.');
      return null;
    }
  }, [scanId]);

  useEffect(() => {
    if (!scanId) return;

    fetchScan();

    const interval = setInterval(async () => {
      setPollCount(c => c + 1);
      const data = await fetchScan();

      if (!data) {
        clearInterval(interval);
        return;
      }

      if (data.status === 'COMPLETED' || data.status === 'FAILED') {
        clearInterval(interval);
        return;
      }

      if (pollCount >= MAX_POLLS) {
        clearInterval(interval);
        setError('Scan is taking longer than expected. Try refreshing.');
      }
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center">
        <div className="bg-red-50 border border-red-200 rounded-xl p-8 inline-block">
          <div className="text-4xl mb-4">⚠️</div>
          <h2 className="text-xl font-bold text-gray-900 mb-2">Something went wrong</h2>
          <p className="text-gray-600 mb-6">{error}</p>
          <button
            onClick={() => router.push('/')}
            className="bg-crimson text-white px-6 py-2.5 rounded-lg font-medium hover:bg-crimson-dark"
          >
            Start New Scan
          </button>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 flex flex-col items-center">
        <div className="animate-spin h-8 w-8 border-4 border-crimson border-t-transparent rounded-full mb-4" />
        <p className="text-gray-500 text-sm">Loading scan...</p>
      </div>
    );
  }

  // Show progress view while running
  if (scan.status === 'QUEUED' || scan.status === 'RUNNING') {
    return <ScanProgressView scan={scan} />;
  }

  // Completed/Failed — show report
  const findings = scan.findings || [];
  const failFindings = findings.filter(f => f.status === 'FAIL' || f.status === 'ERROR');
  const passFindings = findings.filter(f => f.status === 'PASS');

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8 animate-fade-in">

      {/* Report Header */}
      <div className="mb-8">
        <div className="flex items-center gap-2 text-sm text-gray-400 mb-2">
          <button onClick={() => router.push('/')} className="hover:text-gray-600">← New Scan</button>
          <span>/</span>
          <span className="text-gray-600 font-medium">{scan.target}</span>
        </div>
        <h1 className="text-3xl font-bold text-gray-900 mb-1">Security Report</h1>
        <p className="text-gray-500 text-sm">
          Scanned {scan.target} · {scan.completedAt
            ? new Date(scan.completedAt).toLocaleString()
            : new Date(scan.startedAt).toLocaleString()}
        </p>
      </div>

      {scan.status === 'FAILED' && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 mb-6">
          <p className="text-red-700 font-medium">Scan failed</p>
          <p className="text-red-600 text-sm mt-1">{scan.errorMessage || 'An error occurred during scanning.'}</p>
        </div>
      )}

      {/* Security Overview */}
      <SecurityOverview findings={findings} target={scan.target} />

      {/* Priority Findings (non-pass) */}
      {failFindings.length > 0 && (
        <section className="mt-8" id="findings-section">
          <h2 className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 bg-crimson rounded-full" />
            Priority Findings
          </h2>
          <div className="flex flex-col gap-3">
            {failFindings.map((finding, idx) => (
              <FindingCard
                key={finding.id ?? idx}
                finding={finding}
                scanId={scanId}
                isExpanded={expandedFinding === (finding.id ?? idx)}
                onToggle={() => setExpandedFinding(
                  expandedFinding === (finding.id ?? idx) ? null : (finding.id ?? idx)
                )}
              />
            ))}
          </div>
        </section>
      )}

      {/* Passed Checks */}
      {passFindings.length > 0 && (
        <section className="mt-8" id="passed-section">
          <h2 className="text-lg font-bold text-gray-900 mb-4 flex items-center gap-2">
            <span className="w-2 h-2 bg-green-500 rounded-full" />
            Passed Checks
          </h2>
          <div className="flex flex-col gap-2">
            {passFindings.map((finding, idx) => (
              <FindingCard
                key={finding.id ?? idx}
                finding={finding}
                scanId={scanId}
                isExpanded={expandedFinding === (finding.id ?? idx)}
                onToggle={() => setExpandedFinding(
                  expandedFinding === (finding.id ?? idx) ? null : (finding.id ?? idx)
                )}
              />
            ))}
          </div>
        </section>
      )}

      {/* History link */}
      {scan.domainId && (
        <div className="mt-10 text-center">
          <button
            onClick={() => router.push(`/history?domainId=${scan.domainId}`)}
            className="text-sm text-gray-500 hover:text-crimson font-medium transition-colors"
          >
            View scan history for {scan.target} →
          </button>
        </div>
      )}
    </div>
  );
}
