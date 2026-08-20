'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { api } from '@/lib/api';
import { ScanResponse, DomainScanHistoryResponse, ScanSummary } from '@/types';

export default function HistoryPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const domainId = searchParams.get('domainId');

  const [allScans, setAllScans] = useState<ScanResponse[]>([]);
  const [domainHistory, setDomainHistory] = useState<DomainScanHistoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        if (domainId) {
          const history = await api.getDomainHistory(Number(domainId));
          setDomainHistory(history);
        } else {
          const scans = await api.getAllScans();
          setAllScans(scans);
        }
      } catch (err: unknown) {
        const apiErr = err as { message?: string };
        setError(apiErr?.message || 'Failed to load history.');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [domainId]);

  if (loading) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 flex flex-col items-center">
        <div className="animate-spin h-8 w-8 border-4 border-crimson border-t-transparent rounded-full mb-4" />
        <p className="text-gray-500 text-sm">Loading history...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center">
        <p className="text-red-600 mb-4">{error}</p>
        <button onClick={() => router.push('/')} className="text-crimson underline">
          Go back
        </button>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-8">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-1">
          {domainHistory ? `Scan History — ${domainHistory.url}` : 'All Scans'}
        </h1>
        <p className="text-gray-500 text-sm">
          {domainHistory
            ? `${domainHistory.scans.length} scan${domainHistory.scans.length !== 1 ? 's' : ''} recorded`
            : `${allScans.length} total scan${allScans.length !== 1 ? 's' : ''}`}
        </p>
      </div>

      {domainHistory ? (
        <DomainHistoryView history={domainHistory} onScanClick={(id) => router.push(`/scan/${id}`)} />
      ) : (
        <AllScansView scans={allScans} onScanClick={(id) => router.push(`/scan/${id}`)} />
      )}

      {!domainHistory && allScans.length === 0 && (
        <div className="text-center py-16">
          <div className="text-5xl mb-4">🔍</div>
          <h2 className="text-xl font-semibold text-gray-900 mb-2">No scans yet</h2>
          <p className="text-gray-500 mb-6">Start your first security scan to see results here.</p>
          <button
            onClick={() => router.push('/')}
            className="bg-crimson text-white px-6 py-2.5 rounded-lg font-medium hover:bg-crimson-dark"
          >
            Start a Scan
          </button>
        </div>
      )}
    </div>
  );
}

function DomainHistoryView({
  history,
  onScanClick,
}: {
  history: DomainScanHistoryResponse;
  onScanClick: (id: string) => void;
}) {
  return (
    <div>
      {/* Improvement timeline */}
      {history.scans.length >= 2 && (
        <div className="bg-white border border-gray-100 rounded-xl p-5 mb-6 shadow-card">
          <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-4">
            Security Progress
          </h2>
          <div className="flex items-stretch gap-3 overflow-x-auto pb-2">
            {[...history.scans].reverse().map((scan, idx) => (
              <div key={scan.id} className="flex flex-col items-center min-w-[100px]">
                {idx > 0 && (
                  <div className="flex items-center self-start w-full">
                    <div className="flex-1 h-0.5 bg-gray-200" />
                    <span className="text-xs text-gray-300 px-1">→</span>
                  </div>
                )}
                <ScanMiniCard scan={scan} onClick={() => onScanClick(scan.id)} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* List */}
      <div className="flex flex-col gap-3">
        {history.scans.map(scan => (
          <ScanHistoryRow key={scan.id} scan={scan} onClick={() => onScanClick(scan.id)} />
        ))}
      </div>
    </div>
  );
}

function AllScansView({
  scans,
  onScanClick,
}: {
  scans: ScanResponse[];
  onScanClick: (id: string) => void;
}) {
  return (
    <div className="flex flex-col gap-3">
      {scans.map(scan => (
        <button
          key={scan.id}
          onClick={() => onScanClick(scan.id)}
          className="w-full text-left bg-white border border-gray-100 rounded-xl p-4 shadow-card
            hover:shadow-card-hover hover:border-gray-200 transition-all"
        >
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="font-semibold text-gray-900">{scan.target}</p>
              <p className="text-xs text-gray-400 mt-0.5">
                {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : '—'}
              </p>
            </div>
            <StatusBadge status={scan.status} />
          </div>
          {scan.findings && (
            <div className="mt-3 flex flex-wrap gap-2">
              <MiniCount icon="🔴" count={scan.findings.filter(f => f.severity === 'HIGH' || f.severity === 'CRITICAL').length} label="High" />
              <MiniCount icon="🟠" count={scan.findings.filter(f => f.severity === 'MEDIUM').length} label="Med" />
              <MiniCount icon="✅" count={scan.findings.filter(f => f.status === 'PASS').length} label="Pass" />
            </div>
          )}
        </button>
      ))}
    </div>
  );
}

function ScanHistoryRow({ scan, onClick }: { scan: ScanSummary; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left bg-white border border-gray-100 rounded-xl p-4 shadow-card
        hover:shadow-card-hover hover:border-gray-200 transition-all"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs text-gray-400">
            {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : '—'}
          </p>
        </div>
        <StatusBadge status={scan.status} />
      </div>
      <div className="mt-2 flex flex-wrap gap-2">
        <MiniCount icon="🔴" count={scan.highCount} label="High" />
        <MiniCount icon="🟠" count={scan.mediumCount} label="Med" />
        <MiniCount icon="🟡" count={scan.lowCount} label="Low" />
        <MiniCount icon="✅" count={scan.passCount} label="Pass" />
      </div>
    </button>
  );
}

function ScanMiniCard({ scan, onClick }: { scan: ScanSummary; onClick: () => void }) {
  const total = scan.highCount + scan.mediumCount + scan.lowCount;
  return (
    <button
      onClick={onClick}
      className={`text-center p-3 rounded-xl border-2 min-w-[80px] hover:border-crimson transition-colors
        ${total === 0 ? 'border-green-200 bg-green-50' : 'border-amber-200 bg-amber-50'}`}
    >
      <p className="text-2xl font-bold text-gray-900">{total}</p>
      <p className="text-xs text-gray-500">issues</p>
      <p className="text-xs text-gray-400 mt-1">
        {scan.startedAt ? new Date(scan.startedAt).toLocaleDateString() : '—'}
      </p>
    </button>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    COMPLETED: 'bg-green-50 text-green-700 border-green-200',
    RUNNING: 'bg-blue-50 text-blue-700 border-blue-200',
    QUEUED: 'bg-gray-50 text-gray-600 border-gray-200',
    FAILED: 'bg-red-50 text-red-700 border-red-200',
  };
  return (
    <span className={`text-xs font-semibold px-2.5 py-1 rounded-full border ${colors[status] || colors.QUEUED}`}>
      {status}
    </span>
  );
}

function MiniCount({ icon, count, label }: { icon: string; count: number; label: string }) {
  if (count === 0) return null;
  return (
    <span className="text-xs bg-gray-50 border border-gray-100 rounded-full px-2.5 py-1 font-medium text-gray-600">
      {icon} {count} {label}
    </span>
  );
}
