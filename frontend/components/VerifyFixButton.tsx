'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { FindingResponse, VerifyResponse } from '@/types';
import { SEVERITY_CONFIG } from '@/types';

interface VerifyFixButtonProps {
  scanId: string;
  checkName: string;
  originalFinding: FindingResponse;
}

export default function VerifyFixButton({ scanId, checkName, originalFinding }: VerifyFixButtonProps) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerifyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleVerify = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await api.verifyFix(scanId, { checkName });
      setResult(response);
    } catch (err: unknown) {
      const apiErr = err as { message?: string };
      setError(apiErr?.message || 'Verification failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {!result && (
        <button
          id={`verify-fix-btn-${checkName}`}
          onClick={handleVerify}
          disabled={loading}
          className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border-2 text-sm font-semibold
            transition-all duration-200
            ${loading
              ? 'border-gray-200 bg-gray-50 text-gray-400 cursor-not-allowed'
              : 'border-crimson text-crimson hover:bg-crimson hover:text-white'
            }`}
        >
          {loading ? (
            <>
              <div className="w-4 h-4 border-2 border-gray-400 border-t-transparent rounded-full animate-spin" />
              Re-running check...
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              Verify Fix
            </>
          )}
        </button>
      )}

      {error && (
        <div className="mt-3 p-3 bg-red-50 border border-red-100 rounded-lg text-sm text-red-600">
          {error}
          <button onClick={handleVerify} className="ml-2 underline text-red-700 font-medium">
            Retry
          </button>
        </div>
      )}

      {result && (
        <div className="mt-4 animate-slide-up">
          {/* Before / After comparison */}
          <div className={`rounded-xl border-2 p-4 ${
            result.improved ? 'border-green-200 bg-green-50' : 'border-amber-200 bg-amber-50'
          }`}>
            <div className="flex items-center gap-2 mb-4">
              <span className="text-xl">{result.improved ? '🎉' : '⚠️'}</span>
              <h4 className={`font-bold ${result.improved ? 'text-green-700' : 'text-amber-700'}`}>
                {result.improved ? 'Issue Resolved!' : 'Issue Still Present'}
              </h4>
            </div>

            <div className="grid grid-cols-2 gap-3">
              {/* Before */}
              <div>
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Before</p>
                {result.before.map((f, i) => (
                  <div key={i} className="flex items-start gap-2 bg-white/70 rounded-lg p-2.5 border border-red-100">
                    <span className="text-red-500 mt-0.5 flex-shrink-0">❌</span>
                    <div>
                      <p className="text-xs font-medium text-gray-800">{f.title}</p>
                      <span className={`text-xs font-semibold ${SEVERITY_CONFIG[f.severity].color}`}>
                        {f.severity}
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* After */}
              <div>
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">After</p>
                {result.after.map((f, i) => (
                  <div key={i} className={`flex items-start gap-2 bg-white/70 rounded-lg p-2.5 border
                    ${f.status === 'PASS' ? 'border-green-100' : 'border-amber-100'}`}>
                    <span className={`mt-0.5 flex-shrink-0 ${f.status === 'PASS' ? 'text-green-500' : 'text-amber-500'}`}>
                      {f.status === 'PASS' ? '✅' : '⚠️'}
                    </span>
                    <div>
                      <p className="text-xs font-medium text-gray-800">{f.title}</p>
                      <span className={`text-xs font-semibold ${SEVERITY_CONFIG[f.severity].color}`}>
                        {f.severity}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <button
              onClick={() => setResult(null)}
              className="mt-3 text-xs text-gray-400 hover:text-gray-600 underline"
            >
              Re-verify again
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
