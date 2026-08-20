'use client';

import { ScanResponse, CHECK_DISPLAY_NAMES } from '@/types';

const CHECKS = ['SSL_TLS', 'SECURITY_HEADERS', 'HTTPS_REDIRECT', 'COOKIE_SECURITY'];

interface ScanProgressViewProps {
  scan: ScanResponse;
}

export default function ScanProgressView({ scan }: ScanProgressViewProps) {
  const completedChecks = scan.completedChecks || 0;

  return (
    <div className="max-w-2xl mx-auto px-4 py-16">
      <div className="bg-white border border-gray-100 rounded-2xl shadow-card p-8 text-center">

        {/* Animated Shield */}
        <div className="flex justify-center mb-6">
          <div className="relative">
            <div className="w-20 h-20 bg-red-50 rounded-full flex items-center justify-center">
              <svg className="w-10 h-10 text-crimson" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round"
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            {/* Outer ring */}
            <div className="absolute inset-0 border-4 border-crimson border-t-transparent rounded-full animate-spin" />
          </div>
        </div>

        <h1 className="text-2xl font-bold text-gray-900 mb-1">Security Scan Running</h1>
        <p className="text-gray-500 mb-1">
          Scanning <span className="font-semibold text-gray-700">{scan.target}</span>
        </p>
        <p className="text-sm text-gray-400 mb-8">
          {completedChecks} of {scan.totalChecks} checks complete
        </p>

        {/* Progress bar */}
        <div className="w-full bg-gray-100 rounded-full h-2 mb-8 overflow-hidden">
          <div
            className="h-2 bg-crimson rounded-full transition-all duration-500"
            style={{ width: `${(completedChecks / scan.totalChecks) * 100}%` }}
          />
        </div>

        {/* Check list */}
        <div className="text-left space-y-3">
          {CHECKS.map((checkName, idx) => {
            const isComplete = idx < completedChecks;
            const isRunning = idx === completedChecks && scan.status === 'RUNNING';
            const isPending = idx > completedChecks;

            return (
              <div
                key={checkName}
                className={`flex items-center gap-3 p-3 rounded-lg transition-colors
                  ${isComplete ? 'bg-green-50' : isRunning ? 'bg-blue-50' : 'bg-gray-50'}`}
              >
                {/* Status icon */}
                <div className="flex-shrink-0 w-6 h-6 flex items-center justify-center">
                  {isComplete ? (
                    <svg className="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : isRunning ? (
                    <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <div className="w-4 h-4 border-2 border-gray-200 rounded-full" />
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium ${
                    isComplete ? 'text-green-700'
                    : isRunning ? 'text-blue-700'
                    : 'text-gray-400'
                  }`}>
                    {CHECK_DISPLAY_NAMES[checkName] || checkName}
                  </p>
                </div>

                <div className="text-xs">
                  {isComplete && <span className="text-green-600 font-medium">Done</span>}
                  {isRunning && <span className="text-blue-600 font-medium scan-pulse">Running...</span>}
                  {isPending && <span className="text-gray-300">Pending</span>}
                </div>
              </div>
            );
          })}
        </div>

        <p className="mt-6 text-xs text-gray-400">
          This page updates automatically. Please wait...
        </p>
      </div>
    </div>
  );
}
