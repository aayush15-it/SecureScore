'use client';

import { useState } from 'react';

interface RemediationPanelProps {
  remediation: string;
}

export default function RemediationPanel({ remediation }: RemediationPanelProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(remediation);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const el = document.createElement('textarea');
      el.value = remediation;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="mb-4">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
          How to Fix
        </h4>
        <button
          id={`copy-remediation-btn`}
          onClick={handleCopy}
          className={`flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg border transition-all
            ${copied
              ? 'bg-green-50 border-green-200 text-green-700'
              : 'bg-white border-gray-200 text-gray-600 hover:border-gray-300 hover:text-gray-900'
            }`}
        >
          {copied ? (
            <>
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
              </svg>
              Copied!
            </>
          ) : (
            <>
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
              </svg>
              Copy Fix
            </>
          )}
        </button>
      </div>

      <div className="relative bg-gray-900 rounded-xl overflow-hidden">
        {/* Syntax highlight header */}
        <div className="flex items-center gap-1.5 px-4 py-2.5 bg-gray-800 border-b border-gray-700">
          <div className="w-3 h-3 rounded-full bg-red-400 opacity-70" />
          <div className="w-3 h-3 rounded-full bg-yellow-400 opacity-70" />
          <div className="w-3 h-3 rounded-full bg-green-400 opacity-70" />
          <span className="ml-2 text-xs text-gray-400">Remediation Guide</span>
        </div>
        <pre className="text-sm text-gray-100 p-4 overflow-x-auto whitespace-pre-wrap font-mono leading-relaxed max-h-64 overflow-y-auto">
          {remediation}
        </pre>
      </div>
    </div>
  );
}
