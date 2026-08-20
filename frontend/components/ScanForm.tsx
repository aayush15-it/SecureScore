'use client';

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { ApiError } from '@/types';

export default function ScanForm() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validateUrlFormat = (value: string): string | null => {
    if (!value.trim()) return 'Please enter a website URL.';
    try {
      const u = new URL(value.trim());
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return 'URL must start with http:// or https://';
      }
      if (!u.hostname || u.hostname.length < 2) {
        return 'Please enter a valid domain name.';
      }
      return null;
    } catch {
      // Try prepending https://
      try {
        new URL('https://' + value.trim());
        return null; // valid with prefix
      } catch {
        return 'Please enter a valid URL (e.g. https://example.com)';
      }
    }
  };

  const normalizeUrl = (value: string): string => {
    const trimmed = value.trim();
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      return 'https://' + trimmed;
    }
    return trimmed;
  };

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const normalized = normalizeUrl(url);
    const validationError = validateUrlFormat(normalized);
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    try {
      const scan = await api.createScan({ url: normalized });
      router.push(`/scan/${scan.id}`);
    } catch (err: unknown) {
      const apiErr = err as ApiError;
      setError(apiErr?.message || 'Failed to start scan. Please try again.');
      setLoading(false);
    }
  }, [url, router]);

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div className="relative">
          <div className="absolute inset-y-0 left-4 flex items-center pointer-events-none">
            <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
            </svg>
          </div>
          <input
            id="scan-url-input"
            type="text"
            value={url}
            onChange={e => { setUrl(e.target.value); setError(null); }}
            placeholder="https://yourwebsite.com"
            className={`w-full pl-12 pr-4 py-4 text-lg border-2 rounded-xl bg-white shadow-sm
              focus:outline-none focus:ring-0 transition-colors
              ${error
                ? 'border-red-400 focus:border-red-500'
                : 'border-gray-200 focus:border-crimson'
              }`}
            disabled={loading}
            autoComplete="url"
            autoFocus
          />
        </div>

        {error && (
          <div id="scan-error-msg" className="flex items-start gap-2 text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-4 py-3">
            <svg className="w-4 h-4 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            {error}
          </div>
        )}

        <button
          id="start-scan-btn"
          type="submit"
          disabled={loading || !url.trim()}
          className={`w-full py-4 px-8 rounded-xl text-white font-semibold text-lg
            transition-all duration-200 shadow-md hover:shadow-lg
            ${loading || !url.trim()
              ? 'bg-gray-300 cursor-not-allowed'
              : 'bg-crimson hover:bg-crimson-dark active:scale-[0.99]'
            }`}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-3">
              <svg className="animate-spin h-5 w-5" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Starting Scan...
            </span>
          ) : (
            <span className="flex items-center justify-center gap-2">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              Start Security Scan
            </span>
          )}
        </button>

        <p className="text-center text-xs text-gray-400">
          SecureScore checks 4 external security areas. No software to install.
          Only public websites can be scanned.
        </p>
      </form>
    </div>
  );
}
