import {
  ScanRequest,
  ScanResponse,
  FindingResponse,
  VerifyRequest,
  VerifyResponse,
  DomainScanHistoryResponse,
} from '@/types';

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8080';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BACKEND_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {}),
    },
  });

  if (!res.ok) {
    const error = await res.json().catch(() => ({
      error: 'UNKNOWN',
      message: `Request failed with status ${res.status}`,
      status: res.status,
    }));
    throw error;
  }

  return res.json();
}

export const api = {
  /**
   * Create a new scan.
   */
  createScan: (data: ScanRequest): Promise<ScanResponse> =>
    request('/api/scans', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  /**
   * Get scan status and findings.
   */
  getScan: (scanId: string): Promise<ScanResponse> =>
    request(`/api/scans/${scanId}`),

  /**
   * Get all findings for a scan.
   */
  getFindings: (scanId: string): Promise<FindingResponse[]> =>
    request(`/api/scans/${scanId}/findings`),

  /**
   * Verify a fix was applied by re-running a check.
   */
  verifyFix: (scanId: string, data: VerifyRequest): Promise<VerifyResponse> =>
    request(`/api/scans/${scanId}/verify`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  /**
   * Get all past scans.
   */
  getAllScans: (): Promise<ScanResponse[]> =>
    request('/api/scans'),

  /**
   * Get scan history for a domain.
   */
  getDomainHistory: (domainId: number): Promise<DomainScanHistoryResponse> =>
    request(`/api/domains/${domainId}/scans`),
};
