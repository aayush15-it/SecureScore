// SecureScore — Type Definitions

export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'PASS' | 'UNKNOWN';

export type CheckStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | 'ERROR';

export type CheckName = 'SSL_TLS' | 'SECURITY_HEADERS' | 'HTTPS_REDIRECT' | 'COOKIE_SECURITY';

export interface ScanRequest {
  url: string;
}

export interface ScanResponse {
  id: string;
  target: string;
  domainId: number;
  status: ScanStatus;
  completedChecks: number;
  totalChecks: number;
  startedAt: string;
  completedAt: string | null;
  errorMessage: string | null;
  findings: FindingResponse[] | null;
}

export interface FindingResponse {
  id: number | null;
  checkName: string;
  title: string;
  severity: Severity;
  status: CheckStatus;
  description: string;
  evidence: string;
  whyItMatters: string;
  remediation: string;
  createdAt: string;
}

export interface VerifyRequest {
  checkName: string;
}

export interface VerifyResponse {
  checkName: string;
  target: string;
  before: FindingResponse[];
  after: FindingResponse[];
  improved: boolean;
}

export interface ScanSummary {
  id: string;
  status: ScanStatus;
  startedAt: string;
  completedAt: string | null;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  passCount: number;
  unknownCount: number;
}

export interface DomainScanHistoryResponse {
  domainId: number;
  url: string;
  scans: ScanSummary[];
}

export interface ApiError {
  error: string;
  message: string;
  status: number;
  timestamp: string;
}

// UI Helpers
export const SEVERITY_CONFIG: Record<Severity, { label: string; color: string; bg: string; border: string; icon: string }> = {
  CRITICAL: { label: 'Critical', color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-200', icon: '🔴' },
  HIGH:     { label: 'High',     color: 'text-red-600', bg: 'bg-red-50', border: 'border-red-200', icon: '🔴' },
  MEDIUM:   { label: 'Medium',   color: 'text-amber-600', bg: 'bg-amber-50', border: 'border-amber-200', icon: '🟠' },
  LOW:      { label: 'Low',      color: 'text-yellow-600', bg: 'bg-yellow-50', border: 'border-yellow-200', icon: '🟡' },
  INFO:     { label: 'Info',     color: 'text-blue-600', bg: 'bg-blue-50', border: 'border-blue-200', icon: 'ℹ️' },
  PASS:     { label: 'Pass',     color: 'text-green-600', bg: 'bg-green-50', border: 'border-green-200', icon: '✅' },
  UNKNOWN:  { label: 'Unknown',  color: 'text-gray-500', bg: 'bg-gray-50', border: 'border-gray-200', icon: '❔' },
};

export const CHECK_DISPLAY_NAMES: Record<string, string> = {
  SSL_TLS: 'SSL/TLS Certificate',
  SECURITY_HEADERS: 'Security Headers',
  HTTPS_REDIRECT: 'HTTPS Redirect',
  COOKIE_SECURITY: 'Cookie Security',
};

export const SCAN_STATUS_CONFIG: Record<ScanStatus, { label: string; color: string }> = {
  QUEUED: { label: 'Queued', color: 'text-gray-500' },
  RUNNING: { label: 'Scanning...', color: 'text-blue-600' },
  COMPLETED: { label: 'Complete', color: 'text-green-600' },
  FAILED: { label: 'Failed', color: 'text-red-600' },
};
