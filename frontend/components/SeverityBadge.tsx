'use client';

import { Severity, CheckStatus } from '@/types';
import { SEVERITY_CONFIG } from '@/types';

interface SeverityBadgeProps {
  severity: Severity;
  status?: CheckStatus;
  size?: 'sm' | 'md' | 'lg';
}

export default function SeverityBadge({ severity, status, size = 'md' }: SeverityBadgeProps) {
  const config = SEVERITY_CONFIG[severity];
  
  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-xs px-2.5 py-1',
    lg: 'text-sm px-3 py-1.5',
  };

  return (
    <span className={`inline-flex items-center gap-1 font-medium rounded-full border
      ${config.color} ${config.bg} ${config.border}
      ${sizeClasses[size]}`}
    >
      <span>{config.icon}</span>
      <span>{config.label}</span>
    </span>
  );
}
