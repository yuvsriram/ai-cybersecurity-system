import {
  apiRequest,
} from './client'

import type {
  SecurityAlert,
} from './types'

export type CaseStatus =
  | 'open'
  | 'investigating'
  | 'resolved'
  | 'closed'

export type CaseSeverity =
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export interface SecurityCase {
  id: string

  title: string
  summary: string | null

  status: CaseStatus
  severity: CaseSeverity

  creation_source: string

  created_at: string
  updated_at: string
  closed_at: string | null
}

export interface CaseDetail
  extends SecurityCase {
  alerts: SecurityAlert[]
}

export interface CaseCreateRequest {
  title: string

  summary: string | null

  severity: CaseSeverity

  alert_ids: string[]
}

export interface CaseQuery {
  limit?: number
  offset?: number
  status?: CaseStatus | ''
  severity?: CaseSeverity | ''
}

export async function listCases(
  apiKey: string | null,
  query: CaseQuery = {},
  signal?: AbortSignal,
): Promise<SecurityCase[]> {
  const parameters =
    new URLSearchParams()

  parameters.set(
    'limit',
    String(
      query.limit ?? 100,
    ),
  )

  parameters.set(
    'offset',
    String(
      query.offset ?? 0,
    ),
  )

  if (query.status) {
    parameters.set(
      'status',
      query.status,
    )
  }

  if (query.severity) {
    parameters.set(
      'severity',
      query.severity,
    )
  }

  return apiRequest<
    SecurityCase[]
  >(
    `/api/v1/cases?${parameters.toString()}`,
    {
      apiKey,
      signal,
    },
  )
}

export async function getCase(
  apiKey: string | null,
  caseId: string,
  signal?: AbortSignal,
): Promise<CaseDetail> {
  return apiRequest<
    CaseDetail
  >(
    `/api/v1/cases/${encodeURIComponent(
      caseId,
    )}`,
    {
      apiKey,
      signal,
    },
  )
}

export async function createCase(
  apiKey: string | null,
  request: CaseCreateRequest,
  signal?: AbortSignal,
): Promise<CaseDetail> {
  return apiRequest<
    CaseDetail
  >(
    '/api/v1/cases',
    {
      method: 'POST',

      apiKey,

      signal,

      headers: {
        'Content-Type':
          'application/json',
      },

      body: JSON.stringify(
        request,
      ),
    },
  )
}

export async function addAlertToCase(
  apiKey: string | null,
  caseId: string,
  alertId: string,
  signal?: AbortSignal,
): Promise<CaseDetail> {
  return apiRequest<
    CaseDetail
  >(
    `/api/v1/cases/${encodeURIComponent(
      caseId,
    )}/alerts/${encodeURIComponent(
      alertId,
    )}`,
    {
      method: 'POST',
      apiKey,
      signal,
    },
  )
}