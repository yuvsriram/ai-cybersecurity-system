import {
  apiRequest,
} from './client'

import type {
  InvestigationResult,
} from './types'

export type InvestigationRunStatus =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'

export interface InvestigationRun {
  id: string
  alert_id: string

  status: InvestigationRunStatus

  provider: string
  model: string
  prompt_version: string

  created_at: string
  started_at: string | null
  completed_at: string | null

  result: InvestigationResult | null

  error_message: string | null
}

export async function listInvestigationRuns(
  apiKey: string | null,
  alertId: string,
  signal?: AbortSignal,
): Promise<InvestigationRun[]> {
  return apiRequest<
    InvestigationRun[]
  >(
    `/api/v1/alerts/${encodeURIComponent(
      alertId,
    )}/investigations`,
    {
      apiKey,
      signal,
    },
  )
}

export async function getInvestigationRun(
  apiKey: string | null,
  alertId: string,
  runId: string,
  signal?: AbortSignal,
): Promise<InvestigationRun> {
  return apiRequest<
    InvestigationRun
  >(
    `/api/v1/alerts/${encodeURIComponent(
      alertId,
    )}/investigations/${encodeURIComponent(
      runId,
    )}`,
    {
      apiKey,
      signal,
    },
  )
}

export async function createInvestigationRun(
  apiKey: string | null,
  alertId: string,
  signal?: AbortSignal,
): Promise<InvestigationRun> {
  return apiRequest<
    InvestigationRun
  >(
    `/api/v1/alerts/${encodeURIComponent(
      alertId,
    )}/investigations`,
    {
      method: 'POST',
      apiKey,
      signal,
    },
  )
}