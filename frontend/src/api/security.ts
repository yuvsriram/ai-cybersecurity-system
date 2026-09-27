import {
  apiRequest,
} from './client'

import type {
  AlertEvidence,
  AnalysisRequest,
  LogAnalysisExplanationResponse,
  LogAnalysisResponse,
  SecurityAlert,
  SecurityEvent,
  SecurityOverview,
} from './types'

const MAX_PAGE_SIZE = 500

export interface EventQuery {
  limit?: number
  offset?: number
  eventCode?: string
  userName?: string
}

export interface AlertQuery {
  limit?: number
  offset?: number
  severity?: string
  ruleId?: string
}

function setOptionalParameter(
  parameters: URLSearchParams,
  name: string,
  value: string | undefined,
) {
  const normalized =
    value?.trim()

  if (normalized) {
    parameters.set(
      name,
      normalized,
    )
  }
}

export async function analyzeLogs(
  apiKey: string | null,
  request: AnalysisRequest,
  signal?: AbortSignal,
): Promise<LogAnalysisResponse> {
  return apiRequest<LogAnalysisResponse>(
    '/api/v1/analyze',
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

export async function explainLogs(
  apiKey: string | null,
  request: AnalysisRequest,
  signal?: AbortSignal,
): Promise<LogAnalysisExplanationResponse> {
  return apiRequest<
    LogAnalysisExplanationResponse
  >(
    '/api/v1/analyze/explain',
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

export async function listEvents(
  apiKey: string | null,
  query: EventQuery = {},
  signal?: AbortSignal,
): Promise<SecurityEvent[]> {
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

  setOptionalParameter(
    parameters,
    'event_code',
    query.eventCode,
  )

  setOptionalParameter(
    parameters,
    'user_name',
    query.userName,
  )

  return apiRequest<SecurityEvent[]>(
    `/api/v1/events?${parameters.toString()}`,
    {
      apiKey,
      signal,
    },
  )
}

export async function getEvent(
  apiKey: string | null,
  eventId: number,
  signal?: AbortSignal,
): Promise<SecurityEvent> {
  return apiRequest<SecurityEvent>(
    `/api/v1/events/${eventId}`,
    {
      apiKey,
      signal,
    },
  )
}

export async function listAlerts(
  apiKey: string | null,
  query: AlertQuery = {},
  signal?: AbortSignal,
): Promise<SecurityAlert[]> {
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

  setOptionalParameter(
    parameters,
    'severity',
    query.severity,
  )

  setOptionalParameter(
    parameters,
    'rule_id',
    query.ruleId,
  )

  return apiRequest<SecurityAlert[]>(
    `/api/v1/alerts?${parameters.toString()}`,
    {
      apiKey,
      signal,
    },
  )
}

export async function getAlert(
  apiKey: string | null,
  alertId: string,
  signal?: AbortSignal,
): Promise<SecurityAlert> {
  return apiRequest<SecurityAlert>(
    `/api/v1/alerts/${encodeURIComponent(
      alertId,
    )}`,
    {
      apiKey,
      signal,
    },
  )
}

export async function getAlertEvidence(
  apiKey: string | null,
  alertId: string,
  signal?: AbortSignal,
): Promise<AlertEvidence> {
  return apiRequest<AlertEvidence>(
    `/api/v1/alerts/${encodeURIComponent(
      alertId,
    )}/evidence`,
    {
      apiKey,
      signal,
    },
  )
}

async function fetchAllPages<T>(
  fetchPage: (
    offset: number,
    limit: number,
  ) => Promise<T[]>,
): Promise<T[]> {
  const results: T[] = []

  let offset = 0

  while (true) {
    const page = await fetchPage(
      offset,
      MAX_PAGE_SIZE,
    )

    results.push(
      ...page,
    )

    if (
      page.length <
      MAX_PAGE_SIZE
    ) {
      return results
    }

    offset += page.length
  }
}

export async function fetchAllEvents(
  apiKey: string | null,
  signal?: AbortSignal,
): Promise<SecurityEvent[]> {
  return fetchAllPages(
    (
      offset,
      limit,
    ) =>
      listEvents(
        apiKey,
        {
          offset,
          limit,
        },
        signal,
      ),
  )
}

export async function fetchAllAlerts(
  apiKey: string | null,
  signal?: AbortSignal,
): Promise<SecurityAlert[]> {
  return fetchAllPages(
    (
      offset,
      limit,
    ) =>
      listAlerts(
        apiKey,
        {
          offset,
          limit,
        },
        signal,
      ),
  )
}

export async function fetchSecurityOverview(
  apiKey: string | null,
  signal?: AbortSignal,
): Promise<SecurityOverview> {
  const [
    events,
    alerts,
  ] = await Promise.all([
    fetchAllEvents(
      apiKey,
      signal,
    ),

    fetchAllAlerts(
      apiKey,
      signal,
    ),
  ])

  const recentAlerts = [
    ...alerts,
  ]
    .sort(
      (left, right) =>
        Date.parse(
          right.created_at,
        ) -
        Date.parse(
          left.created_at,
        ),
    )
    .slice(
      0,
      5,
    )

  const highSeverityCount =
    alerts.filter(
      (alert) =>
        alert.severity
          .trim()
          .toLowerCase() ===
        'high',
    ).length

  const detectionRuleCount =
    new Set(
      alerts.map(
        (alert) =>
          alert.rule_id,
      ),
    ).size

  return {
    eventCount:
      events.length,

    alertCount:
      alerts.length,

    highSeverityCount,

    detectionRuleCount,

    recentAlerts,
  }
}