import {
  apiRequest,
} from './client'

export interface PublicAuditEvent {
  id: number
  created_at: string

  actor_role: string

  action: string
  resource_type: string

  outcome: string
}

export async function listPublicAuditEvents(
  apiKey: string | null,
  signal?: AbortSignal,
): Promise<PublicAuditEvent[]> {
  return apiRequest<
    PublicAuditEvent[]
  >(
    '/api/v1/audit/public?limit=200',
    {
      apiKey,
      signal,
    },
  )
}