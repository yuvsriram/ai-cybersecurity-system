import {
  apiRequest,
} from './client'

export interface LivenessResponse {
  status: string
}

export interface ReadinessResponse {
  status: string
  database: string
}

export async function getLiveness(
  signal?: AbortSignal,
): Promise<LivenessResponse> {
  return apiRequest<
    LivenessResponse
  >(
    '/health/live',
    {
      apiKey: null,
      signal,
    },
  )
}

export async function getReadiness(
  signal?: AbortSignal,
): Promise<ReadinessResponse> {
  return apiRequest<
    ReadinessResponse
  >(
    '/health/ready',
    {
      apiKey: null,
      signal,
    },
  )
}