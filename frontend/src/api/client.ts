const API_KEY_HEADER = 'X-API-Key'

export class ApiError extends Error {
  readonly status: number

  constructor(
    message: string,
    status: number,
  ) {
    super(message)

    this.name = 'ApiError'
    this.status = status
  }
}

interface RequestOptions
  extends RequestInit {
  apiKey?: string | null
}

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const {
    apiKey,
    headers,
    ...requestOptions
  } = options

  const requestHeaders = new Headers(
    headers,
  )

  requestHeaders.set(
    'Accept',
    'application/json',
  )

  if (apiKey) {
    requestHeaders.set(
      API_KEY_HEADER,
      apiKey,
    )
  }

  const response = await fetch(
    path,
    {
      ...requestOptions,
      headers: requestHeaders,
    },
  )

  if (!response.ok) {
    let message =
      `Request failed with HTTP ${response.status}`

    try {
      const body =
        await response.json()

      if (
        body &&
        typeof body.detail === 'string'
      ) {
        message = body.detail
      }
    } catch {
      
    }

    throw new ApiError(
      message,
      response.status,
    )
  }

  if (response.status === 204) {
    return undefined as T
  }

  return response.json() as Promise<T>
}