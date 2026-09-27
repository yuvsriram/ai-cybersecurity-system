import {
  createContext,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'

import {
  appConfig,
  type AuthMode,
} from '../config/app'

const SESSION_KEY =
  'cybersec-api-key'

interface ApiKeyContextValue {
  apiKey: string | null
  authMode: AuthMode
  connected: boolean

  connect: (
    apiKey: string,
  ) => void

  disconnect: () => void
}

const ApiKeyContext =
  createContext<ApiKeyContextValue | null>(
    null,
  )

function loadSessionApiKey():
  string | null {
  if (
    appConfig.authMode ===
    'demo'
  ) {
    return null
  }

  const value =
    sessionStorage.getItem(
      SESSION_KEY,
    )

  if (!value) {
    return null
  }

  const normalized =
    value.trim()

  return normalized || null
}

export function ApiKeyProvider({
  children,
}: {
  children: ReactNode
}) {
  const [
    apiKey,
    setApiKey,
  ] = useState<string | null>(
    loadSessionApiKey,
  )

  const value =
    useMemo<ApiKeyContextValue>(
      () => ({
        apiKey,

        authMode:
          appConfig.authMode,

        connected:
          appConfig.authMode ===
            'demo' ||
          apiKey !== null,

        connect(
          newApiKey: string,
        ) {
          if (
            appConfig.authMode ===
            'demo'
          ) {
            return
          }

          const normalized =
            newApiKey.trim()

          if (!normalized) {
            throw new Error(
              'API key must not be empty',
            )
          }

          sessionStorage.setItem(
            SESSION_KEY,
            normalized,
          )

          setApiKey(
            normalized,
          )
        },

        disconnect() {
          if (
            appConfig.authMode ===
            'demo'
          ) {
            return
          }

          sessionStorage.removeItem(
            SESSION_KEY,
          )

          setApiKey(
            null,
          )
        },
      }),
      [apiKey],
    )

  return (
    <ApiKeyContext.Provider
      value={value}
    >
      {children}
    </ApiKeyContext.Provider>
  )
}

export function useApiKey():
  ApiKeyContextValue {
  const context =
    useContext(ApiKeyContext)

  if (!context) {
    throw new Error(
      'useApiKey must be used inside ApiKeyProvider',
    )
  }

  return context
}