export type AuthMode =
  | 'manual'
  | 'demo'

function getAuthMode(): AuthMode {
  const rawMode =
    import.meta.env
      .VITE_AUTH_MODE
      ?.trim()
      .toLowerCase()

  if (rawMode === 'demo') {
    return 'demo'
  }

  return 'manual'
}

export const appConfig = {
  authMode: getAuthMode(),
}