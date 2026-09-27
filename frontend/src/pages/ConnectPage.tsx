import {
  KeyRound,
  ShieldCheck,
} from 'lucide-react'
import {
  useState,
  type FormEvent,
} from 'react'
import {
  useNavigate,
} from 'react-router-dom'

import {
  ApiError,
  apiRequest,
} from '../api/client'
import {
  useApiKey,
} from '../auth/ApiKeyContext'

export function ConnectPage() {
  const navigate =
    useNavigate()

  const {
    connect,
  } = useApiKey()

  const [
    apiKey,
    setApiKey,
  ] = useState('')

  const [
    error,
    setError,
  ] = useState<string | null>(
    null,
  )

  const [
    loading,
    setLoading,
  ] = useState(false)

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    const normalized =
      apiKey.trim()

    if (!normalized) {
      setError(
        'Enter an API key.',
      )

      return
    }

    setLoading(true)
    setError(null)

    try {
      await apiRequest<unknown[]>(
        '/api/v1/events?limit=1',
        {
          apiKey: normalized,
        },
      )

      connect(
        normalized,
      )

      setApiKey('')

      navigate(
        '/',
        {
          replace: true,
        },
      )
    } catch (requestError) {
      if (
        requestError
        instanceof ApiError
      ) {
        if (
          requestError.status === 401 ||
          requestError.status === 403
        ) {
          setError(
            'The API key was rejected.',
          )
        } else {
          setError(
            requestError.message,
          )
        }
      } else {
        setError(
          'Unable to connect to the API.',
        )
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="connect-page">
      <section className="connect-card">
        <div className="connect-logo">
          <ShieldCheck
            size={26}
          />
        </div>

        <p className="page-kicker">
          SENTINEL AI
        </p>

        <h1>
          Connect to the SOC
        </h1>

        <p className="connect-description">
          Authenticate with an API key to
          access security events, alerts,
          investigations, and cases.
        </p>

        <form
          className="connect-form"
          onSubmit={handleSubmit}
        >
          <label
            htmlFor="api-key"
          >
            API key
          </label>

          <div className="input-with-icon">
            <KeyRound
              size={17}
            />

            <input
              id="api-key"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={apiKey}
              placeholder="Enter API key"
              onChange={(event) =>
                setApiKey(
                  event.target.value,
                )
              }
            />
          </div>

          {error && (
            <div
              className="connect-error"
              role="alert"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
          >
            {loading
              ? 'Connecting...'
              : 'Connect'}
          </button>
        </form>

        <p className="connect-note">
          Credentials are retained only for
          the current browser session.
        </p>
      </section>
    </main>
  )
}