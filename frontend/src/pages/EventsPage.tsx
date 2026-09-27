import {
  ChevronLeft,
  ChevronRight,
  Filter,
  RefreshCw,
} from 'lucide-react'
import {
  useEffect,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from 'react'

import {
  listEvents,
} from '../api/security'
import type {
  SecurityEvent,
} from '../api/types'
import {
  useApiKey,
} from '../auth/ApiKeyContext'

const PAGE_SIZE = 50

interface EventFilters {
  eventCode: string
  userName: string
}

function formatDateTime(
  value: string,
): string {
  const date =
    new Date(value)

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return value
  }

  return date.toLocaleString()
}

function shortFingerprint(
  value: string,
): string {
  if (
    value.length <= 16
  ) {
    return value
  }

  return (
    `${value.slice(
      0,
      8,
    )}…${value.slice(
      -6,
    )}`
  )
}

export function EventsPage() {
  const {
    apiKey,
    authMode,
  } = useApiKey()

  const [
    events,
    setEvents,
  ] =
    useState<SecurityEvent[]>(
      [],
    )

  const [
    selectedEvent,
    setSelectedEvent,
  ] =
    useState<SecurityEvent | null>(
      null,
    )

  const [
    eventCode,
    setEventCode,
  ] = useState('')

  const [
    userName,
    setUserName,
  ] = useState('')

  const [
    filters,
    setFilters,
  ] =
    useState<EventFilters>({
      eventCode: '',
      userName: '',
    })

  const [
    offset,
    setOffset,
  ] = useState(0)

  const [
    refreshIndex,
    setRefreshIndex,
  ] = useState(0)

  const [
    loading,
    setLoading,
  ] = useState(true)

  const [
    error,
    setError,
  ] =
    useState<string | null>(
      null,
    )

  useEffect(
    () => {
      const canRequest =
        authMode === 'demo' ||
        apiKey !== null

      if (!canRequest) {
        return
      }

      const controller =
        new AbortController()

      setLoading(true)
      setError(null)
      setSelectedEvent(null)

      listEvents(
        apiKey,
        {
          limit:
            PAGE_SIZE,

          offset,

          eventCode:
            filters.eventCode,

          userName:
            filters.userName,
        },
        controller.signal,
      )
        .then(
          (result) => {
            if (
              !controller
                .signal
                .aborted
            ) {
              setEvents(
                result,
              )
            }
          },
        )
        .catch(
          (requestError) => {
            if (
              controller
                .signal
                .aborted
            ) {
              return
            }

            setError(
              requestError
                instanceof Error
                ? requestError.message
                : (
                    'Unable to '
                    + 'load events.'
                  ),
            )
          },
        )
        .finally(
          () => {
            if (
              !controller
                .signal
                .aborted
            ) {
              setLoading(false)
            }
          },
        )

      return () => {
        controller.abort()
      }
    },
    [
      apiKey,
      authMode,
      filters,
      offset,
      refreshIndex,
    ],
  )

  function applyFilters(
    event:
      FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    setOffset(0)

    setFilters({
      eventCode:
        eventCode.trim(),

      userName:
        userName.trim(),
    })
  }

  function clearFilters() {
    setEventCode('')
    setUserName('')
    setOffset(0)

    setFilters({
      eventCode: '',
      userName: '',
    })
  }

  function selectWithKeyboard(
    keyboardEvent:
      KeyboardEvent<HTMLTableRowElement>,
    securityEvent:
      SecurityEvent,
  ) {
    if (
      keyboardEvent.key ===
        'Enter' ||
      keyboardEvent.key ===
        ' '
    ) {
      keyboardEvent.preventDefault()

      setSelectedEvent(
        securityEvent,
      )
    }
  }

  const start =
    events.length > 0
      ? offset + 1
      : 0

  const end =
    offset +
    events.length

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="page-kicker">
            TELEMETRY
          </p>

          <h1>
            Security Events
          </h1>

          <p className="page-description">
            Search and inspect normalized
            security telemetry persisted
            by the platform.
          </p>
        </div>

        <button
          className="secondary-button"
          type="button"
          disabled={loading}
          onClick={() =>
            setRefreshIndex(
              (value) =>
                value + 1,
            )
          }
        >
          <RefreshCw
            size={15}
          />

          Refresh
        </button>
      </div>

      <form
        className="filter-bar"
        onSubmit={
          applyFilters
        }
      >
        <div className="filter-heading">
          <Filter
            size={15}
          />

          Filters
        </div>

        <input
          value={eventCode}
          placeholder="Event code"
          onChange={(event) =>
            setEventCode(
              event.target.value,
            )
          }
        />

        <input
          value={userName}
          placeholder="User name"
          onChange={(event) =>
            setUserName(
              event.target.value,
            )
          }
        />

        <button
          className="primary-small-button"
          type="submit"
        >
          Apply
        </button>

        <button
          className="ghost-small-button"
          type="button"
          onClick={clearFilters}
        >
          Clear
        </button>
      </form>

      {error && (
        <div
          className="error-banner"
          role="alert"
        >
          {error}
        </div>
      )}

      <article className="panel data-panel">
        <div className="data-panel-header">
          <div>
            <span className="panel-kicker">
              EVENT STORE
            </span>

            <h2>
              Normalized events
            </h2>
          </div>

          <span className="range-label">
            {loading
              ? 'Loading…'
              : `${start}–${end}`}
          </span>
        </div>

        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Code</th>
                <th>User</th>
                <th>Host</th>
                <th>Action</th>
                <th>Outcome</th>
              </tr>
            </thead>

            <tbody>
              {!loading &&
                events.length ===
                  0 && (
                  <tr>
                    <td
                      className="empty-table"
                      colSpan={6}
                    >
                      No events matched
                      the current filters.
                    </td>
                  </tr>
                )}

              {events.map(
                (
                  securityEvent,
                ) => (
                  <tr
                    key={
                      securityEvent.id
                    }
                    className={
                      selectedEvent
                        ?.id ===
                      securityEvent.id
                        ? (
                            'data-row '
                            + 'data-row-selected'
                          )
                        : 'data-row'
                    }
                    role="button"
                    tabIndex={0}
                    onClick={() =>
                      setSelectedEvent(
                        securityEvent,
                      )
                    }
                    onKeyDown={(
                      keyboardEvent,
                    ) =>
                      selectWithKeyboard(
                        keyboardEvent,
                        securityEvent,
                      )
                    }
                  >
                    <td>
                      {formatDateTime(
                        securityEvent
                          .occurred_at,
                      )}
                    </td>

                    <td>
                      <span className="code-badge">
                        {
                          securityEvent
                            .event_code
                        }
                      </span>
                    </td>

                    <td>
                      {
                        securityEvent
                          .user_name ??
                        '—'
                      }
                    </td>

                    <td>
                      {
                        securityEvent
                          .host_name ??
                        securityEvent
                          .destination_host ??
                        '—'
                      }
                    </td>

                    <td>
                      {
                        securityEvent
                          .action
                      }
                    </td>

                    <td>
                      {
                        securityEvent
                          .outcome ??
                        'unknown'
                      }
                    </td>
                  </tr>
                ),
              )}
            </tbody>
          </table>
        </div>

        <div className="pagination-bar">
          <button
            className="ghost-small-button"
            type="button"
            disabled={
              offset === 0 ||
              loading
            }
            onClick={() =>
              setOffset(
                Math.max(
                  0,
                  offset -
                    PAGE_SIZE,
                ),
              )
            }
          >
            <ChevronLeft
              size={15}
            />

            Previous
          </button>

          <span>
            Offset {offset}
          </span>

          <button
            className="ghost-small-button"
            type="button"
            disabled={
              loading ||
              events.length <
                PAGE_SIZE
            }
            onClick={() =>
              setOffset(
                offset +
                  PAGE_SIZE,
              )
            }
          >
            Next

            <ChevronRight
              size={15}
            />
          </button>
        </div>
      </article>

      {selectedEvent && (
        <article className="panel detail-panel">
          <div className="detail-panel-heading">
            <div>
              <span className="panel-kicker">
                EVENT DETAIL
              </span>

              <h2>
                Event {
                  selectedEvent.id
                }
              </h2>
            </div>

            <span className="code-badge">
              {
                selectedEvent
                  .event_code
              }
            </span>
          </div>

          <div className="detail-grid">
            <div>
              <span>
                Category
              </span>
              <strong>
                {
                  selectedEvent
                    .category
                }
              </strong>
            </div>

            <div>
              <span>
                Action
              </span>
              <strong>
                {
                  selectedEvent
                    .action
                }
              </strong>
            </div>

            <div>
              <span>
                Outcome
              </span>
              <strong>
                {
                  selectedEvent
                    .outcome ??
                  'unknown'
                }
              </strong>
            </div>

            <div>
              <span>
                User
              </span>
              <strong>
                {
                  selectedEvent
                    .user_name ??
                  '—'
                }
              </strong>
            </div>

            <div>
              <span>
                Source IP
              </span>
              <strong>
                {
                  selectedEvent
                    .source_ip ??
                  '—'
                }
              </strong>
            </div>

            <div>
              <span>
                Destination
              </span>
              <strong>
                {
                  selectedEvent
                    .destination_host ??
                  selectedEvent
                    .destination_ip ??
                  '—'
                }
              </strong>
            </div>

            <div>
              <span>
                Provider
              </span>
              <strong>
                {
                  selectedEvent
                    .source_provider ??
                  '—'
                }
              </strong>
            </div>

            <div>
              <span>
                Fingerprint
              </span>
              <strong
                title={
                  selectedEvent
                    .event_fingerprint
                }
              >
                {shortFingerprint(
                  selectedEvent
                    .event_fingerprint,
                )}
              </strong>
            </div>
          </div>
        </article>
      )}
    </section>
  )
}