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
  listAlerts,
} from '../api/security'
import type {
  SecurityAlert,
} from '../api/types'
import {
  useApiKey,
} from '../auth/ApiKeyContext'

const PAGE_SIZE = 50

interface AlertFilters {
  severity: string
  ruleId: string
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

function severityClass(
  severity: string,
): string {
  return (
    `severity-badge severity-${severity
      .trim()
      .toLowerCase()}`
  )
}

export function AlertsPage() {
  const {
    apiKey,
    authMode,
  } = useApiKey()

  const [
    alerts,
    setAlerts,
  ] =
    useState<SecurityAlert[]>(
      [],
    )

  const [
    selectedAlert,
    setSelectedAlert,
  ] =
    useState<SecurityAlert | null>(
      null,
    )

  const [
    severity,
    setSeverity,
  ] = useState('')

  const [
    ruleId,
    setRuleId,
  ] = useState('')

  const [
    filters,
    setFilters,
  ] =
    useState<AlertFilters>({
      severity: '',
      ruleId: '',
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
      setSelectedAlert(null)

      listAlerts(
        apiKey,
        {
          limit:
            PAGE_SIZE,

          offset,

          severity:
            filters.severity,

          ruleId:
            filters.ruleId,
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
              setAlerts(
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
                    + 'load alerts.'
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
      severity:
        severity.trim(),

      ruleId:
        ruleId.trim(),
    })
  }

  function clearFilters() {
    setSeverity('')
    setRuleId('')
    setOffset(0)

    setFilters({
      severity: '',
      ruleId: '',
    })
  }

  function selectWithKeyboard(
    keyboardEvent:
      KeyboardEvent<HTMLTableRowElement>,
    alert:
      SecurityAlert,
  ) {
    if (
      keyboardEvent.key ===
        'Enter' ||
      keyboardEvent.key ===
        ' '
    ) {
      keyboardEvent.preventDefault()

      setSelectedAlert(
        alert,
      )
    }
  }

  const start =
    alerts.length > 0
      ? offset + 1
      : 0

  const end =
    offset +
    alerts.length

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="page-kicker">
            DETECTION
          </p>

          <h1>
            Security Alerts
          </h1>

          <p className="page-description">
            Review rule detections,
            severity, evidence references,
            and MITRE ATT&CK mappings.
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

        <select
          value={severity}
          onChange={(event) =>
            setSeverity(
              event.target.value,
            )
          }
        >
          <option value="">
            All severities
          </option>

          <option value="high">
            High
          </option>

          <option value="medium">
            Medium
          </option>

          <option value="low">
            Low
          </option>
        </select>

        <input
          value={ruleId}
          placeholder="Rule ID"
          onChange={(event) =>
            setRuleId(
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
              DETECTIONS
            </span>

            <h2>
              Alert queue
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
                <th>Severity</th>
                <th>Rule</th>
                <th>Detection</th>
                <th>User</th>
                <th>Source</th>
                <th>Created</th>
              </tr>
            </thead>

            <tbody>
              {!loading &&
                alerts.length ===
                  0 && (
                  <tr>
                    <td
                      className="empty-table"
                      colSpan={6}
                    >
                      No alerts matched
                      the current filters.
                    </td>
                  </tr>
                )}

              {alerts.map(
                (alert) => (
                  <tr
                    key={alert.id}
                    className={
                      selectedAlert
                        ?.id ===
                      alert.id
                        ? (
                            'data-row '
                            + 'data-row-selected'
                          )
                        : 'data-row'
                    }
                    role="button"
                    tabIndex={0}
                    onClick={() =>
                      setSelectedAlert(
                        alert,
                      )
                    }
                    onKeyDown={(
                      keyboardEvent,
                    ) =>
                      selectWithKeyboard(
                        keyboardEvent,
                        alert,
                      )
                    }
                  >
                    <td>
                      <span
                        className={
                          severityClass(
                            alert.severity,
                          )
                        }
                      >
                        {
                          alert.severity
                        }
                      </span>
                    </td>

                    <td>
                      <span className="code-badge">
                        {
                          alert.rule_id
                        }
                      </span>
                    </td>

                    <td>
                      {alert.title}
                    </td>

                    <td>
                      {
                        alert
                          .user_name ??
                        '—'
                      }
                    </td>

                    <td>
                      {
                        alert
                          .source_ip ??
                        alert
                          .source_host ??
                        '—'
                      }
                    </td>

                    <td>
                      {formatDateTime(
                        alert.created_at,
                      )}
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
              alerts.length <
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

      {selectedAlert && (
        <article className="panel detail-panel">
          <div className="detail-panel-heading">
            <div>
              <span className="panel-kicker">
                ALERT DETAIL
              </span>

              <h2>
                {
                  selectedAlert
                    .title
                }
              </h2>
            </div>

            <span
              className={
                severityClass(
                  selectedAlert
                    .severity,
                )
              }
            >
              {
                selectedAlert
                  .severity
              }
            </span>
          </div>

          <p className="detail-description">
            {
              selectedAlert
                .description
            }
          </p>

          <div className="detail-grid">
            <div>
              <span>Rule</span>

              <strong>
                {
                  selectedAlert
                    .rule_id
                }
                {' v'}
                {
                  selectedAlert
                    .rule_version
                }
              </strong>
            </div>

            <div>
              <span>User</span>

              <strong>
                {
                  selectedAlert
                    .user_name ??
                  '—'
                }
              </strong>
            </div>

            <div>
              <span>Source</span>

              <strong>
                {
                  selectedAlert
                    .source_ip ??
                  selectedAlert
                    .source_host ??
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
                  selectedAlert
                    .destination_host ??
                  '—'
                }
              </strong>
            </div>

            <div>
              <span>
                First seen
              </span>

              <strong>
                {formatDateTime(
                  selectedAlert
                    .first_seen_at,
                )}
              </strong>
            </div>

            <div>
              <span>
                Last seen
              </span>

              <strong>
                {formatDateTime(
                  selectedAlert
                    .last_seen_at,
                )}
              </strong>
            </div>

            <div>
              <span>
                Evidence events
              </span>

              <strong>
                {
                  selectedAlert
                    .evidence_event_fingerprints
                    .length
                }
              </strong>
            </div>

            <div>
              <span>
                MITRE ATT&CK
              </span>

              <strong>
                {selectedAlert
                  .mitre_techniques
                  .length > 0
                  ? (
                      selectedAlert
                        .mitre_techniques
                        .join(', ')
                    )
                  : '—'}
              </strong>
            </div>
          </div>
        </article>
      )}
    </section>
  )
}