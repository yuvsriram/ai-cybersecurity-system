import {
  AlertTriangle,
  BellRing,
  Database,
  RefreshCw,
  ShieldAlert,
  Waypoints,
} from 'lucide-react'
import {
  useEffect,
  useState,
} from 'react'
import {
  useNavigate,
} from 'react-router-dom'

import {
  fetchSecurityOverview,
} from '../api/security'
import type {
  SecurityOverview,
} from '../api/types'
import {
  useApiKey,
} from '../auth/ApiKeyContext'

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

export function DashboardPage() {
  const navigate =
    useNavigate()

  const {
    apiKey,
    authMode,
  } = useApiKey()

  const [
    overview,
    setOverview,
  ] =
    useState<SecurityOverview | null>(
      null,
    )

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

  const [
    refreshIndex,
    setRefreshIndex,
  ] = useState(0)

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

      fetchSecurityOverview(
        apiKey,
        controller.signal,
      )
        .then(
          (result) => {
            if (
              !controller
                .signal
                .aborted
            ) {
              setOverview(
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
                    'Unable to load '
                    + 'security overview.'
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
      refreshIndex,
    ],
  )

  const metrics = [
    {
      label:
        'Security Events',

      value:
        overview
          ? String(
              overview.eventCount,
            )
          : '—',

      detail:
        'Normalized telemetry',

      icon:
        Database,
    },
    {
      label:
        'Detected Alerts',

      value:
        overview
          ? String(
              overview.alertCount,
            )
          : '—',

      detail:
        'Rule-generated findings',

      icon:
        BellRing,
    },
    {
      label:
        'High Severity',

      value:
        overview
          ? String(
              overview
                .highSeverityCount,
            )
          : '—',

      detail:
        'Require analyst review',

      icon:
        ShieldAlert,
    },
    {
      label:
        'Detection Rules',

      value:
        overview
          ? String(
              overview
                .detectionRuleCount,
            )
          : '—',

      detail:
        'Rules represented in alerts',

      icon:
        Waypoints,
    },
  ]

  const pipeline = [
    'Telemetry',
    'Normalization',
    'Detection',
    'Alerts',
    'AI Investigation',
    'Cases',
  ]

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="page-kicker">
            SECURITY OVERVIEW
          </p>

          <h1>
            Threat Detection Dashboard
          </h1>

          <p className="page-description">
            Live telemetry and detections
            from the cybersecurity
            platform.
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

          {loading
            ? 'Loading'
            : 'Refresh'}
        </button>
      </div>

      {error && (
        <div
          className="error-banner"
          role="alert"
        >
          <AlertTriangle
            size={17}
          />

          <span>
            {error}
          </span>
        </div>
      )}

      <div className="metric-grid">
        {metrics.map(
          ({
            label,
            value,
            detail,
            icon: Icon,
          }) => (
            <article
              className="metric-card"
              key={label}
            >
              <div className="metric-icon">
                <Icon
                  size={20}
                />
              </div>

              <div className="metric-label">
                {label}
              </div>

              <div className="metric-value">
                {loading
                  ? '…'
                  : value}
              </div>

              <div className="metric-detail">
                {detail}
              </div>
            </article>
          ),
        )}
      </div>

      <div className="dashboard-grid">
        <article className="panel">
          <div className="panel-header panel-header-row">
            <div>
              <span className="panel-kicker">
                LIVE ALERTS
              </span>

              <h2>
                Recent detections
              </h2>
            </div>

            <button
              className="text-button"
              type="button"
              onClick={() =>
                navigate(
                  '/alerts',
                )
              }
            >
              View all
            </button>
          </div>

          {loading && (
            <div className="loading-state">
              Loading alerts…
            </div>
          )}

          {!loading &&
            overview &&
            overview
              .recentAlerts
              .length === 0 && (
              <div className="loading-state">
                No alerts found.
              </div>
            )}

          {!loading &&
            overview &&
            overview
              .recentAlerts
              .length > 0 && (
              <div className="recent-alert-list">
                {overview
                  .recentAlerts
                  .map(
                    (alert) => (
                      <button
                        key={
                          alert.id
                        }
                        className="recent-alert"
                        type="button"
                        onClick={() =>
                          navigate(
                            '/alerts',
                          )
                        }
                      >
                        <div>
                          <div className="recent-alert-title">
                            {
                              alert.title
                            }
                          </div>

                          <div className="recent-alert-meta">
                            {
                              alert.rule_id
                            }
                            {' · '}
                            {formatDateTime(
                              alert.created_at,
                            )}
                          </div>
                        </div>

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
                      </button>
                    ),
                  )}
              </div>
            )}
        </article>

        <article className="panel">
          <div className="panel-header">
            <div>
              <span className="panel-kicker">
                PIPELINE
              </span>

              <h2>
                Detection workflow
              </h2>
            </div>
          </div>

          <div className="pipeline">
            {pipeline.map(
              (
                stage,
                index,
              ) => (
                <div
                  className="pipeline-stage"
                  key={stage}
                >
                  <span className="pipeline-number">
                    {String(
                      index + 1,
                    ).padStart(
                      2,
                      '0',
                    )}
                  </span>

                  <span>
                    {stage}
                  </span>
                </div>
              ),
            )}
          </div>
        </article>
      </div>
    </section>
  )
}