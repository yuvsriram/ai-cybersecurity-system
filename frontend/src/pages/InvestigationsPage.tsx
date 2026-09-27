import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  Clock3,
  Play,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  XCircle,
} from 'lucide-react'

import {
  useEffect,
  useMemo,
  useState,
} from 'react'

import {
  createInvestigationRun,
  getInvestigationRun,
  listInvestigationRuns,
  type InvestigationRun,
  type InvestigationRunStatus,
} from '../api/investigations'

import {
  listAlerts,
} from '../api/security'

import type {
  InvestigationEvidenceSummary,
  InvestigationResult,
  SecurityAlert,
} from '../api/types'

import {
  useApiKey,
} from '../auth/ApiKeyContext'

const ALERT_LIMIT = 50

function formatDateTime(
  value: string | null,
): string {
  if (!value) {
    return '--'
  }

  const parsed =
    new Date(value)

  if (
    Number.isNaN(
      parsed.getTime(),
    )
  ) {
    return value
  }

  return parsed.toLocaleString()
}

function formatDuration(
  seconds: number,
): string {
  if (seconds < 60) {
    return `${seconds.toFixed(0)} sec`
  }

  if (seconds < 3600) {
    return `${(
      seconds / 60
    ).toFixed(1)} min`
  }

  return `${(
    seconds / 3600
  ).toFixed(1)} hr`
}

function shortId(
  value: string,
): string {
  if (value.length <= 18) {
    return value
  }

  return (
    `${value.slice(
      0,
      8,
    )}...${value.slice(
      -6,
    )}`
  )
}

function statusClass(
  status: InvestigationRunStatus,
): string {
  return (
    `investigation-status `
    + `investigation-status-${status}`
  )
}

function StatusIcon({
  status,
}: {
  status: InvestigationRunStatus
}) {
  if (status === 'completed') {
    return (
      <CheckCircle2
        size={14}
      />
    )
  }

  if (status === 'failed') {
    return (
      <XCircle
        size={14}
      />
    )
  }

  return (
    <Clock3
      size={14}
    />
  )
}

function updateRun(
  runs: InvestigationRun[],
  updated: InvestigationRun,
): InvestigationRun[] {
  const exists =
    runs.some(
      (run) =>
        run.id === updated.id,
    )

  const next =
    exists
      ? runs.map(
          (run) =>
            run.id === updated.id
              ? updated
              : run,
        )
      : [
          updated,
          ...runs,
        ]

  return next.sort(
    (left, right) =>
      Date.parse(
        right.created_at,
      ) -
      Date.parse(
        left.created_at,
      ),
  )
}

export function InvestigationsPage() {
  const {
    apiKey,
    authMode,
  } = useApiKey()

  const [
    alerts,
    setAlerts,
  ] = useState<SecurityAlert[]>([])

  const [
    runs,
    setRuns,
  ] =
    useState<InvestigationRun[]>([])

  const [
    selectedRunId,
    setSelectedRunId,
  ] =
    useState<string | null>(
      null,
    )

  const [
    selectedAlertId,
    setSelectedAlertId,
  ] =
    useState<string>('')

  const [
    loading,
    setLoading,
  ] = useState(true)

  const [
    refreshing,
    setRefreshing,
  ] = useState(false)

  const [
    queueing,
    setQueueing,
  ] = useState(false)

  const [
    error,
    setError,
  ] =
    useState<string | null>(
      null,
    )

  const selectedRun =
    useMemo(
      () =>
        runs.find(
          (run) =>
            run.id ===
            selectedRunId,
        ) ?? null,
      [
        runs,
        selectedRunId,
      ],
    )

  const alertsById =
    useMemo(
      () =>
        new Map(
          alerts.map(
            (alert) => [
              alert.id,
              alert,
            ],
          ),
        ),
      [alerts],
    )

  const stats =
    useMemo(
      () => ({
        total: runs.length,

        completed:
          runs.filter(
            (run) =>
              run.status ===
              'completed',
          ).length,

        active:
          runs.filter(
            (run) =>
              run.status ===
                'queued' ||
              run.status ===
                'running',
          ).length,

        failed:
          runs.filter(
            (run) =>
              run.status ===
              'failed',
          ).length,
      }),
      [runs],
    )

  async function loadData(
    background = false,
  ) {
    if (background) {
      setRefreshing(true)
    } else {
      setLoading(true)
    }

    setError(null)

    try {
      const loadedAlerts =
        await listAlerts(
          apiKey,
          {
            limit:
              ALERT_LIMIT,
            offset: 0,
          },
        )

      const sortedAlerts =
        [...loadedAlerts]
          .sort(
            (
              left,
              right,
            ) =>
              Date.parse(
                right.created_at,
              ) -
              Date.parse(
                left.created_at,
              ),
          )

      const runGroups =
        await Promise.all(
          sortedAlerts.map(
            (alert) =>
              listInvestigationRuns(
                apiKey,
                alert.id,
              ),
          ),
        )

      const loadedRuns =
        runGroups
          .flat()
          .sort(
            (
              left,
              right,
            ) =>
              Date.parse(
                right.created_at,
              ) -
              Date.parse(
                left.created_at,
              ),
          )

      setAlerts(
        sortedAlerts,
      )

      setRuns(
        loadedRuns,
      )

      setSelectedAlertId(
        (current) =>
          current &&
          sortedAlerts.some(
            (alert) =>
              alert.id === current,
          )
            ? current
            : (
                sortedAlerts[0]
                  ?.id ?? ''
              ),
      )

      setSelectedRunId(
        (current) => {
          if (
            current &&
            loadedRuns.some(
              (run) =>
                run.id === current,
            )
          ) {
            return current
          }

          return (
            loadedRuns[0]
              ?.id ?? null
          )
        },
      )
    } catch (
      requestError
    ) {
      setError(
        requestError
          instanceof Error
          ? requestError.message
          : (
              'Unable to load '
              + 'investigation history.'
            ),
      )
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(
    () => {
      void loadData()
    },
    [
      apiKey,
      authMode,
    ],
  )

  useEffect(
    () => {
      if (!selectedRun) {
        return
      }

      if (
        selectedRun.status !==
          'queued' &&
        selectedRun.status !==
          'running'
      ) {
        return
      }

      const timer =
        window.setTimeout(
          () => {
            void (
              async () => {
                try {
                  const updated =
                    await getInvestigationRun(
                      apiKey,
                      selectedRun
                        .alert_id,
                      selectedRun.id,
                    )

                  setRuns(
                    (current) =>
                      updateRun(
                        current,
                        updated,
                      ),
                  )
                } catch (
                  requestError
                ) {
                  setError(
                    requestError
                      instanceof Error
                      ? requestError
                          .message
                      : (
                          'Unable to refresh '
                          + 'investigation status.'
                        ),
                  )
                }
              }
            )()
          },
          2500,
        )

      return () => {
        window.clearTimeout(
          timer,
        )
      }
    },
    [
      apiKey,
      selectedRun,
    ],
  )

  async function queueInvestigation() {
    if (
      authMode === 'demo'
    ) {
      return
    }

    if (!selectedAlertId) {
      setError(
        'Select an alert before queuing an investigation.',
      )

      return
    }

    setQueueing(true)
    setError(null)

    try {
      const run =
        await createInvestigationRun(
          apiKey,
          selectedAlertId,
        )

      setRuns(
        (current) =>
          updateRun(
            current,
            run,
          ),
      )

      setSelectedRunId(
        run.id,
      )
    } catch (
      requestError
    ) {
      setError(
        requestError
          instanceof Error
          ? requestError.message
          : (
              'Unable to queue '
              + 'the investigation.'
            ),
      )
    } finally {
      setQueueing(false)
    }
  }

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="page-kicker">
            AI OPERATIONS
          </p>

          <h1>
            AI Investigations
          </h1>

          <p className="page-description">
            Review persisted,
            evidence-grounded AI
            investigation runs and their
            analyst-focused findings.
          </p>
        </div>

        <div className="investigation-heading-badge">
          <ShieldCheck
            size={15}
          />

          Grounded output
        </div>
      </div>

      {authMode === 'demo' && (
        <div className="investigation-demo-banner">
          <ShieldCheck
            size={17}
          />

          <div>
            <strong>
              Read-only public demo
            </strong>

            <span>
              Investigation history is
              visible, but public visitors
              cannot queue persistent AI
              jobs.
            </span>
          </div>
        </div>
      )}

      {error && (
        <div
          className="error-banner investigation-error"
          role="alert"
        >
          <AlertTriangle
            size={17}
          />

          {error}
        </div>
      )}

      <div className="investigation-stat-grid">
        <StatCard
          label="Total runs"
          value={stats.total}
        />

        <StatCard
          label="Completed"
          value={stats.completed}
        />

        <StatCard
          label="Active"
          value={stats.active}
        />

        <StatCard
          label="Failed"
          value={stats.failed}
        />
      </div>

      <article className="panel investigation-controls">
        <div>
          <span className="panel-kicker">
            OPERATIONS
          </span>

          <h2>
            Investigation history
          </h2>
        </div>

        <div className="investigation-control-actions">
          {authMode !== 'demo' && (
            <>
              <select
                value={
                  selectedAlertId
                }
                disabled={
                  alerts.length === 0
                }
                onChange={
                  (event) =>
                    setSelectedAlertId(
                      event.target.value,
                    )
                }
              >
                {alerts.map(
                  (alert) => (
                    <option
                      key={alert.id}
                      value={alert.id}
                    >
                      {
                        alert.rule_id
                      }
                      {' — '}
                      {
                        alert.title
                      }
                    </option>
                  ),
                )}
              </select>

              <button
                className="investigation-primary-button"
                type="button"
                disabled={
                  queueing ||
                  !selectedAlertId
                }
                onClick={() => {
                  void queueInvestigation()
                }}
              >
                <Play
                  size={14}
                />

                {queueing
                  ? 'Queueing...'
                  : 'Queue Investigation'}
              </button>
            </>
          )}

          <button
            className="secondary-button"
            type="button"
            disabled={
              loading ||
              refreshing
            }
            onClick={() => {
              void loadData(true)
            }}
          >
            <RefreshCw
              size={14}
            />

            {refreshing
              ? 'Refreshing...'
              : 'Refresh'}
          </button>
        </div>
      </article>

      <div className="investigation-layout">
        <article className="panel investigation-list-panel">
          <div className="investigation-panel-heading">
            <div>
              <span className="panel-kicker">
                RUNS
              </span>

              <h2>
                Recent investigations
              </h2>
            </div>

            <span className="range-label">
              {runs.length} runs
            </span>
          </div>

          {loading ? (
            <div className="investigation-empty">
              Loading investigation
              history...
            </div>
          ) : runs.length === 0 ? (
            <div className="investigation-empty">
              No persisted investigation
              runs are available yet.
            </div>
          ) : (
            <div className="investigation-run-list">
              {runs.map(
                (run) => {
                  const alert =
                    alertsById.get(
                      run.alert_id,
                    )

                  return (
                    <button
                      key={run.id}
                      type="button"
                      className={[
                        'investigation-run-row',

                        selectedRunId ===
                        run.id
                          ? (
                              'investigation-run-row-active'
                            )
                          : '',
                      ]
                        .filter(Boolean)
                        .join(' ')}
                      onClick={() =>
                        setSelectedRunId(
                          run.id,
                        )
                      }
                    >
                      <div className="investigation-run-top">
                        <div>
                          <span className="code-badge">
                            {
                              alert
                                ?.rule_id ??
                              'ALERT'
                            }
                          </span>

                          <strong>
                            {
                              alert
                                ?.title ??
                              shortId(
                                run.alert_id,
                              )
                            }
                          </strong>
                        </div>

                        <span
                          className={
                            statusClass(
                              run.status,
                            )
                          }
                        >
                          <StatusIcon
                            status={
                              run.status
                            }
                          />

                          {run.status}
                        </span>
                      </div>

                      <div className="investigation-run-meta">
                        <span>
                          {run.model}
                        </span>

                        <span>
                          {formatDateTime(
                            run.created_at,
                          )}
                        </span>
                      </div>
                    </button>
                  )
                },
              )}
            </div>
          )}
        </article>

        <article className="panel investigation-detail-panel">
          {!selectedRun ? (
            <div className="investigation-empty investigation-detail-empty">
              <Bot
                size={30}
              />

              <strong>
                Select an investigation
              </strong>

              <span>
                Choose a run to inspect
                its grounded AI result.
              </span>
            </div>
          ) : (
            <InvestigationDetail
              run={selectedRun}
              alert={
                alertsById.get(
                  selectedRun
                    .alert_id,
                ) ?? null
              }
            />
          )}
        </article>
      </div>
    </section>
  )
}

function StatCard({
  label,
  value,
}: {
  label: string
  value: number
}) {
  return (
    <article className="panel investigation-stat-card">
      <span>
        {label}
      </span>

      <strong>
        {value}
      </strong>
    </article>
  )
}

function InvestigationDetail({
  run,
  alert,
}: {
  run: InvestigationRun
  alert: SecurityAlert | null
}) {
  return (
    <div>
      <div className="investigation-panel-heading">
        <div>
          <span className="panel-kicker">
            INVESTIGATION
          </span>

          <h2>
            {alert?.title ??
              'Investigation detail'}
          </h2>
        </div>

        <span
          className={
            statusClass(
              run.status,
            )
          }
        >
          <StatusIcon
            status={run.status}
          />

          {run.status}
        </span>
      </div>

      <div className="investigation-metadata-grid">
        <Metadata
          label="Rule"
          value={
            alert?.rule_id ??
            '--'
          }
        />

        <Metadata
          label="Severity"
          value={
            alert?.severity ??
            '--'
          }
        />

        <Metadata
          label="Provider"
          value={run.provider}
        />

        <Metadata
          label="Model"
          value={run.model}
        />

        <Metadata
          label="Prompt"
          value={
            `v${run.prompt_version}`
          }
        />

        <Metadata
          label="Run ID"
          value={
            shortId(run.id)
          }
        />
      </div>

      {run.status === 'queued' && (
        <div className="investigation-state-card">
          <Clock3
            size={19}
          />

          <div>
            <strong>
              Investigation queued
            </strong>

            <span>
              Waiting for the background
              worker to claim this run.
            </span>
          </div>
        </div>
      )}

      {run.status === 'running' && (
        <div className="investigation-state-card">
          <Sparkles
            size={19}
          />

          <div>
            <strong>
              Investigation running
            </strong>

            <span>
              The worker is processing the
              evidence package. Status will
              refresh automatically.
            </span>
          </div>
        </div>
      )}

      {run.status === 'failed' && (
        <div className="investigation-failed-card">
          <XCircle
            size={19}
          />

          <div>
            <strong>
              Investigation failed
            </strong>

            <span>
              {run.error_message ??
                'No additional failure detail was returned.'}
            </span>
          </div>
        </div>
      )}

      {run.result && (
        <InvestigationResultView
          result={run.result}
        />
      )}

      <div className="investigation-timeline">
        <Metadata
          label="Created"
          value={formatDateTime(
            run.created_at,
          )}
        />

        <Metadata
          label="Started"
          value={formatDateTime(
            run.started_at,
          )}
        />

        <Metadata
          label="Completed"
          value={formatDateTime(
            run.completed_at,
          )}
        />
      </div>
    </div>
  )
}

function InvestigationResultView({
  result,
}: {
  result: InvestigationResult
}) {
  return (
    <div className="investigation-result">
      <section className="investigation-ai-summary">
        <div className="investigation-section-heading">
          <span>
            AI SUMMARY
          </span>

          <div>
            Outcome:
            {' '}
            <strong>
              {
                result
                  .authentication_outcome
              }
            </strong>
          </div>
        </div>

        <p>
          {result.summary}
        </p>
      </section>

      <div className="investigation-two-column">
        <TextList
          title="Observed behavior"
          items={
            result.observed_behavior
          }
        />

        <TextList
          title="Uncertainties"
          items={
            result.uncertainties
          }
        />
      </div>

      <section className="investigation-section">
        <div className="investigation-section-heading">
          <span>
            EVIDENCE-BACKED FINDINGS
          </span>
        </div>

        {result
          .evidence_findings
          .length === 0 ? (
            <div className="investigation-empty-small">
              No evidence findings
              returned.
            </div>
          ) : (
            <div className="investigation-findings">
              {result
                .evidence_findings
                .map(
                  (
                    finding,
                    index,
                  ) => (
                    <div
                      key={
                        `${index}-${finding.observation}`
                      }
                    >
                      <p>
                        {
                          finding
                            .observation
                        }
                      </p>

                      <div>
                        {finding
                          .event_fingerprints
                          .map(
                            (
                              fingerprint,
                            ) => (
                              <code
                                key={
                                  fingerprint
                                }
                              >
                                {shortId(
                                  fingerprint,
                                )}
                              </code>
                            ),
                          )}
                      </div>
                    </div>
                  ),
                )}
            </div>
          )}
      </section>

      <TextList
        title="Recommended analyst actions"
        items={
          result
            .recommended_next_steps
        }
        ordered
      />

      <EvidenceSummaryView
        summary={
          result.evidence_summary
        }
      />
    </div>
  )
}

function TextList({
  title,
  items,
  ordered = false,
}: {
  title: string
  items: string[]
  ordered?: boolean
}) {
  const content =
    items.length === 0 ? (
      <div className="investigation-empty-small">
        None returned.
      </div>
    ) : ordered ? (
      <ol className="investigation-text-list">
        {items.map(
          (
            item,
            index,
          ) => (
            <li
              key={
                `${index}-${item}`
              }
            >
              {item}
            </li>
          ),
        )}
      </ol>
    ) : (
      <ul className="investigation-text-list">
        {items.map(
          (
            item,
            index,
          ) => (
            <li
              key={
                `${index}-${item}`
              }
            >
              {item}
            </li>
          ),
        )}
      </ul>
    )

  return (
    <section className="investigation-section">
      <div className="investigation-section-heading">
        <span>
          {title}
        </span>
      </div>

      {content}
    </section>
  )
}

function EvidenceSummaryView({
  summary,
}: {
  summary:
    InvestigationEvidenceSummary
}) {
  return (
    <section className="investigation-grounding">
      <div className="investigation-section-heading">
        <span>
          DETERMINISTIC EVIDENCE SUMMARY
        </span>

        <div className="investigation-grounded-label">
          <ShieldCheck
            size={13}
          />

          Application calculated
        </div>
      </div>

      <div className="investigation-grounding-grid">
        <Metadata
          label="Events"
          value={String(
            summary.event_count,
          )}
        />

        <Metadata
          label="Unique users"
          value={String(
            summary.unique_user_count,
          )}
        />

        <Metadata
          label="Duration"
          value={formatDuration(
            summary.duration_seconds,
          )}
        />

        <Metadata
          label="Unknown outcomes"
          value={String(
            summary
              .unknown_outcome_count,
          )}
        />

        <Metadata
          label="Event codes"
          value={
            summary
              .event_codes
              .join(', ') ||
            '--'
          }
        />

        <Metadata
          label="Source hosts"
          value={
            summary
              .source_hosts
              .join(', ') ||
            '--'
          }
        />

        <Metadata
          label="Destination hosts"
          value={
            summary
              .destination_hosts
              .join(', ') ||
            '--'
          }
        />

        <Metadata
          label="First seen"
          value={formatDateTime(
            summary.first_seen_at,
          )}
        />
      </div>
    </section>
  )
}

function Metadata({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="investigation-metadata">
      <span>
        {label}
      </span>

      <strong title={value}>
        {value}
      </strong>
    </div>
  )
}