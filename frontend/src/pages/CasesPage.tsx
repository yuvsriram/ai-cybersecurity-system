import {
  AlertTriangle,
  BriefcaseBusiness,
  CheckCircle2,
  Link2,
  Plus,
  RefreshCw,
  ShieldCheck,
  X,
} from 'lucide-react'

import {
  useEffect,
  useMemo,
  useState,
} from 'react'

import {
  addAlertToCase,
  createCase,
  getCase,
  listCases,
  type CaseDetail,
  type CaseSeverity,
  type CaseStatus,
  type SecurityCase,
} from '../api/cases'

import {
  listAlerts,
} from '../api/security'

import type {
  SecurityAlert,
} from '../api/types'

import {
  useApiKey,
} from '../auth/ApiKeyContext'


const CASE_LIMIT = 200
const ALERT_LIMIT = 500


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


function severityClass(
  severity: string,
): string {
  return (
    `case-severity `
    + `case-severity-${severity}`
  )
}


function statusClass(
  status: string,
): string {
  return (
    `case-status `
    + `case-status-${status}`
  )
}


function summaryFromDetail(
  detail: CaseDetail,
): SecurityCase {
  return {
    id: detail.id,

    title: detail.title,

    summary:
      detail.summary,

    status:
      detail.status,

    severity:
      detail.severity,

    creation_source:
      detail.creation_source,

    created_at:
      detail.created_at,

    updated_at:
      detail.updated_at,

    closed_at:
      detail.closed_at,
  }
}


export function CasesPage() {
  const {
    apiKey,
    authMode,
  } = useApiKey()

  const [
    cases,
    setCases,
  ] =
    useState<SecurityCase[]>([])

  const [
    alerts,
    setAlerts,
  ] =
    useState<SecurityAlert[]>([])

  const [
    selectedCaseId,
    setSelectedCaseId,
  ] =
    useState<string | null>(
      null,
    )

  const [
    detail,
    setDetail,
  ] =
    useState<CaseDetail | null>(
      null,
    )

  const [
    statusFilter,
    setStatusFilter,
  ] =
    useState<CaseStatus | ''>(
      '',
    )

  const [
    severityFilter,
    setSeverityFilter,
  ] =
    useState<CaseSeverity | ''>(
      '',
    )

  const [
    loading,
    setLoading,
  ] = useState(true)

  const [
    detailLoading,
    setDetailLoading,
  ] = useState(false)

  const [
    refreshing,
    setRefreshing,
  ] = useState(false)

  const [
    error,
    setError,
  ] =
    useState<string | null>(
      null,
    )

  const [
    showCreate,
    setShowCreate,
  ] = useState(false)

  const [
    createTitle,
    setCreateTitle,
  ] = useState('')

  const [
    createSummary,
    setCreateSummary,
  ] = useState('')

  const [
    createSeverity,
    setCreateSeverity,
  ] =
    useState<CaseSeverity>(
      'medium',
    )

  const [
    initialAlertId,
    setInitialAlertId,
  ] = useState('')

  const [
    creating,
    setCreating,
  ] = useState(false)

  const [
    alertToAdd,
    setAlertToAdd,
  ] = useState('')

  const [
    addingAlert,
    setAddingAlert,
  ] = useState(false)


  const stats =
    useMemo(
      () => ({
        total:
          cases.length,

        open:
          cases.filter(
            (item) =>
              item.status ===
              'open',
          ).length,

        investigating:
          cases.filter(
            (item) =>
              item.status ===
              'investigating',
          ).length,

        critical:
          cases.filter(
            (item) =>
              item.severity ===
              'critical',
          ).length,
      }),
      [cases],
    )


  const availableAlerts =
    useMemo(
      () => {
        if (!detail) {
          return alerts
        }

        const linked =
          new Set(
            detail.alerts.map(
              (alert) =>
                alert.id,
            ),
          )

        return alerts.filter(
          (alert) =>
            !linked.has(
              alert.id,
            ),
        )
      },
      [
        alerts,
        detail,
      ],
    )


  async function loadCases(
    background = false,
  ) {
    if (background) {
      setRefreshing(true)
    } else {
      setLoading(true)
    }

    setError(null)

    try {
      const [
        loadedCases,
        loadedAlerts,
      ] =
        await Promise.all([
          listCases(
            apiKey,
            {
              limit:
                CASE_LIMIT,

              offset: 0,

              status:
                statusFilter,

              severity:
                severityFilter,
            },
          ),

          listAlerts(
            apiKey,
            {
              limit:
                ALERT_LIMIT,

              offset: 0,
            },
          ),
        ])

      const sortedCases =
        [...loadedCases]
          .sort(
            (
              left,
              right,
            ) =>
              Date.parse(
                right.updated_at,
              ) -
              Date.parse(
                left.updated_at,
              ),
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

      setCases(
        sortedCases,
      )

      setAlerts(
        sortedAlerts,
      )

      setSelectedCaseId(
        (current) => {
          if (
            current &&
            sortedCases.some(
              (item) =>
                item.id ===
                current,
            )
          ) {
            return current
          }

          return (
            sortedCases[0]
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
              + 'cases.'
            ),
      )
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }


  async function loadDetail(
    caseId: string,
  ) {
    setDetailLoading(true)
    setError(null)

    try {
      const loaded =
        await getCase(
          apiKey,
          caseId,
        )

      setDetail(
        loaded,
      )

      setAlertToAdd('')

    } catch (
      requestError
    ) {
      setDetail(null)

      setError(
        requestError
          instanceof Error
          ? requestError.message
          : (
              'Unable to load '
              + 'case detail.'
            ),
      )
    } finally {
      setDetailLoading(false)
    }
  }


  useEffect(
    () => {
      void loadCases()
    },
    [
      apiKey,
      authMode,
      statusFilter,
      severityFilter,
    ],
  )


  useEffect(
    () => {
      if (!selectedCaseId) {
        setDetail(null)
        return
      }

      void loadDetail(
        selectedCaseId,
      )
    },
    [
      apiKey,
      selectedCaseId,
    ],
  )


  function resetCreateForm() {
    setCreateTitle('')
    setCreateSummary('')

    setCreateSeverity(
      'medium',
    )

    setInitialAlertId('')
  }


  async function submitCreate() {
    if (
      authMode === 'demo'
    ) {
      return
    }

    const title =
      createTitle.trim()

    if (!title) {
      setError(
        'Case title is required.',
      )

      return
    }

    setCreating(true)
    setError(null)

    try {
      const created =
        await createCase(
          apiKey,
          {
            title,

            summary:
              createSummary
                .trim() ||
              null,

            severity:
              createSeverity,

            alert_ids:
              initialAlertId
                ? [
                    initialAlertId,
                  ]
                : [],
          },
        )

      setCases(
        (current) => [
          summaryFromDetail(
            created,
          ),
          ...current.filter(
            (item) =>
              item.id !==
              created.id,
          ),
        ],
      )

      setSelectedCaseId(
        created.id,
      )

      setDetail(
        created,
      )

      setShowCreate(false)

      resetCreateForm()

    } catch (
      requestError
    ) {
      setError(
        requestError
          instanceof Error
          ? requestError.message
          : (
              'Unable to create '
              + 'the case.'
            ),
      )
    } finally {
      setCreating(false)
    }
  }


  async function attachAlert() {
    if (
      authMode === 'demo'
    ) {
      return
    }

    if (
      !detail ||
      !alertToAdd
    ) {
      return
    }

    setAddingAlert(true)
    setError(null)

    try {
      const updated =
        await addAlertToCase(
          apiKey,
          detail.id,
          alertToAdd,
        )

      setDetail(
        updated,
      )

      setCases(
        (current) =>
          current.map(
            (item) =>
              item.id ===
              updated.id
                ? (
                    summaryFromDetail(
                      updated,
                    )
                  )
                : item,
          ),
      )

      setAlertToAdd('')

    } catch (
      requestError
    ) {
      setError(
        requestError
          instanceof Error
          ? requestError.message
          : (
              'Unable to attach '
              + 'the alert.'
            ),
      )
    } finally {
      setAddingAlert(false)
    }
  }


  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="page-kicker">
            ANALYST WORKFLOW
          </p>

          <h1>
            Cases
          </h1>

          <p className="page-description">
            Review security cases,
            linked detections, severity,
            and investigation context in
            one analyst workspace.
          </p>
        </div>

        <div className="case-heading-badge">
          <BriefcaseBusiness
            size={15}
          />

          Case management
        </div>
      </div>

      {authMode === 'demo' && (
        <div className="case-demo-banner">
          <ShieldCheck
            size={17}
          />

          <div>
            <strong>
              Read-only public demo
            </strong>

            <span>
              Visitors can review cases
              and linked alerts but cannot
              create or modify cases.
            </span>
          </div>
        </div>
      )}

      {error && (
        <div
          className="error-banner case-error"
          role="alert"
        >
          <AlertTriangle
            size={17}
          />

          {error}
        </div>
      )}

      <div className="case-stat-grid">
        <CaseStat
          label="Visible cases"
          value={stats.total}
        />

        <CaseStat
          label="Open"
          value={stats.open}
        />

        <CaseStat
          label="Investigating"
          value={
            stats.investigating
          }
        />

        <CaseStat
          label="Critical"
          value={stats.critical}
        />
      </div>

      <article className="panel case-controls">
        <div>
          <span className="panel-kicker">
            CASE QUEUE
          </span>

          <h2>
            Analyst cases
          </h2>
        </div>

        <div className="case-control-actions">
          <select
            value={statusFilter}
            onChange={
              (event) =>
                setStatusFilter(
                  event.target
                    .value as (
                      CaseStatus |
                      ''
                    ),
                )
            }
          >
            <option value="">
              All statuses
            </option>

            <option value="open">
              Open
            </option>

            <option value="investigating">
              Investigating
            </option>

            <option value="resolved">
              Resolved
            </option>

            <option value="closed">
              Closed
            </option>
          </select>

          <select
            value={severityFilter}
            onChange={
              (event) =>
                setSeverityFilter(
                  event.target
                    .value as (
                      CaseSeverity |
                      ''
                    ),
                )
            }
          >
            <option value="">
              All severities
            </option>

            <option value="critical">
              Critical
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

          {authMode !== 'demo' && (
            <button
              className="case-primary-button"
              type="button"
              onClick={() =>
                setShowCreate(
                  true,
                )
              }
            >
              <Plus
                size={14}
              />

              New Case
            </button>
          )}

          <button
            className="secondary-button"
            type="button"
            disabled={
              loading ||
              refreshing
            }
            onClick={() => {
              void loadCases(true)
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

      {showCreate &&
       authMode !== 'demo' && (
        <CreateCasePanel
          title={createTitle}
          summary={
            createSummary
          }
          severity={
            createSeverity
          }
          alertId={
            initialAlertId
          }
          alerts={alerts}
          creating={
            creating
          }
          onTitle={
            setCreateTitle
          }
          onSummary={
            setCreateSummary
          }
          onSeverity={
            setCreateSeverity
          }
          onAlert={
            setInitialAlertId
          }
          onSubmit={
            submitCreate
          }
          onCancel={() => {
            setShowCreate(false)

            resetCreateForm()
          }}
        />
      )}

      <div className="case-layout">
        <article className="panel case-list-panel">
          <div className="case-panel-heading">
            <div>
              <span className="panel-kicker">
                CASES
              </span>

              <h2>
                Case queue
              </h2>
            </div>

            <span className="range-label">
              {cases.length} cases
            </span>
          </div>

          {loading ? (
            <div className="case-empty">
              Loading cases...
            </div>
          ) : cases.length === 0 ? (
            <div className="case-empty">
              No cases match the current
              filters.
            </div>
          ) : (
            <div className="case-list">
              {cases.map(
                (item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={[
                      'case-row',

                      selectedCaseId ===
                      item.id
                        ? 'case-row-active'
                        : '',
                    ]
                      .filter(Boolean)
                      .join(' ')}
                    onClick={() =>
                      setSelectedCaseId(
                        item.id,
                      )
                    }
                  >
                    <div className="case-row-heading">
                      <strong>
                        {item.title}
                      </strong>

                      <span
                        className={
                          severityClass(
                            item.severity,
                          )
                        }
                      >
                        {item.severity}
                      </span>
                    </div>

                    <div className="case-row-meta">
                      <span
                        className={
                          statusClass(
                            item.status,
                          )
                        }
                      >
                        {item.status}
                      </span>

                      <span>
                        {
                          formatDateTime(
                            item.updated_at,
                          )
                        }
                      </span>
                    </div>
                  </button>
                ),
              )}
            </div>
          )}
        </article>

        <article className="panel case-detail-panel">
          {detailLoading ? (
            <div className="case-empty">
              Loading case detail...
            </div>
          ) : !detail ? (
            <div className="case-empty case-detail-empty">
              <BriefcaseBusiness
                size={30}
              />

              <strong>
                Select a case
              </strong>

              <span>
                Choose a case to inspect
                its linked detections.
              </span>
            </div>
          ) : (
            <CaseDetailView
              detail={detail}
              availableAlerts={
                availableAlerts
              }
              alertToAdd={
                alertToAdd
              }
              addingAlert={
                addingAlert
              }
              readOnly={
                authMode ===
                'demo'
              }
              onAlertToAdd={
                setAlertToAdd
              }
              onAttach={
                attachAlert
              }
            />
          )}
        </article>
      </div>
    </section>
  )
}


function CaseStat({
  label,
  value,
}: {
  label: string
  value: number
}) {
  return (
    <article className="panel case-stat-card">
      <span>
        {label}
      </span>

      <strong>
        {value}
      </strong>
    </article>
  )
}


function CreateCasePanel({
  title,
  summary,
  severity,
  alertId,
  alerts,
  creating,
  onTitle,
  onSummary,
  onSeverity,
  onAlert,
  onSubmit,
  onCancel,
}: {
  title: string
  summary: string
  severity: CaseSeverity
  alertId: string
  alerts: SecurityAlert[]
  creating: boolean
  onTitle: (value: string) => void
  onSummary: (value: string) => void
  onSeverity:
    (value: CaseSeverity) => void
  onAlert: (value: string) => void
  onSubmit: () => Promise<void>
  onCancel: () => void
}) {
  return (
    <article className="panel case-create-panel">
      <div className="case-panel-heading">
        <div>
          <span className="panel-kicker">
            NEW CASE
          </span>

          <h2>
            Create analyst case
          </h2>
        </div>

        <button
          className="case-icon-button"
          type="button"
          onClick={onCancel}
        >
          <X
            size={15}
          />
        </button>
      </div>

      <div className="case-create-grid">
        <label>
          <span>
            Title
          </span>

          <input
            value={title}
            maxLength={255}
            placeholder={
              'Credential attack investigation'
            }
            onChange={
              (event) =>
                onTitle(
                  event.target.value,
                )
            }
          />
        </label>

        <label>
          <span>
            Severity
          </span>

          <select
            value={severity}
            onChange={
              (event) =>
                onSeverity(
                  event.target
                    .value as CaseSeverity,
                )
            }
          >
            <option value="low">
              Low
            </option>

            <option value="medium">
              Medium
            </option>

            <option value="high">
              High
            </option>

            <option value="critical">
              Critical
            </option>
          </select>
        </label>

        <label>
          <span>
            Initial alert
          </span>

          <select
            value={alertId}
            onChange={
              (event) =>
                onAlert(
                  event.target.value,
                )
            }
          >
            <option value="">
              No initial alert
            </option>

            {alerts.map(
              (alert) => (
                <option
                  key={alert.id}
                  value={alert.id}
                >
                  {alert.rule_id}
                  {' — '}
                  {alert.title}
                </option>
              ),
            )}
          </select>
        </label>
      </div>

      <label className="case-summary-input">
        <span>
          Summary
        </span>

        <textarea
          value={summary}
          maxLength={5000}
          placeholder={
            'Describe the investigation scope and analyst context...'
          }
          onChange={
            (event) =>
              onSummary(
                event.target.value,
              )
          }
        />
      </label>

      <div className="case-create-actions">
        <button
          className="secondary-button"
          type="button"
          onClick={onCancel}
        >
          Cancel
        </button>

        <button
          className="case-primary-button"
          type="button"
          disabled={
            creating ||
            !title.trim()
          }
          onClick={() => {
            void onSubmit()
          }}
        >
          <Plus
            size={14}
          />

          {creating
            ? 'Creating...'
            : 'Create Case'}
        </button>
      </div>
    </article>
  )
}


function CaseDetailView({
  detail,
  availableAlerts,
  alertToAdd,
  addingAlert,
  readOnly,
  onAlertToAdd,
  onAttach,
}: {
  detail: CaseDetail
  availableAlerts: SecurityAlert[]
  alertToAdd: string
  addingAlert: boolean
  readOnly: boolean
  onAlertToAdd: (value: string) => void
  onAttach: () => Promise<void>
}) {
  return (
    <div>
      <div className="case-panel-heading">
        <div>
          <span className="panel-kicker">
            CASE DETAIL
          </span>

          <h2>
            {detail.title}
          </h2>
        </div>

        <div className="case-detail-badges">
          <span
            className={
              statusClass(
                detail.status,
              )
            }
          >
            {detail.status}
          </span>

          <span
            className={
              severityClass(
                detail.severity,
              )
            }
          >
            {detail.severity}
          </span>
        </div>
      </div>

      <div className="case-metadata-grid">
        <Metadata
          label="Case ID"
          value={
            shortId(
              detail.id,
            )
          }
        />

        <Metadata
          label="Source"
          value={
            detail
              .creation_source
          }
        />

        <Metadata
          label="Linked alerts"
          value={String(
            detail.alerts.length,
          )}
        />

        <Metadata
          label="Created"
          value={
            formatDateTime(
              detail.created_at,
            )
          }
        />

        <Metadata
          label="Updated"
          value={
            formatDateTime(
              detail.updated_at,
            )
          }
        />

        <Metadata
          label="Closed"
          value={
            formatDateTime(
              detail.closed_at,
            )
          }
        />
      </div>

      <section className="case-summary-section">
        <span>
          CASE SUMMARY
        </span>

        <p>
          {detail.summary ??
            'No analyst summary has been recorded.'}
        </p>
      </section>

      <section className="case-alert-section">
        <div className="case-section-heading">
          <div>
            <span>
              LINKED DETECTIONS
            </span>

            <strong>
              {detail.alerts.length}
            </strong>
          </div>

          {!readOnly &&
           availableAlerts.length >
             0 && (
            <div className="case-add-alert">
              <select
                value={
                  alertToAdd
                }
                onChange={
                  (event) =>
                    onAlertToAdd(
                      event.target.value,
                    )
                }
              >
                <option value="">
                  Select alert
                </option>

                {availableAlerts.map(
                  (alert) => (
                    <option
                      key={
                        alert.id
                      }
                      value={
                        alert.id
                      }
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
                type="button"
                disabled={
                  addingAlert ||
                  !alertToAdd
                }
                onClick={() => {
                  void onAttach()
                }}
              >
                <Link2
                  size={13}
                />

                {addingAlert
                  ? 'Adding...'
                  : 'Attach'}
              </button>
            </div>
          )}
        </div>

        {detail.alerts.length ===
        0 ? (
          <div className="case-alert-empty">
            No alerts are linked to
            this case.
          </div>
        ) : (
          <div className="case-alert-list">
            {detail.alerts.map(
              (alert) => (
                <div
                  className="case-alert-card"
                  key={alert.id}
                >
                  <div className="case-alert-heading">
                    <div>
                      <span className="code-badge">
                        {
                          alert.rule_id
                        }
                      </span>

                      <strong>
                        {
                          alert.title
                        }
                      </strong>
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
                  </div>

                  <p>
                    {
                      alert.description
                    }
                  </p>

                  <div className="case-alert-meta">
                    <span>
                      Evidence:
                      {' '}
                      {
                        alert
                          .evidence_event_fingerprints
                          .length
                      }
                    </span>

                    <span>
                      MITRE:
                      {' '}
                      {
                        alert
                          .mitre_techniques
                          .join(', ') ||
                        '--'
                      }
                    </span>
                  </div>
                </div>
              ),
            )}
          </div>
        )}
      </section>

      {readOnly && (
        <div className="case-readonly-note">
          <CheckCircle2
            size={15}
          />

          Case mutation controls are
          disabled in the public demo.
        </div>
      )}
    </div>
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
    <div className="case-metadata">
      <span>
        {label}
      </span>

      <strong title={value}>
        {value}
      </strong>
    </div>
  )
}