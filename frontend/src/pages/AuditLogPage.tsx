import {
  FileClock,
  Filter,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react'

import {
  useEffect,
  useMemo,
  useState,
} from 'react'

import {
  listPublicAuditEvents,
  type PublicAuditEvent,
} from '../api/audit'

import {
  useApiKey,
} from '../auth/ApiKeyContext'


function formatDateTime(
  value: string,
): string {
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


function outcomeClass(
  outcome: string,
): string {
  return (
    `audit-outcome `
    + `audit-outcome-${outcome
      .trim()
      .toLowerCase()}`
  )
}


export function AuditLogPage() {
  const {
    apiKey,
  } = useApiKey()

  const [
    events,
    setEvents,
  ] =
    useState<PublicAuditEvent[]>([])

  const [
    selectedId,
    setSelectedId,
  ] =
    useState<number | null>(
      null,
    )

  const [
    actionFilter,
    setActionFilter,
  ] = useState('')

  const [
    resourceFilter,
    setResourceFilter,
  ] = useState('')

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


  async function loadEvents() {
    setLoading(true)
    setError(null)

    try {
      const loaded =
        await listPublicAuditEvents(
          apiKey,
        )

      setEvents(
        loaded,
      )

      setSelectedId(
        (current) => {
          if (
            current !== null &&
            loaded.some(
              (event) =>
                event.id === current,
            )
          ) {
            return current
          }

          return (
            loaded[0]?.id ??
            null
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
              + 'audit activity.'
            ),
      )
    } finally {
      setLoading(false)
    }
  }


  useEffect(
    () => {
      void loadEvents()
    },
    [apiKey],
  )


  const actions =
    useMemo(
      () =>
        Array.from(
          new Set(
            events.map(
              (event) =>
                event.action,
            ),
          ),
        ).sort(),
      [events],
    )


  const resources =
    useMemo(
      () =>
        Array.from(
          new Set(
            events.map(
              (event) =>
                event.resource_type,
            ),
          ),
        ).sort(),
      [events],
    )


  const filteredEvents =
    useMemo(
      () =>
        events.filter(
          (event) =>
            (
              !actionFilter ||
              event.action ===
                actionFilter
            ) &&
            (
              !resourceFilter ||
              event.resource_type ===
                resourceFilter
            ),
        ),
      [
        events,
        actionFilter,
        resourceFilter,
      ],
    )


  const selected =
    useMemo(
      () =>
        filteredEvents.find(
          (event) =>
            event.id ===
            selectedId,
        ) ??
        filteredEvents[0] ??
        null,
      [
        filteredEvents,
        selectedId,
      ],
    )


  const successful =
    events.filter(
      (event) =>
        event.outcome
          .toLowerCase() ===
        'success',
    ).length


  const failed =
    events.length -
    successful


  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="page-kicker">
            SECURITY GOVERNANCE
          </p>

          <h1>
            Audit Log
          </h1>

          <p className="page-description">
            Review sanitized
            security-sensitive platform
            activity while preserving
            privileged audit details.
          </p>
        </div>

        <div className="audit-heading-badge">
          <FileClock
            size={15}
          />

          Immutable activity trail
        </div>
      </div>

      <div className="audit-security-banner">
        <ShieldCheck
          size={17}
        />

        <div>
          <strong>
            Sanitized viewer stream
          </strong>

          <span>
            Actor names, resource IDs,
            detailed messages, and audit
            attributes remain restricted
            to administrators.
          </span>
        </div>
      </div>

      {error && (
        <div
          className="error-banner audit-error"
          role="alert"
        >
          {error}
        </div>
      )}

      <div className="audit-stat-grid">
        <AuditStat
          label="Recent events"
          value={events.length}
        />

        <AuditStat
          label="Successful"
          value={successful}
        />

        <AuditStat
          label="Non-success"
          value={failed}
        />

        <AuditStat
          label="Action types"
          value={actions.length}
        />
      </div>

      <article className="panel audit-controls">
        <div>
          <span className="panel-kicker">
            ACTIVITY
          </span>

          <h2>
            Security audit stream
          </h2>
        </div>

        <div className="audit-filter-controls">
          <Filter
            size={14}
          />

          <select
            value={actionFilter}
            onChange={
              (event) =>
                setActionFilter(
                  event.target.value,
                )
            }
          >
            <option value="">
              All actions
            </option>

            {actions.map(
              (action) => (
                <option
                  key={action}
                  value={action}
                >
                  {action}
                </option>
              ),
            )}
          </select>

          <select
            value={resourceFilter}
            onChange={
              (event) =>
                setResourceFilter(
                  event.target.value,
                )
            }
          >
            <option value="">
              All resources
            </option>

            {resources.map(
              (resource) => (
                <option
                  key={resource}
                  value={resource}
                >
                  {resource}
                </option>
              ),
            )}
          </select>

          <button
            className="secondary-button"
            type="button"
            disabled={loading}
            onClick={() => {
              void loadEvents()
            }}
          >
            <RefreshCw
              size={14}
            />

            Refresh
          </button>
        </div>
      </article>

      <div className="audit-layout">
        <article className="panel audit-list-panel">
          <div className="audit-panel-heading">
            <div>
              <span className="panel-kicker">
                EVENTS
              </span>

              <h2>
                Recent activity
              </h2>
            </div>

            <span className="range-label">
              {
                filteredEvents.length
              } events
            </span>
          </div>

          {loading ? (
            <div className="audit-empty">
              Loading audit events...
            </div>
          ) : filteredEvents.length ===
            0 ? (
              <div className="audit-empty">
                No audit events match
                the selected filters.
              </div>
            ) : (
              <div className="audit-event-list">
                {filteredEvents.map(
                  (event) => (
                    <button
                      key={event.id}
                      type="button"
                      className={[
                        'audit-event-row',

                        selected?.id ===
                        event.id
                          ? 'audit-event-row-active'
                          : '',
                      ]
                        .filter(Boolean)
                        .join(' ')}
                      onClick={() =>
                        setSelectedId(
                          event.id,
                        )
                      }
                    >
                      <div>
                        <strong>
                          {event.action}
                        </strong>

                        <span
                          className={
                            outcomeClass(
                              event.outcome,
                            )
                          }
                        >
                          {event.outcome}
                        </span>
                      </div>

                      <span>
                        {
                          event.resource_type
                        }
                        {' · '}
                        {
                          event.actor_role
                        }
                      </span>

                      <time>
                        {
                          formatDateTime(
                            event.created_at,
                          )
                        }
                      </time>
                    </button>
                  ),
                )}
              </div>
            )}
        </article>

        <article className="panel audit-detail-panel">
          {!selected ? (
            <div className="audit-empty">
              Select an audit event.
            </div>
          ) : (
            <>
              <div className="audit-panel-heading">
                <div>
                  <span className="panel-kicker">
                    EVENT DETAIL
                  </span>

                  <h2>
                    {selected.action}
                  </h2>
                </div>

                <span
                  className={
                    outcomeClass(
                      selected.outcome,
                    )
                  }
                >
                  {selected.outcome}
                </span>
              </div>

              <div className="audit-detail-grid">
                <AuditMetadata
                  label="Event ID"
                  value={String(
                    selected.id,
                  )}
                />

                <AuditMetadata
                  label="Actor role"
                  value={
                    selected.actor_role
                  }
                />

                <AuditMetadata
                  label="Resource"
                  value={
                    selected
                      .resource_type
                  }
                />

                <AuditMetadata
                  label="Action"
                  value={
                    selected.action
                  }
                />

                <AuditMetadata
                  label="Outcome"
                  value={
                    selected.outcome
                  }
                />

                <AuditMetadata
                  label="Time"
                  value={
                    formatDateTime(
                      selected.created_at,
                    )
                  }
                />
              </div>

              <div className="audit-redaction-note">
                <ShieldCheck
                  size={16}
                />

                Sensitive audit metadata is
                intentionally redacted from
                viewer access.
              </div>
            </>
          )}
        </article>
      </div>
    </section>
  )
}


function AuditStat({
  label,
  value,
}: {
  label: string
  value: number
}) {
  return (
    <article className="panel audit-stat-card">
      <span>
        {label}
      </span>

      <strong>
        {value}
      </strong>
    </article>
  )
}


function AuditMetadata({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="audit-metadata">
      <span>
        {label}
      </span>

      <strong title={value}>
        {value}
      </strong>
    </div>
  )
}