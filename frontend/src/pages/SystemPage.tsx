import {
  Activity,
  BrainCircuit,
  Database,
  Gauge,
  RefreshCw,
  Server,
  ShieldCheck,
} from 'lucide-react'

import {
  useEffect,
  useState,
} from 'react'

import {
  getLiveness,
  getReadiness,
  type LivenessResponse,
  type ReadinessResponse,
} from '../api/system'

import {
  useApiKey,
} from '../auth/ApiKeyContext'


export function SystemPage() {
  const {
    authMode,
  } = useApiKey()

  const [
    live,
    setLive,
  ] =
    useState<LivenessResponse | null>(
      null,
    )

  const [
    ready,
    setReady,
  ] =
    useState<ReadinessResponse | null>(
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
    checkedAt,
    setCheckedAt,
  ] =
    useState<Date | null>(
      null,
    )


  async function refresh() {
    setLoading(true)
    setError(null)

    try {
      const [
        liveness,
        readiness,
      ] =
        await Promise.all([
          getLiveness(),
          getReadiness(),
        ])

      setLive(liveness)
      setReady(readiness)

      setCheckedAt(
        new Date(),
      )
    } catch (
      requestError
    ) {
      setError(
        requestError
          instanceof Error
          ? requestError.message
          : (
              'Unable to retrieve '
              + 'system health.'
            ),
      )
    } finally {
      setLoading(false)
    }
  }


  useEffect(
    () => {
      void refresh()
    },
    [],
  )


  const apiHealthy =
    live?.status === 'ok'

  const databaseHealthy =
    ready?.database === 'ok'


  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="page-kicker">
            PLATFORM OPERATIONS
          </p>

          <h1>
            System
          </h1>

          <p className="page-description">
            Inspect platform health,
            runtime architecture, and
            operational boundaries.
          </p>
        </div>

        <button
          className="secondary-button"
          type="button"
          disabled={loading}
          onClick={() => {
            void refresh()
          }}
        >
          <RefreshCw
            size={14}
          />

          Refresh health
        </button>
      </div>

      {error && (
        <div
          className="error-banner system-error"
          role="alert"
        >
          {error}
        </div>
      )}

      <div className="system-health-grid">
        <HealthCard
          icon={
            <Server size={18} />
          }
          label="API process"
          value={
            apiHealthy
              ? 'Healthy'
              : 'Unavailable'
          }
          healthy={apiHealthy}
        />

        <HealthCard
          icon={
            <Database size={18} />
          }
          label="PostgreSQL"
          value={
            databaseHealthy
              ? 'Ready'
              : 'Unavailable'
          }
          healthy={
            databaseHealthy
          }
        />

        <HealthCard
          icon={
            <Activity size={18} />
          }
          label="Frontend"
          value="Online"
          healthy
        />

        <HealthCard
          icon={
            <ShieldCheck
              size={18}
            />
          }
          label="Access mode"
          value={
            authMode === 'demo'
              ? 'Public viewer'
              : 'Authenticated'
          }
          healthy
        />
      </div>

      <div className="system-layout">
        <article className="panel system-panel">
          <span className="panel-kicker">
            HEALTH
          </span>

          <h2>
            Runtime checks
          </h2>

          <div className="system-check-list">
            <SystemCheck
              name="Liveness"
              endpoint="/health/live"
              value={
                live?.status ??
                'unknown'
              }
            />

            <SystemCheck
              name="Readiness"
              endpoint="/health/ready"
              value={
                ready?.status ??
                'unknown'
              }
            />

            <SystemCheck
              name="Database"
              endpoint="PostgreSQL SELECT 1"
              value={
                ready?.database ??
                'unknown'
              }
            />
          </div>

          <p className="system-last-check">
            Last checked:
            {' '}
            {checkedAt
              ? checkedAt
                  .toLocaleString()
              : '--'}
          </p>
        </article>

        <article className="panel system-panel">
          <span className="panel-kicker">
            ARCHITECTURE
          </span>

          <h2>
            Platform components
          </h2>

          <div className="system-component-grid">
            <ComponentCard
              icon={
                <Activity
                  size={17}
                />
              }
              title="React + Nginx"
              description={
                'SOC interface and '
                + 'server-side demo '
                + 'credential injection.'
              }
            />

            <ComponentCard
              icon={
                <Server
                  size={17}
                />
              }
              title="FastAPI"
              description={
                'Detection, RBAC, '
                + 'analysis, case, and '
                + 'investigation APIs.'
              }
            />

            <ComponentCard
              icon={
                <Database
                  size={17}
                />
              }
              title="PostgreSQL"
              description={
                'Persistent events, '
                + 'alerts, cases, audit '
                + 'and investigation runs.'
              }
            />

            <ComponentCard
              icon={
                <BrainCircuit
                  size={17}
                />
              }
              title="Grounded AI"
              description={
                'Structured evidence '
                + 'explanations with '
                + 'application validation.'
              }
            />

            <ComponentCard
              icon={
                <Gauge
                  size={17}
                />
              }
              title="Observability"
              description={
                'Prometheus metrics, '
                + 'Grafana dashboards '
                + 'and Tempo tracing.'
              }
            />

            <ComponentCard
              icon={
                <ShieldCheck
                  size={17}
                />
              }
              title="Security"
              description={
                'Role-based access, '
                + 'security headers, '
                + 'non-root containers '
                + 'and bounded inputs.'
              }
            />
          </div>
        </article>
      </div>

      <div className="system-boundary-note">
        <ShieldCheck
          size={16}
        />

        <div>
          <strong>
            Operational boundary
          </strong>

          <span>
            Worker and observability
            infrastructure are intentionally
            not exposed directly through
            the public browser interface.
          </span>
        </div>
      </div>
    </section>
  )
}


function HealthCard({
  icon,
  label,
  value,
  healthy,
}: {
  icon: React.ReactNode
  label: string
  value: string
  healthy: boolean
}) {
  return (
    <article
      className={[
        'panel',
        'system-health-card',
        healthy
          ? 'system-health-card-ok'
          : 'system-health-card-error',
      ].join(' ')}
    >
      {icon}

      <div>
        <span>
          {label}
        </span>

        <strong>
          {value}
        </strong>
      </div>
    </article>
  )
}


function SystemCheck({
  name,
  endpoint,
  value,
}: {
  name: string
  endpoint: string
  value: string
}) {
  return (
    <div className="system-check-row">
      <div>
        <strong>
          {name}
        </strong>

        <code>
          {endpoint}
        </code>
      </div>

      <span>
        {value}
      </span>
    </div>
  )
}


function ComponentCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode
  title: string
  description: string
}) {
  return (
    <div className="system-component-card">
      {icon}

      <div>
        <strong>
          {title}
        </strong>

        <p>
          {description}
        </p>
      </div>
    </div>
  )
}