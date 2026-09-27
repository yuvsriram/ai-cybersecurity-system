import {
  AlertTriangle,
  BrainCircuit,
  FileUp,
  FlaskConical,
  Play,
  RotateCcw,
  ShieldAlert,
} from 'lucide-react'
import {
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
} from 'react'

import {
  analyzeLogs,
} from '../api/security'
import type {
  AnalysisFormat,
  AnalysisSeverity,
  LogAnalysisResponse,
} from '../api/types'
import {
  useApiKey,
} from '../auth/ApiKeyContext'

const MAX_FILE_BYTES =
  2_000_000

const DATASET_NAME =
  'interactive_demo'

function accountLockoutSample():
  string {
  return `01/01/2026 12:00:00 PM
EventCode=4740
SourceName=Microsoft-Windows-Security-Auditing
LogName=Security
ComputerName=DC01
RecordNumber=9001
Message=A user account was locked out.
Account That Was Locked Out:
    Security ID: CORP\\alice
    Account Name: alice
Additional Information:
    Caller Computer Name: CLIENT01

`
}

function failedLogonSample():
  string {
  const timestamps = [
    '01/01/2026 12:00:00 PM',
    '01/01/2026 12:00:30 PM',
    '01/01/2026 12:01:00 PM',
    '01/01/2026 12:01:30 PM',
    '01/01/2026 12:02:00 PM',
  ]

  const lines: string[] = []

  timestamps.forEach(
    (
      timestamp,
      index,
    ) => {
      lines.push(
        `${timestamp}
EventCode=4625
SourceName=Microsoft-Windows-Security-Auditing
LogName=Security
ComputerName=SERVER01
RecordNumber=${9100 + index}
Message=An account failed to log on.
Account For Which Logon Failed:
    Security ID: NULL SID
    Account Name: alice
    Account Domain: CORP
Network Information:
    Workstation Name: CLIENT01
    Source Network Address: 10.0.0.50

`,
      )
    },
  )

  return lines.join('')
}

function noDetectionSample():
  string {
  return `01/01/2026 12:00:00 PM
EventCode=4625
SourceName=Microsoft-Windows-Security-Auditing
LogName=Security
ComputerName=SERVER01
RecordNumber=9200
Message=An account failed to log on.
Account For Which Logon Failed:
    Security ID: NULL SID
    Account Name: alice
    Account Domain: CORP
Network Information:
    Workstation Name: CLIENT01
    Source Network Address: 10.0.0.50

`
}

function ntlmPasswordSpraySample():
  string {
  const events: string[] = []

  for (
    let index = 0;
    index < 20;
    index += 1
  ) {
    const occurredAt =
      new Date(
        Date.UTC(
          2026,
          0,
          1,
          12,
          0,
          index * 5,
        ),
      ).toISOString()

    events.push(
      `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-NTLM"/>
    <EventID>8004</EventID>
    <TimeCreated SystemTime="${occurredAt}"/>
    <EventRecordID>${9300 + index}</EventRecordID>
    <Channel>Microsoft-Windows-NTLM/Operational</Channel>
    <Computer>DC01</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="DomainName">CORP</Data>
    <Data Name="UserName">user${String(
      index,
    ).padStart(
      2,
      '0',
    )}</Data>
    <Data Name="WorkstationName">ATTACKER01</Data>
    <Data Name="SChannelName">DC01</Data>
    <Data Name="SChannelType">2</Data>
  </EventData>
</Event>`,
    )
  }

  return events.join('\n')
}

function severityClass(
  severity: string,
): string {
  return (
    `analysis-severity analysis-severity-${severity
      .trim()
      .toLowerCase()}`
  )
}

function severityLabel(
  severity: AnalysisSeverity,
): string {
  if (severity === 'none') {
    return 'No detection'
  }

  return severity
}

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

export function AnalyzeLogsPage() {
  const {
    apiKey,
    authMode,
  } = useApiKey()

  const fileInputRef =
    useRef<HTMLInputElement | null>(
      null,
    )

  const [
    format,
    setFormat,
  ] =
    useState<AnalysisFormat>(
      'splunk_windows_security',
    )

  const [
    content,
    setContent,
  ] = useState('')

  const [
    fileName,
    setFileName,
  ] =
    useState<string | null>(
      null,
    )

  const [
    result,
    setResult,
  ] =
    useState<LogAnalysisResponse | null>(
      null,
    )

  const [
    loading,
    setLoading,
  ] = useState(false)

  const [
    error,
    setError,
  ] =
    useState<string | null>(
      null,
    )

  const contentBytes =
    useMemo(
      () =>
        new TextEncoder()
          .encode(
            content,
          )
          .byteLength,
      [content],
    )

  async function runAnalysis() {
    const normalized =
      content.trim()

    if (!normalized) {
      setError(
        'Paste logs or upload a log file before analyzing.',
      )

      return
    }

    if (
      contentBytes >
      MAX_FILE_BYTES
    ) {
      setError(
        'Input exceeds the 2 MB interactive analysis limit.',
      )

      return
    }

    const canRequest =
      authMode === 'demo' ||
      apiKey !== null

    if (!canRequest) {
      setError(
        'API authentication is not available.',
      )

      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const response =
        await analyzeLogs(
          apiKey,
          {
            format,
            dataset_name:
              DATASET_NAME,
            content:
              normalized,
          },
        )

      setResult(
        response,
      )
    } catch (
      requestError
    ) {
      setError(
        requestError
          instanceof Error
          ? requestError.message
          : (
              'Unable to analyze '
              + 'the supplied logs.'
            ),
      )
    } finally {
      setLoading(false)
    }
  }

  async function handleFile(
    event:
      ChangeEvent<HTMLInputElement>,
  ) {
    const file =
      event.target.files?.[0]

    if (!file) {
      return
    }

    setError(null)
    setResult(null)

    if (
      file.size >
      MAX_FILE_BYTES
    ) {
      setError(
        'File exceeds the 2 MB interactive analysis limit.',
      )

      event.target.value = ''
      return
    }

    try {
      const text =
        await file.text()

      setContent(
        text,
      )

      setFileName(
        file.name,
      )

      if (
        file.name
          .toLowerCase()
          .endsWith(
            '.xml',
          )
      ) {
        setFormat(
          'windows_ntlm_xml',
        )
      }
    } catch {
      setError(
        'Unable to read the selected file.',
      )
    }
  }

  function reset() {
    setContent('')
    setFileName(null)
    setResult(null)
    setError(null)

    setFormat(
      'splunk_windows_security',
    )

    if (
      fileInputRef.current
    ) {
      fileInputRef.current.value =
        ''
    }
  }

  function loadSample(
    sample:
      | 'lockout'
      | 'failed-burst'
      | 'ntlm-spray'
      | 'no-detection',
  ) {
    setResult(null)
    setError(null)
    setFileName(null)

    if (
      sample ===
      'lockout'
    ) {
      setFormat(
        'splunk_windows_security',
      )

      setContent(
        accountLockoutSample(),
      )

      return
    }

    if (
      sample ===
      'failed-burst'
    ) {
      setFormat(
        'splunk_windows_security',
      )

      setContent(
        failedLogonSample(),
      )

      return
    }

    if (
      sample ===
      'ntlm-spray'
    ) {
      setFormat(
        'windows_ntlm_xml',
      )

      setContent(
        ntlmPasswordSpraySample(),
      )

      return
    }

    setFormat(
      'splunk_windows_security',
    )

    setContent(
      noDetectionSample(),
    )
  }

  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="page-kicker">
            INTERACTIVE DETECTION
          </p>

          <h1>
            Analyze Security Logs
          </h1>

          <p className="page-description">
            Paste or upload supported
            security telemetry and run it
            through the same normalization
            and deterministic detection
            rules used by the platform.
          </p>
        </div>

        <div className="analysis-engine-badge">
          <BrainCircuit
            size={15}
          />

          Rule-driven severity
        </div>
      </div>

      <div className="analysis-workspace">
        <article className="panel analysis-input-panel">
          <div className="analysis-section-heading">
            <div>
              <span className="panel-kicker">
                INPUT
              </span>

              <h2>
                Security telemetry
              </h2>
            </div>

            <button
              className="ghost-small-button"
              type="button"
              onClick={reset}
            >
              <RotateCcw
                size={14}
              />

              Reset
            </button>
          </div>

          <div className="analysis-format-field">
            <label
              htmlFor="analysis-format"
            >
              Log format
            </label>

            <select
              id="analysis-format"
              value={format}
              onChange={(event) => {
                const nextFormat =
                  event.target.value as AnalysisFormat

                setFormat(
                  nextFormat,
                )
              }}
            >
              <option value="splunk_windows_security">
                Splunk Windows Security
              </option>

              <option value="windows_ntlm_xml">
                Windows NTLM XML
              </option>
            </select>
          </div>

          <div className="sample-section">
            <div className="sample-section-label">
              Try a detection sample
            </div>

            <div className="sample-buttons">
              <button
                type="button"
                onClick={() =>
                  loadSample(
                    'lockout',
                  )
                }
              >
                Account Lockout
              </button>

              <button
                type="button"
                onClick={() =>
                  loadSample(
                    'failed-burst',
                  )
                }
              >
                Failed Logon Burst
              </button>

              <button
                type="button"
                onClick={() =>
                  loadSample(
                    'ntlm-spray',
                  )
                }
              >
                NTLM Password Spray
              </button>

              <button
                type="button"
                onClick={() =>
                  loadSample(
                    'no-detection',
                  )
                }
              >
                No Detection
              </button>
            </div>
          </div>

          <div className="analysis-editor-heading">
            <label
              htmlFor="analysis-content"
            >
              Raw log input
            </label>

            <span>
              {contentBytes.toLocaleString()}
              {' / '}
              {MAX_FILE_BYTES.toLocaleString()}
              {' bytes'}
            </span>
          </div>

          <textarea
            id="analysis-content"
            className="analysis-editor"
            value={content}
            spellCheck={false}
            placeholder={
              format ===
              'windows_ntlm_xml'
                ? (
                    'Paste Windows NTLM '
                    + 'event XML here...'
                  )
                : (
                    'Paste Splunk Windows '
                    + 'Security logs here...'
                  )
            }
            onChange={(event) => {
              setContent(
                event.target.value,
              )

              setFileName(null)
              setResult(null)
              setError(null)
            }}
          />

          <div className="analysis-input-actions">
            <div>
              <input
                ref={fileInputRef}
                className="visually-hidden"
                type="file"
                accept=".txt,.log,.xml,text/plain,application/xml,text/xml"
                onChange={handleFile}
              />

              <button
                className="secondary-button"
                type="button"
                onClick={() =>
                  fileInputRef
                    .current
                    ?.click()
                }
              >
                <FileUp
                  size={15}
                />

                Upload file
              </button>

              {fileName && (
                <span className="analysis-file-name">
                  {fileName}
                </span>
              )}
            </div>

            <button
              className="analysis-run-button"
              type="button"
              disabled={
                loading ||
                !content.trim()
              }
              onClick={
                runAnalysis
              }
            >
              <Play
                size={16}
              />

              {loading
                ? 'Analyzing...'
                : 'Analyze Logs'}
            </button>
          </div>

          <div className="analysis-security-note">
            <ShieldAlert
              size={15}
            />

            Analysis is non-persistent.
            Submitted telemetry is evaluated
            in memory and is not inserted
            into the event or alert store.
          </div>
        </article>

        <article className="panel analysis-help-panel">
          <span className="panel-kicker">
            PIPELINE
          </span>

          <h2>
            What happens to your logs?
          </h2>

          <div className="analysis-flow">
            <div>
              <strong>01</strong>
              <span>Parse input</span>
            </div>

            <div>
              <strong>02</strong>
              <span>Normalize events</span>
            </div>

            <div>
              <strong>03</strong>
              <span>Run detections</span>
            </div>

            <div>
              <strong>04</strong>
              <span>Calculate severity</span>
            </div>

            <div>
              <strong>05</strong>
              <span>Return evidence</span>
            </div>
          </div>

          <div className="analysis-explanation">
            <FlaskConical
              size={17}
            />

            <p>
              Severity comes from
              deterministic detection
              rules, not from an LLM.
              This keeps the result
              explainable and tied to
              observed evidence.
            </p>
          </div>
        </article>
      </div>

      {error && (
        <div
          className="error-banner analysis-error"
          role="alert"
        >
          <AlertTriangle
            size={17}
          />

          {error}
        </div>
      )}

      {result && (
        <AnalysisResults
          result={result}
        />
      )}
    </section>
  )
}

function AnalysisResults({
  result,
}: {
  result: LogAnalysisResponse
}) {
  return (
    <div className="analysis-results">
      <article className="panel analysis-summary-panel">
        <div className="analysis-section-heading">
          <div>
            <span className="panel-kicker">
              RESULT
            </span>

            <h2>
              Analysis summary
            </h2>
          </div>

          <span
            className={
              severityClass(
                result
                  .overall_severity,
              )
            }
          >
            {severityLabel(
              result
                .overall_severity,
            )}
          </span>
        </div>

        <div className="analysis-stat-grid">
          <div>
            <span>
              Parsed records
            </span>

            <strong>
              {
                result
                  .parsed_records
              }
            </strong>
          </div>

          <div>
            <span>
              Normalized
            </span>

            <strong>
              {
                result
                  .normalized_events
              }
            </strong>
          </div>

          <div>
            <span>
              Unsupported
            </span>

            <strong>
              {
                result
                  .unsupported_records
              }
            </strong>
          </div>

          <div>
            <span>
              Alerts
            </span>

            <strong>
              {
                result
                  .detected_alerts
              }
            </strong>
          </div>
        </div>

        <div className="severity-breakdown">
          <div>
            <span>
              Critical
            </span>
            <strong>
              {
                result
                  .severity_summary
                  .critical
              }
            </strong>
          </div>

          <div>
            <span>
              High
            </span>
            <strong>
              {
                result
                  .severity_summary
                  .high
              }
            </strong>
          </div>

          <div>
            <span>
              Medium
            </span>
            <strong>
              {
                result
                  .severity_summary
                  .medium
              }
            </strong>
          </div>

          <div>
            <span>
              Low
            </span>
            <strong>
              {
                result
                  .severity_summary
                  .low
              }
            </strong>
          </div>
        </div>
      </article>

      <article className="panel analysis-detections-panel">
        <div className="analysis-section-heading">
          <div>
            <span className="panel-kicker">
              DETECTIONS
            </span>

            <h2>
              Rule findings
            </h2>
          </div>

          <span className="range-label">
            {
              result.alerts.length
            } finding
            {
              result.alerts.length === 1
                ? ''
                : 's'
            }
          </span>
        </div>

        {result.alerts.length ===
        0 ? (
          <div className="analysis-empty-result">
            No detection rule fired for
            the supplied telemetry.
          </div>
        ) : (
          <div className="analysis-alert-list">
            {result.alerts.map(
              (
                alert,
                index,
              ) => (
                <div
                  className="analysis-alert-card"
                  key={
                    `${alert.rule_id}-${index}`
                  }
                >
                  <div className="analysis-alert-heading">
                    <div>
                      <span className="code-badge">
                        {
                          alert
                            .rule_id
                        }
                      </span>

                      <h3>
                        {
                          alert
                            .title
                        }
                      </h3>
                    </div>

                    <span
                      className={
                        severityClass(
                          alert.severity,
                        )
                      }
                    >
                      {
                        alert
                          .severity
                      }
                    </span>
                  </div>

                  <p>
                    {
                      alert
                        .description
                    }
                  </p>

                  <div className="analysis-alert-meta">
                    <div>
                      <span>
                        Evidence
                      </span>

                      <strong>
                        {
                          alert
                            .evidence_count
                        } events
                      </strong>
                    </div>

                    <div>
                      <span>
                        User
                      </span>

                      <strong>
                        {
                          alert
                            .user_name ??
                          '—'
                        }
                      </strong>
                    </div>

                    <div>
                      <span>
                        Source
                      </span>

                      <strong>
                        {
                          alert
                            .source_ip ??
                          alert
                            .source_host ??
                          '—'
                        }
                      </strong>
                    </div>

                    <div>
                      <span>
                        MITRE ATT&CK
                      </span>

                      <strong>
                        {alert
                          .mitre_techniques
                          .length > 0
                          ? (
                              alert
                                .mitre_techniques
                                .join(
                                  ', ',
                                )
                            )
                          : '—'}
                      </strong>
                    </div>
                  </div>
                </div>
              ),
            )}
          </div>
        )}
      </article>

      <article className="panel data-panel">
        <div className="data-panel-header">
          <div>
            <span className="panel-kicker">
              EVIDENCE
            </span>

            <h2>
              Normalized events
            </h2>
          </div>

          <span className="range-label">
            {
              result.events.length
            } events
          </span>
        </div>

        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Code</th>
                <th>User</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Outcome</th>
              </tr>
            </thead>

            <tbody>
              {result.events.length ===
              0 ? (
                <tr>
                  <td
                    className="empty-table"
                    colSpan={6}
                  >
                    No supported events
                    were normalized.
                  </td>
                </tr>
              ) : (
                result.events.map(
                  (
                    event,
                    index,
                  ) => (
                    <tr
                      key={
                        `${event.event_fingerprint}-${index}`
                      }
                    >
                      <td>
                        {formatDateTime(
                          event.occurred_at,
                        )}
                      </td>

                      <td>
                        <span className="code-badge">
                          {
                            event
                              .event_code
                          }
                        </span>
                      </td>

                      <td>
                        {
                          event
                            .user_name ??
                          '—'
                        }
                      </td>

                      <td>
                        {
                          event
                            .source_ip ??
                          event
                            .source_host ??
                          '—'
                        }
                      </td>

                      <td>
                        {
                          event
                            .destination_host ??
                          event
                            .destination_ip ??
                          '—'
                        }
                      </td>

                      <td>
                        {
                          event
                            .outcome ??
                          'unknown'
                        }
                      </td>
                    </tr>
                  ),
                )
              )}
            </tbody>
          </table>
        </div>
      </article>
    </div>
  )
}