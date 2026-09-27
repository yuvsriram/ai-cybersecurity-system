import {
  AlertTriangle,
  BrainCircuit,
  FileUp,
  FlaskConical,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'

import {
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
} from 'react'

import {
  analyzeLogs,
  explainLogs,
} from '../api/security'

import type {
  AnalysisFormat,
  AnalysisSeverity,
  InvestigationEvidenceSummary,
  LogAnalysisExplanationResponse,
  LogAnalysisResponse,
} from '../api/types'

import {
  useApiKey,
} from '../auth/ApiKeyContext'

const MAX_FILE_BYTES =
  2_000_000

const DATASET_NAME =
  'interactive_demo'

type AnalysisSample =
  | 'lockout'
  | 'failed-burst'
  | 'ntlm-spray'
  | 'no-detection'

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

function formatDuration(
  seconds: number,
): string {
  if (seconds < 60) {
    return `${seconds.toFixed(0)} sec`
  }

  const minutes =
    seconds / 60

  if (minutes < 60) {
    return `${minutes.toFixed(1)} min`
  }

  return `${(
    minutes / 60
  ).toFixed(1)} hr`
}

function formatKnownOutcomes(
  summary:
    InvestigationEvidenceSummary,
): string {
  const entries =
    Object.entries(
      summary.known_outcomes,
    )

  const pieces =
    entries.map(
      ([name, count]) =>
        `${name}: ${count}`,
    )

  if (
    summary.unknown_outcome_count >
    0
  ) {
    pieces.push(
      `unknown: ${summary.unknown_outcome_count}`,
    )
  }

  if (pieces.length === 0) {
    return 'None'
  }

  return pieces.join(', ')
}

function shortFingerprint(
  value: string,
): string {
  if (value.length <= 16) {
    return value
  }

  return (
    `${value.slice(
      0,
      8,
    )}...${value.slice(
      -8,
    )}`
  )
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
    useState<
      LogAnalysisResponse | null
    >(
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

  const [
    explanationResponse,
    setExplanationResponse,
  ] =
    useState<
      LogAnalysisExplanationResponse
      | null
    >(
      null,
    )

  const [
    explanationLoading,
    setExplanationLoading,
  ] = useState(false)

  const [
    explanationError,
    setExplanationError,
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

  function clearResults() {
    setResult(null)
    setExplanationResponse(null)
    setExplanationError(null)
  }

  function canRequestApi():
    boolean {
    return (
      authMode === 'demo' ||
      apiKey !== null
    )
  }

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

    if (!canRequestApi()) {
      setError(
        'API authentication is not available.',
      )

      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    setExplanationResponse(null)
    setExplanationError(null)

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

  async function runExplanation() {
    const normalized =
      content.trim()

    if (!result) {
      setExplanationError(
        'Run deterministic analysis before generating an AI explanation.',
      )

      return
    }

    if (
      result.alerts.length === 0
    ) {
      setExplanationError(
        'No detection is available to explain.',
      )

      return
    }

    if (!normalized) {
      setExplanationError(
        'The source telemetry is no longer available.',
      )

      return
    }

    if (
      contentBytes >
      MAX_FILE_BYTES
    ) {
      setExplanationError(
        'Input exceeds the 2 MB interactive analysis limit.',
      )

      return
    }

    if (!canRequestApi()) {
      setExplanationError(
        'API authentication is not available.',
      )

      return
    }

    setExplanationLoading(true)
    setExplanationError(null)

    try {
      const response =
        await explainLogs(
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
        response.analysis,
      )

      setExplanationResponse(
        response,
      )

      if (!response.explanation) {
        setExplanationError(
          'The analysis did not contain a finding that could be explained.',
        )
      }
    } catch (
      requestError
    ) {
      setExplanationResponse(null)

      setExplanationError(
        requestError
          instanceof Error
          ? requestError.message
          : (
              'Unable to generate '
              + 'the grounded AI explanation.'
            ),
      )
    } finally {
      setExplanationLoading(false)
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
    clearResults()

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
    setError(null)

    clearResults()

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
    sample: AnalysisSample,
  ) {
    clearResults()

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
                  event.target
                    .value as AnalysisFormat

                setFormat(
                  nextFormat,
                )

                clearResults()
                setError(null)
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
              clearResults()
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
                explanationLoading ||
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

            <div>
              <strong>06</strong>
              <span>
                Optional grounded AI
              </span>
            </div>
          </div>

          <div className="analysis-explanation">
            <FlaskConical
              size={17}
            />

            <p>
              Severity, rule ID, MITRE
              mapping, counts, and evidence
              come from deterministic
              application logic. The optional
              AI layer can explain those
              facts, but cannot redefine them.
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
          explanationResponse={
            explanationResponse
          }
          explanationLoading={
            explanationLoading
          }
          explanationError={
            explanationError
          }
          onExplain={
            runExplanation
          }
        />
      )}
    </section>
  )
}

interface AnalysisResultsProps {
  result: LogAnalysisResponse

  explanationResponse:
    LogAnalysisExplanationResponse
    | null

  explanationLoading: boolean

  explanationError:
    string | null

  onExplain:
    () => Promise<void>
}

function AnalysisResults({
  result,
  explanationResponse,
  explanationLoading,
  explanationError,
  onExplain,
}: AnalysisResultsProps) {
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

        <div className="analysis-authority-banner">
          <ShieldCheck
            size={16}
          />

          <div>
            <strong>
              Deterministic result
            </strong>

            <span>
              Severity and detection
              metadata below are calculated
              before any AI explanation.
            </span>
          </div>
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
                          '--'
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
                          '--'
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
                          : '--'}
                      </strong>
                    </div>
                  </div>
                </div>
              ),
            )}
          </div>
        )}
      </article>

      {result.alerts.length > 0 && (
        <GroundedExplanationPanel
          response={
            explanationResponse
          }
          loading={
            explanationLoading
          }
          error={
            explanationError
          }
          onExplain={
            onExplain
          }
        />
      )}

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
                          '--'
                        }
                      </td>

                      <td>
                        {
                          event
                            .source_ip ??
                          event
                            .source_host ??
                          '--'
                        }
                      </td>

                      <td>
                        {
                          event
                            .destination_host ??
                          event
                            .destination_ip ??
                          '--'
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

interface GroundedExplanationPanelProps {
  response:
    LogAnalysisExplanationResponse
    | null

  loading: boolean

  error:
    string | null

  onExplain:
    () => Promise<void>
}

function GroundedExplanationPanel({
  response,
  loading,
  error,
  onExplain,
}: GroundedExplanationPanelProps) {
  const explanation =
    response?.explanation ??
    null

  const finding =
    response?.primary_finding ??
    null

  return (
    <article className="panel analysis-ai-panel">
      <div className="analysis-ai-header">
        <div>
          <span className="panel-kicker">
            GROUNDED AI
          </span>

          <h2>
            AI investigation explanation
          </h2>

          <p>
            Optional AI interpretation
            generated only from the
            application-supplied detection
            evidence.
          </p>
        </div>

        <div className="analysis-ai-status">
          <Sparkles
            size={15}
          />

          AI-generated interpretation
        </div>
      </div>

      <div className="analysis-ai-boundary">
        <ShieldCheck
          size={17}
        />

        <div>
          <strong>
            Deterministic authority is preserved
          </strong>

          <span>
            The model cannot change the
            rule ID, severity, MITRE
            technique, evidence count, or
            normalized event facts.
          </span>
        </div>
      </div>

      {!explanation && (
        <div className="analysis-ai-cta">
          <div>
            <h3>
              Explain the primary detection
            </h3>

            <p>
              The backend will rerun the
              deterministic analysis,
              construct a bounded evidence
              package, and validate the
              model output before returning
              it.
            </p>
          </div>

          <button
            className="analysis-ai-button"
            type="button"
            disabled={loading}
            onClick={() => {
              void onExplain()
            }}
          >
            <Sparkles
              size={16}
            />

            {loading
              ? 'Generating grounded explanation...'
              : 'Generate AI Explanation'}
          </button>
        </div>
      )}

      {error && (
        <div
          className="analysis-ai-error"
          role="alert"
        >
          <AlertTriangle
            size={16}
          />

          <div>
            <strong>
              AI explanation unavailable
            </strong>

            <span>
              {error}
            </span>
          </div>
        </div>
      )}

      {explanation && (
        <div className="analysis-ai-content">
          {finding && (
            <div className="analysis-ai-grounding-strip">
              <div>
                <span>
                  Rule
                </span>

                <strong>
                  {
                    finding
                      .rule_id
                  }
                </strong>
              </div>

              <div>
                <span>
                  Severity
                </span>

                <strong>
                  {
                    finding
                      .severity
                  }
                </strong>
              </div>

              <div>
                <span>
                  Evidence
                </span>

                <strong>
                  {
                    finding
                      .evidence_count
                  } events
                </strong>
              </div>

              <div>
                <span>
                  MITRE
                </span>

                <strong>
                  {
                    finding
                      .mitre_techniques
                      .join(', ') ||
                    '--'
                  }
                </strong>
              </div>
            </div>
          )}

          <section className="analysis-ai-section analysis-ai-summary">
            <div className="analysis-ai-section-heading">
              <span>
                AI SUMMARY
              </span>

              <div className="analysis-ai-outcome">
                Outcome:
                {' '}
                <strong>
                  {
                    explanation
                      .authentication_outcome
                  }
                </strong>
              </div>
            </div>

            <p>
              {
                explanation
                  .summary
              }
            </p>
          </section>

          <div className="analysis-ai-grid">
            <AIListSection
              title="Observed behavior"
              items={
                explanation
                  .observed_behavior
              }
            />

            <AIListSection
              title="Uncertainties"
              items={
                explanation
                  .uncertainties
              }
            />
          </div>

          <section className="analysis-ai-section">
            <div className="analysis-ai-section-heading">
              <span>
                EVIDENCE FINDINGS
              </span>
            </div>

            {explanation
              .evidence_findings
              .length === 0 ? (
                <div className="analysis-ai-empty">
                  No model-generated evidence
                  findings were returned.
                </div>
              ) : (
                <div className="analysis-ai-findings">
                  {explanation
                    .evidence_findings
                    .map(
                      (
                        evidenceFinding,
                        index,
                      ) => (
                        <div
                          key={
                            `${index}-${evidenceFinding.observation}`
                          }
                        >
                          <p>
                            {
                              evidenceFinding
                                .observation
                            }
                          </p>

                          <div className="analysis-ai-fingerprints">
                            {evidenceFinding
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
                                    {
                                      shortFingerprint(
                                        fingerprint,
                                      )
                                    }
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

          <section className="analysis-ai-section">
            <div className="analysis-ai-section-heading">
              <span>
                RECOMMENDED ANALYST ACTIONS
              </span>
            </div>

            {explanation
              .recommended_next_steps
              .length === 0 ? (
                <div className="analysis-ai-empty">
                  No recommended actions
                  were returned.
                </div>
              ) : (
                <ol className="analysis-ai-actions">
                  {explanation
                    .recommended_next_steps
                    .map(
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
              )}
          </section>

          <GroundingSummary
            summary={
              explanation
                .evidence_summary
            }
          />
        </div>
      )}
    </article>
  )
}

function AIListSection({
  title,
  items,
}: {
  title: string
  items: string[]
}) {
  return (
    <section className="analysis-ai-section">
      <div className="analysis-ai-section-heading">
        <span>
          {title}
        </span>
      </div>

      {items.length === 0 ? (
        <div className="analysis-ai-empty">
          None returned.
        </div>
      ) : (
        <ul className="analysis-ai-list">
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
      )}
    </section>
  )
}

function GroundingSummary({
  summary,
}: {
  summary:
    InvestigationEvidenceSummary
}) {
  return (
    <section className="analysis-ai-grounding">
      <div className="analysis-ai-section-heading">
        <span>
          GROUNDING / EVIDENCE SUMMARY
        </span>

        <div className="analysis-grounded-label">
          <ShieldCheck
            size={13}
          />

          Application calculated
        </div>
      </div>

      <div className="analysis-ai-grounding-grid">
        <div>
          <span>
            Event count
          </span>

          <strong>
            {
              summary
                .event_count
            }
          </strong>
        </div>

        <div>
          <span>
            Unique users
          </span>

          <strong>
            {
              summary
                .unique_user_count
            }
          </strong>
        </div>

        <div>
          <span>
            Duration
          </span>

          <strong>
            {formatDuration(
              summary
                .duration_seconds,
            )}
          </strong>
        </div>

        <div>
          <span>
            Outcomes
          </span>

          <strong>
            {formatKnownOutcomes(
              summary,
            )}
          </strong>
        </div>

        <div>
          <span>
            First seen
          </span>

          <strong>
            {formatDateTime(
              summary
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
              summary
                .last_seen_at,
            )}
          </strong>
        </div>

        <div>
          <span>
            Source hosts
          </span>

          <strong>
            {
              summary
                .source_hosts
                .join(', ') ||
              '--'
            }
          </strong>
        </div>

        <div>
          <span>
            Destination hosts
          </span>

          <strong>
            {
              summary
                .destination_hosts
                .join(', ') ||
              '--'
            }
          </strong>
        </div>
      </div>
    </section>
  )
}