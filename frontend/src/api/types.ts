export interface SecurityEvent {
  id: number
  event_fingerprint: string

  schema_version: string
  occurred_at: string

  event_code: string
  category: string
  action: string
  outcome: string | null

  source_provider: string | null
  source_channel: string | null
  source_dataset: string | null
  source_record_id: string | null

  host_name: string | null

  user_name: string | null
  user_domain: string | null
  user_sid: string | null

  source_host: string | null
  source_ip: string | null

  destination_host: string | null
  destination_ip: string | null

  attributes: Record<string, string>
}

export interface SecurityAlert {
  id: string

  rule_id: string
  rule_version: string

  title: string
  description: string
  severity: string

  created_at: string
  first_seen_at: string
  last_seen_at: string

  user_name: string | null
  source_ip: string | null
  source_host: string | null
  destination_host: string | null

  evidence_record_ids: string[]
  evidence_event_fingerprints: string[]
  evidence_event_codes: string[]

  mitre_techniques: string[]
}

export interface AlertEvidence {
  alert_id: string
  rule_id: string
  evidence_count: number
  events: SecurityEvent[]
}

export interface SecurityOverview {
  eventCount: number
  alertCount: number
  highSeverityCount: number
  detectionRuleCount: number
  recentAlerts: SecurityAlert[]
}

export type AnalysisFormat =
  | 'splunk_windows_security'
  | 'windows_ntlm_xml'

export type AnalysisSeverity =
  | 'none'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export interface AnalysisRequest {
  format: AnalysisFormat
  dataset_name: string
  content: string
}

export interface AnalysisEvent {
  event_fingerprint: string

  occurred_at: string

  event_code: string
  category: string
  action: string
  outcome: string | null

  source_provider: string | null
  source_channel: string | null

  host_name: string | null

  user_name: string | null
  user_domain: string | null

  source_host: string | null
  source_ip: string | null

  destination_host: string | null
  destination_ip: string | null
}

export interface AnalysisAlert {
  rule_id: string
  rule_version: string

  title: string
  description: string
  severity: string

  first_seen_at: string
  last_seen_at: string

  user_name: string | null

  source_ip: string | null
  source_host: string | null

  destination_host: string | null

  evidence_count: number
  evidence_event_codes: string[]

  mitre_techniques: string[]
}

export interface SeveritySummary {
  critical: number
  high: number
  medium: number
  low: number
}

export interface LogAnalysisResponse {
  format: AnalysisFormat

  overall_severity: AnalysisSeverity

  parsed_records: number
  normalized_events: number
  unsupported_records: number

  detected_alerts: number

  severity_summary: SeveritySummary

  alerts: AnalysisAlert[]
  events: AnalysisEvent[]
}

export type AuthenticationOutcome =
  | 'unknown'
  | 'success'
  | 'failure'
  | 'mixed'

export interface InvestigationEvidenceSummary {
  event_count: number

  first_seen_at: string
  last_seen_at: string

  duration_seconds: number

  unique_user_count: number

  source_hosts: string[]
  destination_hosts: string[]
  event_codes: string[]

  known_outcomes: Record<
    string,
    number
  >

  unknown_outcome_count: number
}

export interface InvestigationEvidenceFinding {
  observation: string

  event_fingerprints: string[]
}

export interface InvestigationResult {
  evidence_summary:
    InvestigationEvidenceSummary

  authentication_outcome:
    AuthenticationOutcome

  summary: string

  observed_behavior: string[]

  evidence_findings:
    InvestigationEvidenceFinding[]

  uncertainties: string[]

  recommended_next_steps: string[]
}

export interface LogAnalysisExplanationResponse {
  analysis: LogAnalysisResponse

  primary_finding:
    AnalysisAlert | null

  explanation:
    InvestigationResult | null
}