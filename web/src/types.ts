export interface ServerStatus {
  name: string;
  version: string;
  base_url: string;
  port: number;
  uptime_seconds: number;
  active_rsa_kid: string;
  active_ec_kid: string;
  personas_count: number;
  traces_count: number;
}

export interface Persona {
  id: string;
  sub: string;
  name: string;
  email: string;
  email_verified: boolean;
  roles: string[];
  permissions: string[];
  scopes: string[];
  status: 'active' | 'suspended' | 'pending';
  custom_claims?: Record<string, any>;
}

export interface TraceStep {
  index: number;
  name: string;
  description: string;
  timestamp: string;
  payload?: any;
  status: 'ok' | 'error' | 'pending';
}

export interface FlowTrace {
  id: string;
  authCode?: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  persona: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  codeVerifier?: string;
  computedChallenge?: string;
  status: 'initiated' | 'exchanged' | 'failed';
  errorReason?: string;
  createdAt: string;
  exchangedAt?: string;
  steps: TraceStep[];
}

export interface DecodedJWT {
  raw_token: string;
  header_raw: string;
  payload_raw: string;
  signature_raw: string;
  header: Record<string, any>;
  payload: Record<string, any>;
  algorithm: string;
  key_id?: string;
  token_type?: string;
  subject?: string;
  issuer?: string;
  audience?: string[];
  issued_at?: string;
  expires_at?: string;
  not_before?: string;
  is_expired: boolean;
  ttl_seconds: number;
  has_signature: boolean;
  signature_size_bytes: number;
  parse_error?: string;
}

export interface ValidationResult {
  valid: boolean;
  signature_valid: boolean;
  temporal_valid: boolean;
  algorithm: string;
  key_id?: string;
  key_source: string;
  error?: string;
  warning?: string;
}

export interface AttackVector {
  id: string;
  name: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium';
  description: string;
  remediation: string;
  token: string;
}

export interface TestResult {
  vector_id: string;
  vector_name: string;
  category: string;
  severity: string;
  status_code: number;
  status_text: string;
  passed: boolean;
  verdict: string;
  duration_ms: number;
  snippet: string;
  error_message?: string;
}

export interface SuiteReport {
  target_url: string;
  method: string;
  timestamp: string;
  total_tests: number;
  passed: number;
  failed: number;
  errors: number;
  score_pct: number;
  results: TestResult[];
}
