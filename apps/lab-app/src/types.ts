export interface User {
  id: number;
  username: string;
  role: 'admin' | 'auditor' | 'user';
  api_key: string;
  email: string;
  created_at: string;
}

export interface Incident {
  id: number;
  owner_id: number;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  classification: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';
  description: string;
  system_target: string;
  created_at: string;
}

export interface DiagnosticLog {
  id: number;
  host: string;
  status: 'SUCCESS' | 'ERROR';
  output: string;
  created_at: string;
}

export interface PingResult {
  status: 'SUCCESS' | 'ERROR';
  output: string;
}

export interface ReportResponse {
  status: number;
  body: Record<string, any>;
}
