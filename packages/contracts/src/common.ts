import { z } from 'zod';

/**
 * ============================================================================
 * 1. SEVERITY
 * ============================================================================
 */
export const Severity = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
} as const;

export type Severity = (typeof Severity)[keyof typeof Severity];

export const SeveritySchema = z.preprocess((val) => {
  if (typeof val === 'string') return val.trim().toUpperCase();
  return val;
}, z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']));

/**
 * Numeric scoring helper for risk calculations (CVSS-aligned)
 */
export function severityToScore(severity: Severity): number {
  switch (severity) {
    case Severity.CRITICAL:
      return 10.0;
    case Severity.HIGH:
      return 8.0;
    case Severity.MEDIUM:
      return 5.0;
    case Severity.LOW:
      return 2.0;
    case Severity.INFO:
      return 0.0;
  }
}

/**
 * ============================================================================
 * 2. CONFIDENCE
 * ============================================================================
 */
export const Confidence = {
  CERTAIN: 'CERTAIN',
  FIRM: 'FIRM',
  TENTATIVE: 'TENTATIVE',
} as const;

export type Confidence = (typeof Confidence)[keyof typeof Confidence];

export const ConfidenceSchema = z.preprocess((val) => {
  if (typeof val === 'string') {
    const s = val.trim().toUpperCase();
    if (s === 'HIGH') return 'CERTAIN';
    if (s === 'MEDIUM') return 'FIRM';
    if (s === 'LOW') return 'TENTATIVE';
    return s;
  }
  return val;
}, z.enum(['CERTAIN', 'FIRM', 'TENTATIVE']));

/**
 * ============================================================================
 * 3. TARGET TYPE (AppSec & AgentSec Unified)
 * ============================================================================
 */
export const TargetType = {
  SOURCE_CODE: 'SOURCE_CODE',
  DEPENDENCY: 'DEPENDENCY',
  API_ENDPOINT: 'API_ENDPOINT',
  MCP_TOOL: 'MCP_TOOL',
  LLM_PROMPT: 'LLM_PROMPT',
  AGENT_MEMORY: 'AGENT_MEMORY',
  CONFIGURATION: 'CONFIGURATION',
  CONTAINER_IMAGE: 'CONTAINER_IMAGE',
  CLOUD_RESOURCE: 'CLOUD_RESOURCE',
} as const;

export type TargetType = (typeof TargetType)[keyof typeof TargetType];

export const TargetTypeSchema = z.preprocess((val) => {
  if (typeof val === 'string') return val.trim().toUpperCase();
  return val;
}, z.enum([
  'SOURCE_CODE',
  'DEPENDENCY',
  'API_ENDPOINT',
  'MCP_TOOL',
  'LLM_PROMPT',
  'AGENT_MEMORY',
  'CONFIGURATION',
  'CONTAINER_IMAGE',
  'CLOUD_RESOURCE',
]));

/**
 * ============================================================================
 * 4. VERIFICATION STATUS
 * ============================================================================
 */
export const VerificationStatus = {
  VERIFIED_TRUE_POSITIVE: 'VERIFIED_TRUE_POSITIVE',
  REFUTED_FALSE_POSITIVE: 'REFUTED_FALSE_POSITIVE',
  INCONCLUSIVE: 'INCONCLUSIVE',
  EXECUTION_ERROR: 'EXECUTION_ERROR',
} as const;

export type VerificationStatus = (typeof VerificationStatus)[keyof typeof VerificationStatus];

export const VerificationStatusSchema = z.preprocess((val) => {
  if (typeof val === 'string') return val.trim().toUpperCase();
  return val;
}, z.enum([
  'VERIFIED_TRUE_POSITIVE',
  'REFUTED_FALSE_POSITIVE',
  'INCONCLUSIVE',
  'EXECUTION_ERROR',
]));

/**
 * ============================================================================
 * 5. VERIFICATION TYPE
 * ============================================================================
 */
export const VerificationType = {
  REPRODUCER_EXECUTION: 'REPRODUCER_EXECUTION',
  DETERMINISTIC_AST: 'DETERMINISTIC_AST',
  EDGE_TELEMETRY: 'EDGE_TELEMETRY',
  DUAL_OPINION_CONSENSUS: 'DUAL_OPINION_CONSENSUS',
  SYNTHETIC_BENCHMARK_PROBE: 'SYNTHETIC_BENCHMARK_PROBE',
  HEURISTIC: 'HEURISTIC',
} as const;

export type VerificationType = (typeof VerificationType)[keyof typeof VerificationType];

export const VerificationTypeSchema = z.preprocess((val) => {
  if (typeof val === 'string') return val.trim().toUpperCase();
  return val;
}, z.enum([
  'REPRODUCER_EXECUTION',
  'DETERMINISTIC_AST',
  'EDGE_TELEMETRY',
  'DUAL_OPINION_CONSENSUS',
  'SYNTHETIC_BENCHMARK_PROBE',
  'HEURISTIC',
]));

/**
 * ============================================================================
 * 6. SOURCE ENGINE
 * ============================================================================
 */
export const SourceEngine = {
  MANTIS: 'mantis',
  CODEX_SECURITY: 'codex_security',
  CLOUDFLARE_SECURITY_CENTER: 'cloudflare_security_center',
  QUALITY_ENGINE: 'quality_engine',
  HARNESS2: 'harness2',
  BUILTIN: 'builtin',
} as const;

export type SourceEngine = (typeof SourceEngine)[keyof typeof SourceEngine] | string;

export const SourceEngineSchema = z.preprocess((val) => {
  if (typeof val === 'string') return val.trim().toLowerCase();
  return val;
}, z.string().min(1));

/**
 * ============================================================================
 * 7. GATE VERDICT
 * ============================================================================
 */
export const GateVerdict = {
  PASS: 'PASS',
  BLOCK: 'BLOCK',
  REJECT: 'REJECT',
  REQUIRES_HUMAN_APPROVAL: 'REQUIRES_HUMAN_APPROVAL',
  HOLD: 'HOLD',
  ERROR: 'ERROR',
} as const;

export type GateVerdict = (typeof GateVerdict)[keyof typeof GateVerdict];

export const GateVerdictSchema = z.preprocess((val) => {
  if (typeof val === 'string') return val.trim().toUpperCase();
  return val;
}, z.enum(['PASS', 'BLOCK', 'REJECT', 'REQUIRES_HUMAN_APPROVAL', 'HOLD', 'ERROR']));

/**
 * ============================================================================
 * 8. COMMON WEAKNESS ENUMERATION (CWE)
 * ============================================================================
 */
export const CommonCwe = {
  CWE_22: 'CWE-22',   // Path Traversal
  CWE_78: 'CWE-78',   // OS Command Injection
  CWE_79: 'CWE-79',   // Cross-site Scripting
  CWE_89: 'CWE-89',   // SQL Injection
  CWE_94: 'CWE-94',   // Code Injection
  CWE_200: 'CWE-200', // Information Exposure
  CWE_284: 'CWE-284', // Improper Access Control
  CWE_287: 'CWE-287', // Improper Authentication
  CWE_312: 'CWE-312', // Cleartext Storage of Sensitive Information
  CWE_326: 'CWE-326', // Inadequate Encryption Strength
  CWE_352: 'CWE-352', // Cross-Site Request Forgery (CSRF)
  CWE_502: 'CWE-502', // Deserialization of Untrusted Data
  CWE_862: 'CWE-862', // Missing Authorization
  CWE_918: 'CWE-918', // Server-Side Request Forgery (SSRF)
} as const;

export const CweIdSchema = z.preprocess((val) => {
  if (typeof val === 'string') return val.trim().toUpperCase();
  return val;
}, z.string().regex(/^CWE-\d+$/, 'CWE ID must match format CWE-<number>, e.g. CWE-89'));

/**
 * ============================================================================
 * 9. OWASP TAXONOMIES (Web 2021, API 2023, LLM 2025)
 * ============================================================================
 */
export const OwaspWeb2021 = {
  A01_BROKEN_ACCESS_CONTROL: 'A01:2021-Broken Access Control',
  A02_CRYPTOGRAPHIC_FAILURES: 'A02:2021-Cryptographic Failures',
  A03_INJECTION: 'A03:2021-Injection',
  A04_INSECURE_DESIGN: 'A04:2021-Insecure Design',
  A05_SECURITY_MISCONFIGURATION: 'A05:2021-Security Misconfiguration',
  A06_VULNERABLE_OUTDATED_COMPONENTS: 'A06:2021-Vulnerable and Outdated Components',
  A07_IDENTIFICATION_AUTH_FAILURES: 'A07:2021-Identification and Authentication Failures',
  A08_SOFTWARE_DATA_INTEGRITY_FAILURES: 'A08:2021-Software and Data Integrity Failures',
  A09_SECURITY_LOGGING_FAILURES: 'A09:2021-Security Logging and Monitoring Failures',
  A10_SSRF: 'A10:2021-Server-Side Request Forgery',
} as const;

export const OwaspApi2023 = {
  API1_BOLA: 'API1:2023-Broken Object Level Authorization',
  API2_BROKEN_AUTHENTICATION: 'API2:2023-Broken Authentication',
  API3_BOPLA: 'API3:2023-Broken Object Property Level Authorization',
  API4_UNRESTRICTED_RESOURCE_CONSUMPTION: 'API4:2023-Unrestricted Resource Consumption',
  API5_BFLA: 'API5:2023-Broken Function Level Authorization',
  API6_UNRESTRICTED_ACCESS_SENSITIVE_FLOWS: 'API6:2023-Unrestricted Access to Sensitive Business Flows',
  API7_SSRF: 'API7:2023-Server Side Request Forgery',
  API8_SECURITY_MISCONFIGURATION: 'API8:2023-Security Misconfiguration',
  API9_IMPROPER_INVENTORY_MANAGEMENT: 'API9:2023-Improper Inventory Management',
  API10_UNSAFE_CONSUMPTION_OF_APIS: 'API10:2023-Unsafe Consumption of APIs',
} as const;

export const OwaspLlm2025 = {
  LLM01_PROMPT_INJECTION: 'LLM01:2025-Prompt Injection',
  LLM02_SENSITIVE_INFO_DISCLOSURE: 'LLM02:2025-Sensitive Information Disclosure',
  LLM03_SUPPLY_CHAIN_RISKS: 'LLM03:2025-Supply Chain Risks',
  LLM04_DATA_MODEL_POISONING: 'LLM04:2025-Data and Model Poisoning',
  LLM05_IMPROPER_OUTPUT_HANDLING: 'LLM05:2025-Improper Output Handling',
  LLM06_EXCESSIVE_AGENCY: 'LLM06:2025-Excessive Agency',
  LLM07_INSECURE_TOOL_DESIGN: 'LLM07:2025-Insecure Tool Design',
  LLM08_VECTOR_EMBEDDING_WEAKNESSES: 'LLM08:2025-Vector and Embedding Weaknesses',
  LLM09_MISINFORMATION: 'LLM09:2025-Misinformation',
  LLM10_UNBOUNDED_CONSUMPTION: 'LLM10:2025-Unbounded Consumption',
} as const;

/**
 * Validates OWASP category strings across Web, API, and LLM standards.
 * Accepts exact canonical strings or structured OWASP prefix syntax.
 */
export const OwaspCategorySchema = z.string().min(3).refine((val) => {
  const trimmed = val.trim();
  const pattern = /^(A\d{2}:2021|API\d{1,2}:2023|LLM\d{2}:2025)[-:][\w\s-]+$/i;
  return pattern.test(trimmed);
}, {
  message: 'OWASP category must match Web (e.g. A03:2021-Injection), API (e.g. API3:2023-Broken Object Property Level Authorization), or LLM (e.g. LLM01:2025-Prompt Injection)',
});
