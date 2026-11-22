/**
 * @file packages/jev-judge/src/sanitizer.ts
 * @description State allowlisting & secret/source-code sanitization for TypeSafe JEV.
 * Guarantees no secrets, credentials, private source code, or local filesystem paths
 * ever cross into external JEV inference payloads.
 */

import { sha256, type JudgeAnalysisInput, type JudgeEvidenceInput } from './schemas.js';

const SECRET_PATTERNS: ReadonlyArray<{ name: string; regex: RegExp; replacement: string }> = [
  {
    name: 'pem_private_key',
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replacement: '[REDACTED_PRIVATE_KEY]',
  },
  {
    name: 'bearer_token',
    regex: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
    replacement: 'Bearer [REDACTED]',
  },
  {
    name: 'jwt_token',
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    replacement: '[REDACTED_JWT]',
  },
  {
    name: 'openai_or_sk_key',
    regex: /\bsk-[A-Za-z0-9_-]{12,}\b/g,
    replacement: '[REDACTED_API_KEY]',
  },
  {
    name: 'typesafe_or_ts_key',
    regex: /\bts_(?:live|test|key)_[A-Za-z0-9_-]{8,}\b/g,
    replacement: '[REDACTED_TYPESAFE_KEY]',
  },
  {
    name: 'github_token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b/g,
    replacement: '[REDACTED_GH_TOKEN]',
  },
  {
    name: 'aws_access_key',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    replacement: '[REDACTED_AWS_KEY]',
  },
  {
    name: 'slack_token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    replacement: '[REDACTED_SLACK_TOKEN]',
  },
  {
    name: 'url_credentials',
    regex: /\b(https?:\/\/)([^:@/\s]+):([^@/\s]+)@/gi,
    replacement: '$1[REDACTED_USER]:[REDACTED_PASS]@',
  },
  {
    name: 'kv_secret_assignment',
    regex: /\b(TYPESAFE_API_KEY|API_KEY|SECRET_KEY|ACCESS_TOKEN|PRIVATE_KEY|PASSWORD|AUTH_TOKEN)\s*[:=]\s*(['"]?)[^\s,'";]{4,}\2/gi,
    replacement: '$1=[REDACTED]',
  },
];

const LOCAL_PATH_REGEX = /(?:[A-Za-z]:\\(?:Users|Windows|Program Files)[^\s"'`;]+|\/(?:Users|home|var\/secrets|etc\/shadow)[^\s"'`;]*)/gi;
const CODE_FENCE_REGEX = /```[\s\S]*?```/g;

export interface SanitizedJevPathSummary {
  pathId: string;
  startIdentity: string;
  targetAsset: string;
  targetDestination?: string;
  violatedPolicyId: string;
  status: string;
  deterministicRisk: string;
  evidenceIds: string[];
  edges: Array<{
    edgeId: string;
    from: string;
    to: string;
    kind: string;
    scope: string;
    dataClassification?: string;
    policyId?: string;
    policyVersion: string;
    sourceRef: string;
  }>;
  missingReferencesCount: number;
}

export interface SanitizedJevEvidenceSummary {
  evidenceId: string;
  kind: string;
  verified: boolean;
  contentSha256: string;
  producer: string;
  commitSha?: string;
  sourceRef: string;
}

export interface SanitizedJevState {
  schemaVersion: 'jev.sanitized.state.v1';
  mode: 'LAB';
  productionTested: false;
  analysisId: string;
  tenantScopeDigest: string;
  fixtureId: string;
  policyVersion: string;
  analysisStatus: string;
  inputSha256: string;
  legitimateOperationsPreserved: boolean;
  pathsCount: number;
  paths: SanitizedJevPathSummary[];
  evidenceCount: number;
  verifiedEvidenceCount: number;
  evidence: SanitizedJevEvidenceSummary[];
  diagnosticCodes: string[];
  redactionsApplied: number;
}

export interface SanitizeResult {
  state: SanitizedJevState;
  sanitizedStateDigest: string;
  redactionsApplied: number;
}

export function sanitizeStringForExternalJev(input: string): {
  value: string;
  redactions: number;
} {
  let value = input;
  let redactions = 0;

  value = value.replace(CODE_FENCE_REGEX, () => {
    redactions += 1;
    return '[REDACTED_CODE_BLOCK]';
  });

  for (const rule of SECRET_PATTERNS) {
    const matches = value.match(rule.regex);
    if (matches && matches.length > 0) {
      redactions += matches.length;
      value = value.replace(rule.regex, rule.replacement);
    }
  }

  const pathMatches = value.match(LOCAL_PATH_REGEX);
  if (pathMatches && pathMatches.length > 0) {
    redactions += pathMatches.length;
    value = value.replace(LOCAL_PATH_REGEX, (matched) => {
      const normalized = matched.replace(/\\/g, '/');
      const parts = normalized.split('/').filter(Boolean);
      const tail = parts[parts.length - 1] ?? 'file';
      return `[PATH_REDACTED]/${tail}`;
    });
  }

  return { value, redactions };
}

export function containsSensitiveMaterial(text: string): boolean {
  for (const rule of SECRET_PATTERNS) {
    rule.regex.lastIndex = 0;
    if (rule.regex.test(text)) {
      rule.regex.lastIndex = 0;
      return true;
    }
    rule.regex.lastIndex = 0;
  }
  LOCAL_PATH_REGEX.lastIndex = 0;
  const hasLocalPath = LOCAL_PATH_REGEX.test(text);
  LOCAL_PATH_REGEX.lastIndex = 0;
  return hasLocalPath;
}

/**
 * Builds an allowlisted, sanitized summary of ChainBreak graph facts and evidence metadata.
 * Raw source code, local OS paths, and any credentials/secrets are stripped before leaving process memory.
 */
export function sanitizeStateForJev(
  analysis: JudgeAnalysisInput,
  evidenceList?: JudgeEvidenceInput[]
): SanitizeResult {
  let redactionsApplied = 0;

  const clean = (raw: string | undefined): string => {
    if (!raw) return '';
    const res = sanitizeStringForExternalJev(raw);
    redactionsApplied += res.redactions;
    return res.value;
  };

  const mergedEvidenceMap = new Map<string, JudgeEvidenceInput>();
  for (const ev of analysis.evidence ?? []) {
    mergedEvidenceMap.set(ev.evidenceId, ev);
  }
  for (const ev of evidenceList ?? []) {
    mergedEvidenceMap.set(ev.evidenceId, ev);
  }

  const evidenceSummaries: SanitizedJevEvidenceSummary[] = Array.from(
    mergedEvidenceMap.values()
  ).map((ev) => ({
    evidenceId: clean(ev.evidenceId),
    kind: ev.kind,
    verified: ev.verified,
    contentSha256: ev.contentSha256,
    producer: clean(ev.producer),
    ...(ev.commitSha ? { commitSha: ev.commitSha } : {}),
    sourceRef: clean(ev.sourceRef),
  }));

  const pathSummaries: SanitizedJevPathSummary[] = analysis.paths.map((p) => ({
    pathId: clean(p.pathId),
    startIdentity: clean(p.startIdentity),
    targetAsset: clean(p.targetAsset),
    ...(p.targetDestination
      ? { targetDestination: clean(p.targetDestination) }
      : {}),
    violatedPolicyId: clean(p.violatedPolicyId),
    status: p.status,
    deterministicRisk: p.riskRecommendation,
    evidenceIds: p.evidenceIds.map((id) => clean(id)),
    edges: p.edges.map((e) => ({
      edgeId: clean(e.edgeId),
      from: clean(e.from),
      to: clean(e.to),
      kind: clean(e.kind),
      scope: clean(e.scope),
      ...(e.dataClassification
        ? { dataClassification: e.dataClassification }
        : {}),
      ...(e.policyId ? { policyId: clean(e.policyId) } : {}),
      policyVersion: clean(e.policyVersion),
      sourceRef: clean(e.sourceRef),
    })),
    missingReferencesCount: p.missingReferences?.length ?? 0,
  }));

  const diagnosticCodes = (analysis.diagnostics ?? []).map((d) =>
    typeof d.code === 'string' ? clean(d.code) : 'DIAGNOSTIC'
  );

  const state: SanitizedJevState = {
    schemaVersion: 'jev.sanitized.state.v1',
    mode: 'LAB',
    productionTested: false,
    analysisId: clean(analysis.analysisId),
    tenantScopeDigest: sha256({ tenantId: analysis.tenantId }).slice(0, 16),
    fixtureId: clean(analysis.fixtureId),
    policyVersion: clean(analysis.policyVersion),
    analysisStatus: analysis.status,
    inputSha256: analysis.inputSha256,
    legitimateOperationsPreserved: analysis.legitimateOperationsPreserved,
    pathsCount: pathSummaries.length,
    paths: pathSummaries,
    evidenceCount: evidenceSummaries.length,
    verifiedEvidenceCount: evidenceSummaries.filter((e) => e.verified).length,
    evidence: evidenceSummaries,
    diagnosticCodes,
    redactionsApplied,
  };

  const serialized = JSON.stringify(state);
  if (containsSensitiveMaterial(serialized)) {
    throw new Error(
      'SANITIZATION_FAILED: sensitive material remained after state allowlisting'
    );
  }

  return {
    state,
    sanitizedStateDigest: sha256(state),
    redactionsApplied,
  };
}
