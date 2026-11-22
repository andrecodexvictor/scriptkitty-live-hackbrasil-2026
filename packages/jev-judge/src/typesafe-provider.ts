/**
 * @file packages/jev-judge/src/typesafe-provider.ts
 * @description TypeSafe AI JEV provider compatible with `@typesafe-ai/sdk`
 * (`TypeSafeClient`, `noul`, `choice`, `client.systemOne({ state, questions })`)
 * plus clearly labeled deterministic offline mock provider when `TYPESAFE_API_KEY` is absent.
 */

import {
  sanitizeStringForExternalJev,
  type SanitizedJevState,
} from './sanitizer.js';
import {
  AtomicJevAnswersSchema,
  type AtomicJevAnswers,
  type JevDecisionSource,
  type JevProviderStatus,
} from './schemas.js';

export type QuestionDefinition =
  | { type: 'noul'; instructions: string; criteria?: string[] }
  | { type: 'choice'; instructions: string; criteria: string[] };

export function noul(
  instructions: string,
  criteria?: string[]
): { type: 'noul'; instructions: string; criteria?: string[] } {
  return criteria !== undefined
    ? { type: 'noul', instructions, criteria }
    : { type: 'noul', instructions };
}

export function choice(
  instructions: string,
  criteria: string[]
): { type: 'choice'; instructions: string; criteria: string[] } {
  return { type: 'choice', instructions, criteria };
}

export const JEV_ATOMIC_QUESTION_TEXTS = {
  evidence_sufficient:
    'Are the cited graph identifiers, policy references, and reachability facts backed by independent verified evidence of matching tenant and policy scope?',
  needs_manual_review:
    'Do material evidence gaps, inconclusive paths, high severity risks, or ambiguity require human security review?',
  triage:
    'Based strictly on the verified policy graph facts and evidence metadata, classify the advisory triage outcome without confirming production exploitation.',
} as const;

export function buildJevAtomicQuestions(): {
  evidence_sufficient: { type: 'noul'; instructions: string; criteria?: string[] };
  needs_manual_review: { type: 'noul'; instructions: string; criteria?: string[] };
  triage: { type: 'choice'; instructions: string; criteria: string[] };
} {
  return {
    evidence_sufficient: noul(JEV_ATOMIC_QUESTION_TEXTS.evidence_sufficient, [
      'Every cited evidenceId has verified === true and matching non-empty sourceRef',
      'All graph path edges have valid policyVersion and sourceRef bindings',
      'Input SHA-256 integrity is verified in LAB scope',
    ]),
    needs_manual_review: noul(JEV_ATOMIC_QUESTION_TEXTS.needs_manual_review, [
      'Any finding is P0 or P1',
      'Any path is INCONCLUSIVE or has missingReferencesCount > 0',
      'Any evidence record is missing or unverified or diagnostics indicate truncation',
    ]),
    triage: choice(JEV_ATOMIC_QUESTION_TEXTS.triage, [
      'likely_actionable',
      'needs_more_evidence',
      'likely_irrelevant',
    ]),
  };
}

export interface SystemOneRequest {
  state: unknown;
  questions: Record<string, QuestionDefinition>;
  model?: string;
}

export interface SystemOneResponse {
  model: string;
  answers: Record<string, unknown>;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
  };
}

export interface TypeSafeClientLike {
  systemOne(
    request: SystemOneRequest,
    options?: { signal?: AbortSignal; timeout?: number }
  ): Promise<SystemOneResponse>;
}

export class TypeSafeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TypeSafeError';
  }
}

export class TypeSafeAPIError extends TypeSafeError {
  readonly status: number;

  constructor(status: number, message: string) {
    super(`TypeSafe API error (${status}): ${message}`);
    this.name = 'TypeSafeAPIError';
    this.status = status;
  }
}

export interface TypeSafeClientOptions {
  apiKey?: string;
  baseURL?: string;
  defaultModel?: string;
  timeout?: number;
  headers?: Record<string, string>;
  fetch?: typeof globalThis.fetch;
}

/**
 * Lightweight, wire-compatible `@typesafe-ai/sdk` `TypeSafeClient` targeting
 * `${baseURL}/v1/systemone` (`Authorization: Bearer <TYPESAFE_API_KEY>`).
 */
export class TypeSafeClient implements TypeSafeClientLike {
  private readonly apiKey: string;
  private readonly baseURL: string;
  readonly defaultModel: string;
  private readonly timeout: number;
  private readonly extraHeaders: Record<string, string>;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(options: TypeSafeClientOptions = {}) {
    const apiKey = options.apiKey ?? process.env.TYPESAFE_API_KEY;
    if (!apiKey || !apiKey.trim()) {
      throw new TypeSafeError(
        'TYPESAFE_API_KEY is required for live TypeSafeClient execution'
      );
    }
    this.apiKey = apiKey.trim();
    this.baseURL = (
      options.baseURL ??
      process.env.TYPESAFE_BASE_URL ??
      'https://api.typesafe.ai'
    ).replace(/\/+$/, '');
    this.defaultModel = options.defaultModel ?? 'jev-latest';
    this.timeout = options.timeout ?? 30_000;
    this.extraHeaders = options.headers ?? {};
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }

  async systemOne(
    request: SystemOneRequest,
    options: { signal?: AbortSignal; timeout?: number } = {}
  ): Promise<SystemOneResponse> {
    const timeoutMs = options.timeout ?? this.timeout;
    const timeoutController = new AbortController();
    const timer = setTimeout(() => timeoutController.abort(), timeoutMs);

    const onCallerAbort = () => timeoutController.abort();
    if (options.signal) {
      if (options.signal.aborted) {
        clearTimeout(timer);
        throw new TypeSafeError('Request aborted before dispatch');
      }
      options.signal.addEventListener('abort', onCallerAbort, { once: true });
    }

    try {
      const response = await this.fetchImpl(`${this.baseURL}/v1/systemone`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
          ...this.extraHeaders,
        },
        body: JSON.stringify({
          model: request.model ?? this.defaultModel,
          state: request.state,
          questions: request.questions,
        }),
        signal: timeoutController.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        const redacted = sanitizeStringForExternalJev(text).value;
        throw new TypeSafeAPIError(
          response.status,
          redacted.slice(0, 200) || response.statusText || 'HTTP error'
        );
      }

      const json = (await response.json()) as SystemOneResponse;
      if (!json || typeof json !== 'object' || !json.answers) {
        throw new TypeSafeError('Malformed systemOne JSON response from TypeSafe API');
      }
      return json;
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', onCallerAbort);
    }
  }
}

export interface JevInferenceOutput {
  model: string;
  modelVersion: string;
  answers: AtomicJevAnswers;
  decisionSource: JevDecisionSource;
  providerStatus: JevProviderStatus;
}

export interface JevProvider {
  readonly mode: 'LIVE' | 'MOCK';
  getStatus(): JevProviderStatus;
  evaluate(params: {
    state: SanitizedJevState;
    questions: ReturnType<typeof buildJevAtomicQuestions>;
    model?: string;
    signal?: AbortSignal;
    timeoutMs?: number;
  }): Promise<JevInferenceOutput>;
}

/**
 * Live `@typesafe-ai/sdk`-compatible JEV provider wrapping `TypeSafeClient`.
 */
export class LiveTypeSafeJevProvider implements JevProvider {
  readonly mode = 'LIVE' as const;
  private readonly client: TypeSafeClientLike;
  private readonly defaultModel: string;

  constructor(client: TypeSafeClientLike, defaultModel = 'jev-latest') {
    this.client = client;
    this.defaultModel = defaultModel;
  }

  getStatus(): JevProviderStatus {
    return 'LIVE';
  }

  async evaluate(params: {
    state: SanitizedJevState;
    questions: ReturnType<typeof buildJevAtomicQuestions>;
    model?: string;
    signal?: AbortSignal;
    timeoutMs?: number;
  }): Promise<JevInferenceOutput> {
    const response = await this.client.systemOne(
      {
        state: params.state,
        questions: params.questions,
        model: params.model ?? this.defaultModel,
      },
      { signal: params.signal, timeout: params.timeoutMs }
    );

    const parsed = AtomicJevAnswersSchema.safeParse(response.answers);
    if (!parsed.success) {
      throw new TypeSafeError(
        `Invalid JEV atomic answers schema: ${parsed.error.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join('; ')}`
      );
    }

    return {
      model: response.model || params.model || this.defaultModel,
      modelVersion: response.model || params.model || this.defaultModel,
      answers: parsed.data,
      decisionSource: 'LIVE',
      providerStatus: 'LIVE',
    };
  }
}

/**
 * Deterministic offline LAB mock provider used transparently when `TYPESAFE_API_KEY` is absent.
 * Always emits `decisionSource: "MOCK"` and `providerStatus: "NOT_CONFIGURED"` (or `"FALLBACK"`).
 */
export class MockTypeSafeJevProvider implements JevProvider {
  readonly mode = 'MOCK' as const;
  private readonly status: Extract<JevProviderStatus, 'NOT_CONFIGURED' | 'FALLBACK'>;
  private readonly decisionSource: Extract<JevDecisionSource, 'MOCK' | 'FALLBACK'>;

  constructor(options: { asFallback?: boolean } = {}) {
    this.status = options.asFallback ? 'FALLBACK' : 'NOT_CONFIGURED';
    this.decisionSource = options.asFallback ? 'FALLBACK' : 'MOCK';
  }

  getStatus(): JevProviderStatus {
    return this.status;
  }

  async evaluate(params: {
    state: SanitizedJevState;
  }): Promise<JevInferenceOutput> {
    const { state } = params;
    const allEvidenceVerified =
      state.evidenceCount > 0 && state.verifiedEvidenceCount === state.evidenceCount;
    const hasInconclusive =
      state.analysisStatus === 'INCONCLUSIVE' ||
      state.paths.some((p) => p.status === 'INCONCLUSIVE' || p.missingReferencesCount > 0);
    const hasValidatedPaths = state.paths.some((p) => p.status === 'PATH_VALIDATED');
    const hasCritical = state.paths.some(
      (p) => p.deterministicRisk === 'P0' || p.deterministicRisk === 'P1'
    );

    const evidenceScore = allEvidenceVerified && !hasInconclusive ? 0.94 : 0.35;
    const manualReviewScore =
      hasInconclusive || !allEvidenceVerified || hasCritical || !state.legitimateOperationsPreserved
        ? 0.92
        : 0.12;

    let answers: AtomicJevAnswers;
    if (!allEvidenceVerified || hasInconclusive || state.analysisStatus !== 'COMPLETED') {
      answers = {
        evidence_sufficient: { type: 'noul', noul: evidenceScore },
        needs_manual_review: { type: 'noul', noul: manualReviewScore },
        triage: {
          type: 'choice',
          choice: 'needs_more_evidence',
          confidence: 0.85,
          probabilities: {
            likely_actionable: 0.1,
            needs_more_evidence: 0.85,
            likely_irrelevant: 0.05,
          },
        },
      };
    } else if (hasValidatedPaths) {
      answers = {
        evidence_sufficient: { type: 'noul', noul: evidenceScore },
        needs_manual_review: { type: 'noul', noul: manualReviewScore },
        triage: {
          type: 'choice',
          choice: 'likely_actionable',
          confidence: 0.91,
          probabilities: {
            likely_actionable: 0.91,
            needs_more_evidence: 0.06,
            likely_irrelevant: 0.03,
          },
        },
      };
    } else {
      answers = {
        evidence_sufficient: { type: 'noul', noul: evidenceScore },
        needs_manual_review: { type: 'noul', noul: manualReviewScore },
        triage: {
          type: 'choice',
          choice: 'likely_irrelevant',
          confidence: 0.93,
          probabilities: {
            likely_actionable: 0.02,
            needs_more_evidence: 0.05,
            likely_irrelevant: 0.93,
          },
        },
      };
    }

    return {
      model: 'mock-offline-v0',
      modelVersion: '0.1.0-mock',
      answers,
      decisionSource: this.decisionSource,
      providerStatus: this.status,
    };
  }
}

export function resolveJevProviderStatus(envApiKey = process.env.TYPESAFE_API_KEY): 'LIVE' | 'NOT_CONFIGURED' {
  return typeof envApiKey === 'string' && envApiKey.trim().length > 0
    ? 'LIVE'
    : 'NOT_CONFIGURED';
}

export function resolveDefaultJevProvider(options: {
  apiKey?: string;
  baseURL?: string;
  defaultModel?: string;
  fetch?: typeof globalThis.fetch;
  client?: TypeSafeClientLike;
} = {}): JevProvider {
  if (options.client) {
    return new LiveTypeSafeJevProvider(options.client, options.defaultModel);
  }
  const apiKey = options.apiKey ?? process.env.TYPESAFE_API_KEY;
  if (apiKey && apiKey.trim().length > 0) {
    const client = new TypeSafeClient({
      apiKey,
      baseURL: options.baseURL,
      defaultModel: options.defaultModel,
      fetch: options.fetch,
    });
    return new LiveTypeSafeJevProvider(client, client.defaultModel);
  }
  return new MockTypeSafeJevProvider();
}
