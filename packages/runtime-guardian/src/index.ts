/**
 * @file packages/runtime-guardian/src/index.ts
 * @description Main entrypoint for @script-kitty/runtime-guardian.
 */

// Types & Contracts
export * from './types.js';

// Tool Poisoning Defense
export {
  normalizeToolForHash,
  computeToolDefinitionHash,
  computeToolHash,
  scanDescriptionForPoisoning,
  validateAndFilterTools,
  ToolPoisoningGuard,
} from './tool-poisoning.js';

// Prompt Injection Defense
export {
  BEHAVIORAL_OVERRIDE_PATTERNS,
  DELIMITER_PATTERNS,
  OBFUSCATION_CHARS_REGEX,
  EXFILTRATION_PATTERNS,
  CREDENTIAL_PATTERNS,
  normalizeLeetSpeak,
  scanStringForInjection,
  sanitizeString,
  PromptInjectionDetector,
  type ScanFinding,
  type ScanResult,
} from './prompt-injection.js';

// Resource Scope & Path Boundary Guard
export {
  DEFAULT_BLOCKED_PATTERNS,
  DEFAULT_PATH_ARGUMENT_NAMES,
  validateAndResolvePath,
  ScopeBoundaryGuard,
} from './scope-guard.js';

// Confused Deputy & Delegation Defense
export {
  DEFAULT_VERIFICATION_TOOLS,
  DEFAULT_STATE_CHANGING_TOOLS,
  signDelegationToken,
  createDelegationClaims,
  verifyDelegationToken,
  ConfusedDeputyGuard,
} from './confused-deputy.js';

// Cryptographic Audit Logging & Merkle Custody
export {
  GENESIS_HASH,
  EMPTY_MERKLE_ROOT,
  sha256,
  canonicalStringify,
  computeGuardianEventHash,
  computeMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
  verifyGuardianAuditChain,
  type IAuditLogger,
  type LogEventParams,
  InMemoryAuditLogger,
  FileAuditLogger,
} from './audit-logger.js';

// Middleware & Server/Client Interceptors
export {
  RuntimeGuardian,
  createGuardianMiddleware,
  wrapMcpServer,
  createGuardianClientInterceptor,
} from './middleware.js';
