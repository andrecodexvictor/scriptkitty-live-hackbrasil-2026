/**
 * @file packages/adapters/src/index.ts
 * @description Unified public entrypoint and re-exports for @script-kitty/adapters (ScriptKitty 2.0).
 * Exposes decoupled security engine adapters (Mantis, Codex Security, Cloudflare Security Center,
 * Quality Engine, Harness², OWASP Security Skills Pack, and Kali Lab MCP Verification),
 * execution boundary enforcement helpers, and canonical contract adapters.
 */

// 1. Adapter Interface & Lifecycle Types
export * from './adapter-interface.js';

// 2. Execution Boundary Wrappers (Timeouts, Budgets, Secret Sanitization, Error Isolation)
export * from './execution-boundary.js';

// 3. Google Mantis Adapter (ADK Summarization, Living Threat Models, Sandboxed PoC, Patch Loop)
export * from './mantis-adapter.js';

// 4. OpenAI Codex Security Adapter (Threat Modeling, SARIF 2.1.0, Reachability, Spending Ceiling)
export * from './codex-security-adapter.js';

// 5. Cloudflare Security Center Adapter (ASM, API Shield, Edge Logpush Telemetry)
export * from './cloudflare-adapter.js';

// 6. Quality Engine Adapter (Deterministic Boundary, .security-pack.json v1, Quad-State, Loopback Capabilities)
export * from './quality-engine-adapter.js';

// 7. Google Harness² Adapter (LAB_ISOLATED Recursive Strategy/Memory Optimization, Gated False by Default)
export * from './harness2-adapter.js';

// 8. OWASP Security Skills Pack Adapter (AppSec, AgentSec/MCP, Supply Chain, Cloudflare Edge Policies)
export * from './owasp-skills-adapter.js';

// 9. Kali Linux Security Verification MCP Adapter Contract (LAB_SANDBOX_ONLY, Allowlisted, SoD + Guardian)
export * from './kali-mcp-adapter.js';
