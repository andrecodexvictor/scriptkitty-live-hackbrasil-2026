/**
 * @file packages/quality-gate/src/index.ts
 * @description Unified public entrypoint and re-exports for @script-kitty/quality-gate.
 */

// 1. Policy & Scopes
export * from './policy.js';

// 2. Separation of Duties (Tri-Party Validator)
export * from './separation-of-duties.js';

// 3. Tamper-Evident Audit Logging & Merkle Computation
export * from './audit.js';

// 4. Deterministic Quality Gate Engine
export * from './engine.js';
