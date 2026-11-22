/**
 * @file packages/contracts/src/custody.ts
 * @description Cryptographic Chain of Custody, SHA-256 Hashing, Canonical Serialization,
 * and Binary Merkle Tree Computation for ScriptKitty 2.0.
 */

import { createHash } from 'node:crypto';
import type { SecurityFinding } from './finding.js';
import type { Evidence } from './evidence.js';
import type { PatchProposal } from './patch.js';
import type { GateDecision } from './gate.js';

/**
 * Genesis parent hash for Stage 0 (Finding) in the chain of custody.
 */
export const GENESIS_HASH =
  'GENESIS_0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Null Merkle root representation for empty leaf sets (64 hexadecimal zeros).
 */
export const EMPTY_MERKLE_ROOT =
  '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Supported Contract Types across the evidence lifecycle.
 */
export type ContractType = 'FINDING' | 'EVIDENCE' | 'PATCH' | 'GATE';

/**
 * Single immutable node in a cryptographic chain of custody.
 */
export interface CustodyNode {
  index: number;
  contract_type: ContractType;
  contract_id: string;
  parent_hash: string;
  leaf_hash: string;
  timestamp: string;
  chain_hash: string;
}

/**
 * Complete sealed Chain of Custody package.
 */
export interface ChainOfCustody {
  chain_id: string;
  finding_id: string;
  nodes: CustodyNode[];
  merkle_root: string;
  total_nodes: number;
  is_valid: boolean;
  created_at: string;
}

/**
 * Result of a chain integrity verification.
 */
export interface ChainVerificationResult {
  valid: boolean;
  total_nodes: number;
  merkle_root: string;
  broken_index?: number;
  error?: string;
}

/**
 * Single step in a logarithmic Merkle audit proof.
 */
export interface MerkleProofStep {
  position: 'left' | 'right';
  hash: string;
}

/**
 * Logarithmic Merkle inclusion proof.
 */
export type MerkleProof = MerkleProofStep[];

/**
 * Computes a standard SHA-256 hexadecimal digest of input data.
 */
export function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Canonical JSON Serializer (RFC 8785 aligned).
 * Deterministically sorts object keys lexicographically, strips whitespace,
 * normalizes primitives, and ignores undefined values.
 */
export function canonicalStringify(val: unknown): string {
  if (val === null || typeof val !== 'object') {
    return JSON.stringify(val);
  }
  if (typeof (val as { toISOString?: unknown }).toISOString === 'function') {
    return JSON.stringify((val as { toISOString: () => string }).toISOString());
  }
  if (Array.isArray(val)) {
    return '[' + val.map((item) => (item === undefined ? 'null' : canonicalStringify(item))).join(',') + ']';
  }
  const obj = val as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const entries: string[] = [];
  for (const key of sortedKeys) {
    const v = obj[key];
    if (v !== undefined) {
      entries.push(JSON.stringify(key) + ':' + canonicalStringify(v));
    }
  }
  return '{' + entries.join(',') + '}';
}

/**
 * Computes canonical leaf hash for a SecurityFinding contract.
 * Strips self-referential hash fields (`fingerprint`, `finding_hash`, `findingHash`).
 */
export function hashSecurityFinding(finding: SecurityFinding | Record<string, unknown>): string {
  const copy = { ...finding } as Record<string, unknown>;
  delete copy.fingerprint;
  delete copy.finding_hash;
  delete copy.findingHash;
  delete copy.hash;
  return sha256(canonicalStringify(copy));
}

/**
 * Computes canonical leaf hash for an Evidence contract.
 * Strips self-referential custody fields (`chain_hash`, `chainHash`, `evidence_hash`, `evidenceHash`, `signature`).
 */
export function hashEvidence(evidence: Evidence | Record<string, unknown>): string {
  const copy = { ...evidence } as Record<string, unknown>;
  delete copy.chain_hash;
  delete copy.chainHash;
  delete copy.evidence_hash;
  delete copy.evidenceHash;
  delete copy.signature;
  return sha256(canonicalStringify(copy));
}

/**
 * Computes canonical leaf hash for a PatchProposal contract.
 * Strips self-referential patch hash fields (`patch_sha256`, `patchSha256`, `hash`).
 */
export function hashPatchProposal(patch: PatchProposal | Record<string, unknown>): string {
  const copy = { ...patch } as Record<string, unknown>;
  delete copy.patch_sha256;
  delete copy.patchSha256;
  delete copy.hash;
  return sha256(canonicalStringify(copy));
}

/**
 * Computes canonical leaf hash for a GateDecision contract.
 * Strips self-referential decision signature fields (`audit_signature`, `auditSignature`, `signature`).
 */
export function hashGateDecision(gate: GateDecision | Record<string, unknown>): string {
  const copy = { ...gate } as Record<string, unknown>;
  delete copy.audit_signature;
  delete copy.auditSignature;
  delete copy.signature;
  return sha256(canonicalStringify(copy));
}

/**
 * Computes node chain hash from constituent link fields:
 * chain_hash = sha256(`${index}:${contract_type}:${contract_id}:${parent_hash}:${leaf_hash}:${timestamp}`)
 */
export function computeNodeChainHash(
  index: number,
  contractType: ContractType,
  contractId: string,
  parentHash: string,
  leafHash: string,
  timestamp: string
): string {
  const payload = [index, contractType, contractId, parentHash, leafHash, timestamp].join(':');
  return sha256(payload);
}

/**
 * Binary Merkle Tree Root Computation.
 * Fully aligned with packages/audit/src/lib.rs:
 * - 0 leaves: returns 64 hexadecimal zeros.
 * - 1 leaf: returns that leaf's hash.
 * - Odd number of leaves: duplicates the last leaf.
 * - Chunk pairs: sha256(left_hex + right_hex).
 */
export function computeMerkleRoot(leaves: string[]): string {
  if (leaves.length === 0) {
    return EMPTY_MERKLE_ROOT;
  }
  let currentLevel = [...leaves];
  while (currentLevel.length > 1) {
    if (currentLevel.length % 2 !== 0) {
      currentLevel.push(currentLevel[currentLevel.length - 1]);
    }
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const combined = currentLevel[i] + currentLevel[i + 1];
      nextLevel.push(sha256(combined));
    }
    currentLevel = nextLevel;
  }
  return currentLevel[0];
}

/**
 * Generates an inclusion proof for a target leaf in a binary Merkle tree.
 */
export function generateMerkleProof(leaves: string[], targetIndex: number): MerkleProof {
  if (targetIndex < 0 || targetIndex >= leaves.length) {
    throw new Error(`Target index ${targetIndex} out of bounds for leaf array of length ${leaves.length}`);
  }
  const proof: MerkleProof = [];
  let currentLevel = [...leaves];
  let idx = targetIndex;

  while (currentLevel.length > 1) {
    if (currentLevel.length % 2 !== 0) {
      currentLevel.push(currentLevel[currentLevel.length - 1]);
    }
    const isRightSibling = idx % 2 === 0;
    const siblingIndex = isRightSibling ? idx + 1 : idx - 1;

    proof.push({
      position: isRightSibling ? 'right' : 'left',
      hash: currentLevel[siblingIndex],
    });

    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      nextLevel.push(sha256(currentLevel[i] + currentLevel[i + 1]));
    }
    currentLevel = nextLevel;
    idx = Math.floor(idx / 2);
  }

  return proof;
}

/**
 * Verifies a Merkle proof against an expected root.
 */
export function verifyMerkleProof(leafHash: string, proof: MerkleProof, expectedRoot: string): boolean {
  let current = leafHash;
  for (const step of proof) {
    if (step.position === 'right') {
      current = sha256(current + step.hash);
    } else {
      current = sha256(step.hash + current);
    }
  }
  return current === expectedRoot;
}

/**
 * Verifies the mathematical integrity of a custody node array.
 */
export function verifyChainIntegrity(nodes: CustodyNode[]): ChainVerificationResult {
  if (nodes.length === 0) {
    return {
      valid: false,
      total_nodes: 0,
      merkle_root: EMPTY_MERKLE_ROOT,
      error: 'Custody chain cannot be empty',
    };
  }

  let expectedParent = GENESIS_HASH;
  const leafHashes: string[] = [];

  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    leafHashes.push(node.leaf_hash);

    if (node.index !== i) {
      return {
        valid: false,
        total_nodes: nodes.length,
        merkle_root: '',
        broken_index: i,
        error: `Node index mismatch at position ${i}: expected ${i}, found ${node.index}`,
      };
    }

    if (node.parent_hash !== expectedParent) {
      return {
        valid: false,
        total_nodes: nodes.length,
        merkle_root: '',
        broken_index: i,
        error: `Parent hash mismatch at node ${i}: expected ${expectedParent}, found ${node.parent_hash}`,
      };
    }

    const recomputedChainHash = computeNodeChainHash(
      node.index,
      node.contract_type,
      node.contract_id,
      node.parent_hash,
      node.leaf_hash,
      node.timestamp
    );

    if (node.chain_hash !== recomputedChainHash) {
      return {
        valid: false,
        total_nodes: nodes.length,
        merkle_root: '',
        broken_index: i,
        error: `Chain hash corruption at node ${i}: stored ${node.chain_hash}, computed ${recomputedChainHash}`,
      };
    }

    expectedParent = node.chain_hash;
  }

  const computedRoot = computeMerkleRoot(leafHashes);

  return {
    valid: true,
    total_nodes: nodes.length,
    merkle_root: computedRoot,
  };
}

/**
 * Verifies a ChainOfCustody instance by verifying node sequence/hash integrity
 * and explicitly asserting that the declared Merkle root matches the recomputed Merkle root.
 */
export function verifyChainOfCustody(
  chain: ChainOfCustody | { nodes: CustodyNode[]; merkle_root?: string }
): ChainVerificationResult {
  if (!chain || typeof chain !== 'object' || !Array.isArray(chain.nodes)) {
    return {
      valid: false,
      total_nodes: 0,
      merkle_root: '',
      error: 'Invalid ChainOfCustody: nodes array is required',
    };
  }

  const integrity = verifyChainIntegrity(chain.nodes);
  if (!integrity.valid) {
    return integrity;
  }

  if (chain.merkle_root !== undefined && chain.merkle_root !== integrity.merkle_root) {
    return {
      valid: false,
      total_nodes: chain.nodes.length,
      merkle_root: integrity.merkle_root,
      error: `Merkle root mismatch: chain declared ${chain.merkle_root}, computed ${integrity.merkle_root}`,
    };
  }

  return integrity;
}

/**
 * Constructs an immutable Chain of Custody connecting Finding -> Evidence -> Patch -> Gate.
 */
export function buildCustodyChain(params: {
  finding: SecurityFinding;
  evidence: Evidence;
  patch?: PatchProposal;
  gate?: GateDecision;
}): ChainOfCustody {
  const nodes: CustodyNode[] = [];
  const findingId = params.finding.finding_id;

  // Node 0: Finding
  const findingLeaf = hashSecurityFinding(params.finding);
  const node0ChainHash = computeNodeChainHash(
    0,
    'FINDING',
    params.finding.finding_id,
    GENESIS_HASH,
    findingLeaf,
    params.finding.discovered_at
  );
  nodes.push({
    index: 0,
    contract_type: 'FINDING',
    contract_id: params.finding.finding_id,
    parent_hash: GENESIS_HASH,
    leaf_hash: findingLeaf,
    timestamp: params.finding.discovered_at,
    chain_hash: node0ChainHash,
  });

  // Node 1: Evidence
  const evidenceLeaf = hashEvidence(params.evidence);
  const node1ChainHash = computeNodeChainHash(
    1,
    'EVIDENCE',
    params.evidence.evidence_id,
    node0ChainHash,
    evidenceLeaf,
    params.evidence.recorded_at
  );
  nodes.push({
    index: 1,
    contract_type: 'EVIDENCE',
    contract_id: params.evidence.evidence_id,
    parent_hash: node0ChainHash,
    leaf_hash: evidenceLeaf,
    timestamp: params.evidence.recorded_at,
    chain_hash: node1ChainHash,
  });

  let lastChainHash = node1ChainHash;

  // Node 2: PatchProposal (if present)
  if (params.patch) {
    const patchLeaf = hashPatchProposal(params.patch);
    const node2ChainHash = computeNodeChainHash(
      2,
      'PATCH',
      params.patch.patch_id,
      lastChainHash,
      patchLeaf,
      params.patch.created_at
    );
    nodes.push({
      index: 2,
      contract_type: 'PATCH',
      contract_id: params.patch.patch_id,
      parent_hash: lastChainHash,
      leaf_hash: patchLeaf,
      timestamp: params.patch.created_at,
      chain_hash: node2ChainHash,
    });
    lastChainHash = node2ChainHash;
  }

  // Node 3: GateDecision (if present)
  if (params.gate) {
    const gateIndex = nodes.length;
    const gateLeaf = hashGateDecision(params.gate);
    const nodeGateChainHash = computeNodeChainHash(
      gateIndex,
      'GATE',
      params.gate.decision_id,
      lastChainHash,
      gateLeaf,
      params.gate.decided_at
    );
    nodes.push({
      index: gateIndex,
      contract_type: 'GATE',
      contract_id: params.gate.decision_id,
      parent_hash: lastChainHash,
      leaf_hash: gateLeaf,
      timestamp: params.gate.decided_at,
      chain_hash: nodeGateChainHash,
    });
  }

  const leafHashes = nodes.map((n) => n.leaf_hash);
  const merkleRoot = computeMerkleRoot(leafHashes);
  const verification = verifyChainIntegrity(nodes);

  return {
    chain_id: `SK-CHAIN-${findingId}-${Date.now()}`,
    finding_id: findingId,
    nodes,
    merkle_root: merkleRoot,
    total_nodes: nodes.length,
    is_valid: verification.valid,
    created_at: new Date().toISOString(),
  };
}
