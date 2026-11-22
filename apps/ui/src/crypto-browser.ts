/**
 * @file apps/ui/src/crypto-browser.ts
 * @description Browser- and Node-compatible RFC 8785 canonical JSON serialization,
 * synchronous SHA-256 hashing, and binary Merkle tree computation aligned with `@script-kitty/contracts`.
 */

export const GENESIS_HASH =
  'GENESIS_0000000000000000000000000000000000000000000000000000000000000000';

export const EMPTY_MERKLE_ROOT =
  '0000000000000000000000000000000000000000000000000000000000000000';

export type CustodyContractType = 'FINDING' | 'EVIDENCE' | 'PATCH' | 'GATE';

export interface CustodyNodeRecord {
  index: number;
  contract_type: CustodyContractType;
  contract_id: string;
  parent_hash: string;
  leaf_hash: string;
  timestamp: string;
  chain_hash: string;
}

export interface CustodyChainRecord {
  chain_id: string;
  finding_id: string;
  nodes: CustodyNodeRecord[];
  merkle_root: string;
  total_nodes: number;
  is_valid: boolean;
  created_at: string;
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const SHA256_INIT = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}

/**
 * Pure TypeScript FIPS 180-4 SHA-256 over UTF-8 strings (browser + Node compatible).
 */
export function sha256Hex(input: string): string {
  const bytes = new TextEncoder().encode(input);
  const bitLen = bytes.length * 8;
  const paddedLen = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(bytes);
  padded[bytes.length] = 0x80;

  const view = new DataView(padded.buffer);
  const highBits = Math.floor(bitLen / 0x100000000);
  const lowBits = bitLen >>> 0;
  view.setUint32(paddedLen - 8, highBits, false);
  view.setUint32(paddedLen - 4, lowBits, false);

  const hash = new Uint32Array(SHA256_INIT);
  const w = new Uint32Array(64);

  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = hash[0];
    let b = hash[1];
    let c = hash[2];
    let d = hash[3];
    let e = hash[4];
    let f = hash[5];
    let g = hash[6];
    let h = hash[7];

    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    hash[0] = (hash[0] + a) >>> 0;
    hash[1] = (hash[1] + b) >>> 0;
    hash[2] = (hash[2] + c) >>> 0;
    hash[3] = (hash[3] + d) >>> 0;
    hash[4] = (hash[4] + e) >>> 0;
    hash[5] = (hash[5] + f) >>> 0;
    hash[6] = (hash[6] + g) >>> 0;
    hash[7] = (hash[7] + h) >>> 0;
  }

  let out = '';
  for (let i = 0; i < 8; i++) {
    out += hash[i].toString(16).padStart(8, '0');
  }
  return out;
}

/**
 * Canonical JSON Serializer (RFC 8785 aligned), matching `@script-kitty/contracts`.
 */
export function canonicalStringify(val: unknown): string {
  if (val === null || typeof val !== 'object') {
    return JSON.stringify(val);
  }
  if (typeof (val as { toISOString?: unknown }).toISOString === 'function') {
    return JSON.stringify((val as { toISOString: () => string }).toISOString());
  }
  if (Array.isArray(val)) {
    return (
      '[' +
      val
        .map((item) => (item === undefined ? 'null' : canonicalStringify(item)))
        .join(',') +
      ']'
    );
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

export function sha256(val: unknown): string {
  const input = typeof val === 'string' ? val : canonicalStringify(val);
  return sha256Hex(input);
}

export function computePolicyGraphSha256(
  graph: Record<string, unknown>
): string {
  const copy = { ...graph };
  delete copy.declaredInputSha256;
  return sha256Hex(canonicalStringify(copy));
}

export function computeEvidenceContentSha256(payload: unknown): string {
  return sha256Hex(canonicalStringify(payload));
}

export function deriveDeterministicId(prefix: string, payload: unknown): string {
  const digest = sha256Hex(canonicalStringify(payload)).slice(0, 16);
  return `${prefix}-${digest}`;
}

export function computeNodeChainHash(
  index: number,
  contractType: CustodyContractType,
  contractId: string,
  parentHash: string,
  leafHash: string,
  timestamp: string
): string {
  return sha256Hex(
    [index, contractType, contractId, parentHash, leafHash, timestamp].join(':')
  );
}

/**
 * Binary Merkle Tree Root Computation matching `@script-kitty/contracts`.
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
      nextLevel.push(sha256Hex(currentLevel[i] + currentLevel[i + 1]));
    }
    currentLevel = nextLevel;
  }
  return currentLevel[0];
}

export function verifyCustodyChain(nodes: CustodyNodeRecord[]): {
  valid: boolean;
  totalNodes: number;
  merkleRoot: string;
  error?: string;
} {
  if (nodes.length === 0) {
    return {
      valid: false,
      totalNodes: 0,
      merkleRoot: EMPTY_MERKLE_ROOT,
      error: 'Custody chain cannot be empty',
    };
  }

  let expectedParent = GENESIS_HASH;
  const leaves: string[] = [];
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    leaves.push(node.leaf_hash);
    if (node.index !== i || node.parent_hash !== expectedParent) {
      return {
        valid: false,
        totalNodes: nodes.length,
        merkleRoot: '',
        error: `Custody link mismatch at index ${i}`,
      };
    }
    const expectedChainHash = computeNodeChainHash(
      node.index,
      node.contract_type,
      node.contract_id,
      node.parent_hash,
      node.leaf_hash,
      node.timestamp
    );
    if (node.chain_hash !== expectedChainHash) {
      return {
        valid: false,
        totalNodes: nodes.length,
        merkleRoot: '',
        error: `Chain hash mismatch at index ${i}`,
      };
    }
    expectedParent = node.chain_hash;
  }

  return {
    valid: true,
    totalNodes: nodes.length,
    merkleRoot: computeMerkleRoot(leaves),
  };
}
